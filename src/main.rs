use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use grepcp::app::App;
use grepcp::config::{Settings, Transport};
use grepcp::engine::output::human_bytes;
use grepcp::parse::time::{TimeSpec, fmt_local};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "grepcp",
    version,
    about = "Read-only MCP server that searches a log box's rotated log tree"
)]
struct Cli {
    /// Config file.
    #[arg(
        long,
        global = true,
        env = "GREPCP_CONFIG",
        default_value = "/etc/grepcp/config.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the MCP server.
    Serve {
        /// Serve over stdin/stdout (e.g. via `ssh box grepcp serve --stdio`).
        #[arg(long, conflicts_with = "http")]
        stdio: bool,
        /// Serve over HTTPS (needs [server.tls]).
        #[arg(long)]
        http: bool,
    },
    /// Check the config's assumptions against this box.
    Doctor,
    /// Validate the config file and exit.
    CheckConfig,
    /// Dry run: show which files a search would scan.
    Plan {
        #[arg(long, value_delimiter = ',', required = true)]
        service: Vec<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        last: Option<String>,
        #[arg(long)]
        date: Option<String>,
        #[arg(long, value_delimiter = ',')]
        hours: Option<Vec<u32>>,
        #[arg(long, value_delimiter = ',')]
        host: Option<Vec<String>>,
    },
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("GREPCP_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let b = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if std::env::var("GREPCP_LOG_FORMAT").as_deref() == Ok("json") {
        b.json().init();
    } else {
        b.compact().init();
    }
}

fn load(path: &std::path::Path) -> anyhow::Result<Arc<Settings>> {
    Ok(Arc::new(Settings::load(path)?))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::CheckConfig => {
            let s = load(&cli.config)?;
            println!("config ok: box={} root={}", s.box_name(), s.root.display());
            Ok(())
        }
        Cmd::Doctor => {
            let s = load(&cli.config)?;
            let (report, warnings) = grepcp::doctor::run(s)?;
            print!("{report}");
            if warnings > 0 {
                std::process::exit(2);
            }
            Ok(())
        }
        Cmd::Plan {
            service,
            from,
            to,
            last,
            date,
            hours,
            host,
        } => {
            let s = load(&cli.config)?;
            let app = App::new(s.clone())?;
            let now = chrono::Utc::now();
            let spec = TimeSpec {
                from,
                to,
                last,
                date,
                hours,
            };
            let window = grepcp::parse::time::resolve(&spec, &s.tz, now)
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| anyhow::anyhow!("give --from/--to, --last or --date"))?;
            let plan = grepcp::logs::planner::plan(
                &app.catalog,
                &service,
                &window,
                host.as_deref(),
                now,
                None,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            let span = plan.window.span();
            println!(
                "window {} → {}",
                fmt_local(span.from, &s.tz),
                fmt_local(span.to, &s.tz)
            );
            for f in &plan.files {
                println!(
                    "{:>10}  {}/{}{}",
                    human_bytes(f.size),
                    f.service,
                    f.name,
                    if f.live { "  (live)" } else { "" }
                );
            }
            let limit = s.limits().max_scan_bytes;
            println!(
                "{} files, {} total ({} skipped by time); max_scan_bytes {} → {}",
                plan.files.len(),
                human_bytes(plan.total_bytes),
                plan.skipped_by_time,
                human_bytes(limit),
                if plan.total_bytes > limit {
                    "REFUSED"
                } else {
                    "ok"
                }
            );
            for w in plan.warnings {
                println!("! {w}");
            }
            Ok(())
        }
        Cmd::Serve { stdio, http } => {
            init_tracing();
            let s = load(&cli.config)?;
            let transport = if stdio {
                Transport::Stdio
            } else if http {
                Transport::Https
            } else {
                s.raw.server.transport
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .max_blocking_threads(s.limits().max_concurrent_requests * 2 + 4)
                .enable_all()
                .build()?;
            rt.block_on(async move {
                let app = App::new(s)?;
                match transport {
                    Transport::Stdio => grepcp::transport::server::serve_stdio(app).await,
                    Transport::Https => grepcp::transport::http::serve_https(app).await,
                }
            })
        }
    }
}
