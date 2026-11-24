//! `grepcp doctor`: checks the config's assumptions against the real box and prints findings.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use chrono::{Offset, Utc};

use crate::config::{Settings, SuffixMarks, Transport};
use crate::engine::extract;
use crate::engine::output::human_bytes;
use crate::engine::reader::{self, Guard};
use crate::logs::catalog::{Catalog, Compression, LogFile};
use crate::parse::time::{Ts, fmt_local};

const SAMPLE_SERVICES: usize = 5;
/// Rotated files larger than this are skipped for the first/last timestamp probe.
const PROBE_MAX_BYTES: u64 = 256 * 1024 * 1024;

struct Report {
    out: String,
    warnings: usize,
}

impl Report {
    fn ok(&mut self, s: impl AsRef<str>) {
        let _ = writeln!(self.out, "[ok]   {}", s.as_ref());
    }
    fn info(&mut self, s: impl AsRef<str>) {
        let _ = writeln!(self.out, "[info] {}", s.as_ref());
    }
    fn warn(&mut self, s: impl AsRef<str>) {
        self.warnings += 1;
        let _ = writeln!(self.out, "[warn] {}", s.as_ref());
    }
    fn section(&mut self, s: &str) {
        let _ = writeln!(self.out, "\n== {s}");
    }
}

pub fn run(settings: Arc<Settings>) -> anyhow::Result<(String, usize)> {
    let mut r = Report {
        out: String::new(),
        warnings: 0,
    };
    let s = &settings;
    let now = Utc::now();

    r.section("system");
    r.info(format!(
        "arch={} os={} → build target {}-unknown-linux-musl",
        std::env::consts::ARCH,
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    let user = std::env::var("USER").unwrap_or_else(|_| "?".into());
    #[cfg(unix)]
    let euid = unsafe { libc::geteuid() };
    #[cfg(not(unix))]
    let euid = 1u32;
    if euid == 0 {
        r.warn("running as root; the service must run as the dedicated 'grepcp' user");
    } else {
        r.info(format!("running as user={user} uid={euid}"));
    }
    let sys_off = chrono::Local::now().offset().fix().local_minus_utc();
    let cfg_off = now.with_timezone(&s.tz).offset().fix().local_minus_utc();
    if sys_off == cfg_off {
        r.ok(format!(
            "config timezone {} matches the system offset ({:+}h)",
            s.raw.timezone,
            sys_off as f64 / 3600.0
        ));
    } else {
        r.warn(format!(
            "config timezone {} ({:+}h) differs from the system offset ({:+}h); filename suffixes are usually written in system time",
            s.raw.timezone,
            cfg_off as f64 / 3600.0,
            sys_off as f64 / 3600.0
        ));
    }

    r.section("layout");
    let catalog = match Catalog::new(settings.clone()) {
        Ok(c) => c,
        Err(e) => {
            r.warn(format!("cannot open root: {e}"));
            return Ok((r.out, r.warnings));
        }
    };
    let services = catalog
        .list_services()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let readable: Vec<_> = services.iter().filter(|e| e.readable).collect();
    let unreadable: Vec<_> = services
        .iter()
        .filter(|e| !e.readable)
        .map(|e| e.name.as_str())
        .collect();
    r.info(format!(
        "root {}: {} service dirs, {} readable",
        catalog.root().display(),
        services.len(),
        readable.len()
    ));
    if !unreadable.is_empty() {
        r.warn(format!(
            "unreadable service dirs: {}",
            unreadable.join(", ")
        ));
    }

    let mut all_files: Vec<(String, Vec<Arc<LogFile>>)> = Vec::new();
    let mut unmatched_total = 0;
    for e in &readable {
        match catalog.files(&e.name) {
            Ok(sf) => {
                if !sf.unmatched.is_empty() {
                    unmatched_total += sf.unmatched.len();
                    r.warn(format!(
                        "{}: {} names do not match file_regex, e.g. {}",
                        e.name,
                        sf.unmatched.len(),
                        sf.unmatched
                            .iter()
                            .take(3)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                all_files.push((e.name.clone(), sf.files.clone()));
            }
            Err(err) => r.warn(format!("{}: {err}", e.name)),
        }
    }
    if unmatched_total == 0 {
        r.ok("every file name matches layout.file_regex");
    }
    let delay: usize = all_files
        .iter()
        .map(|(_, f)| {
            f.iter()
                .filter(|f| !f.live && f.compression == Compression::None)
                .count()
        })
        .sum();
    r.info(format!(
        "{delay} uncompressed rotated files (delaycompress or compression in progress)"
    ));

    let oldest: Option<Ts> = all_files
        .iter()
        .flat_map(|(_, f)| f.iter().filter_map(|f| f.suffix_at))
        .min();
    if let Some(o) = oldest {
        let days = (now - o).num_hours() as f64 / 24.0;
        let msg = format!(
            "oldest rotated file: {} ({days:.1} days); configured retention {} days",
            fmt_local(o, &s.tz),
            s.raw.rotation.retention_days
        );
        if days + 1.0 < s.raw.rotation.retention_days as f64 {
            r.warn(format!("{msg}: retention may be shorter than configured"));
        } else {
            r.info(msg);
        }
    }

    r.section("sizes (largest rotated file per service)");
    let mut biggest: Vec<(u64, String, String)> = all_files
        .iter()
        .filter_map(|(svc, f)| {
            f.iter()
                .filter(|f| !f.live)
                .max_by_key(|f| f.size)
                .map(|f| (f.size, svc.clone(), f.name.clone()))
        })
        .collect();
    biggest.sort_by(|a, b| b.0.cmp(&a.0));
    for (sz, svc, name) in biggest.iter().take(10) {
        r.info(format!("{:>10}  {svc}/{name}", human_bytes(*sz)));
    }
    if let Some((sz, ..)) = biggest.first() {
        let hosts_max = all_files
            .iter()
            .map(|(_, f)| f.iter().filter(|f| f.live).count())
            .max()
            .unwrap_or(1) as u64;
        r.info(format!(
            "rough worst case for one service, one bucket, all hosts: {} (max_scan_bytes = {})",
            human_bytes(sz * hosts_max),
            human_bytes(s.limits().max_scan_bytes)
        ));
    }

    let guard = Guard::new(Instant::now() + StdDuration::from_secs(120));

    r.section("line format");
    match &s.line {
        None => r.warn(
            "no [line] section: no in-file time filtering, sorting by time, or minute counts",
        ),
        Some(p) => {
            let mut tested = 0;
            let mut parsed = 0;
            for (svc, files) in all_files.iter().take(SAMPLE_SERVICES) {
                let Some(live) = files.iter().find(|f| f.live && f.size > 0) else {
                    continue;
                };
                if let Ok((lines, _)) = extract::tail(live, 3, None, 1 << 20, 512, &guard) {
                    for l in lines {
                        tested += 1;
                        let ts = p.parse_ts(&l.text, now);
                        if ts.is_some() {
                            parsed += 1;
                        }
                        let sample =
                            String::from_utf8_lossy(&l.text[..l.text.len().min(160)]).into_owned();
                        r.info(format!(
                            "{svc}: ts={} | {sample}",
                            ts.map(|t| fmt_local(t, &s.tz))
                                .unwrap_or_else(|| "UNPARSED".into())
                        ));
                    }
                }
            }
            if tested == 0 {
                r.warn("no non-empty live files to sample");
            } else if parsed == tested {
                r.ok(format!(
                    "timestamp_regex parsed {parsed}/{tested} sampled lines"
                ));
            } else {
                r.warn(format!(
                    "timestamp_regex parsed only {parsed}/{tested} sampled lines (continuation lines are expected to fail)"
                ));
            }
        }
    }

    r.section("rotation suffix semantics");
    match &s.line {
        None => r.info("skipped (needs [line] to read timestamps)"),
        Some(p) => {
            let mut votes_end = 0;
            let mut votes_start = 0;
            for (svc, files) in all_files.iter().take(SAMPLE_SERVICES * 2) {
                let Some(f) = files
                    .iter()
                    .filter(|f| !f.live && f.size > 0 && f.size <= PROBE_MAX_BYTES)
                    .max_by_key(|f| f.suffix_at)
                else {
                    continue;
                };
                let Some(t) = f.suffix_at else { continue };
                match first_last_ts(f, p, now, &guard) {
                    Some((first, last)) => {
                        let b = s.bucket;
                        let end_fit = first >= t - b - chrono::Duration::minutes(5)
                            && last <= t + chrono::Duration::minutes(15);
                        let start_fit = first >= t - chrono::Duration::minutes(5)
                            && last <= t + b + chrono::Duration::minutes(15);
                        if end_fit && !start_fit {
                            votes_end += 1;
                        } else if start_fit && !end_fit {
                            votes_start += 1;
                        }
                        r.info(format!(
                            "{svc}/{}: suffix {} first {} last {}",
                            f.name,
                            fmt_local(t, &s.tz),
                            fmt_local(first, &s.tz),
                            fmt_local(last, &s.tz)
                        ));
                    }
                    None => r.info(format!("{svc}/{}: no parseable timestamps", f.name)),
                }
            }
            let configured = s.raw.rotation.suffix_marks;
            let rec = if votes_end > votes_start {
                Some(SuffixMarks::End)
            } else if votes_start > votes_end {
                Some(SuffixMarks::Start)
            } else {
                None
            };
            match rec {
                Some(m) if m == configured => {
                    r.ok(format!("suffix_marks = {configured:?} confirmed ({votes_end} end / {votes_start} start)"));
                    if s.raw.rotation.include_adjacent_bucket {
                        r.info("include_adjacent_bucket can likely be set to false (fewer files scanned)");
                    }
                }
                Some(m) => r.warn(format!(
                    "samples suggest suffix_marks = {m:?} but config has {configured:?} ({votes_end} end / {votes_start} start)"
                )),
                None => r.info("inconclusive; keep include_adjacent_bucket = true"),
            }
        }
    }

    r.section("permissions");
    let mut unreadable_files = 0;
    let mut newest_checked = 0;
    for (svc, files) in &all_files {
        if let Some(f) = files.iter().filter(|f| !f.live).max_by_key(|f| f.suffix_at) {
            newest_checked += 1;
            if std::fs::File::open(&f.path).is_err() {
                unreadable_files += 1;
                r.warn(format!(
                    "{svc}/{}: newest rotated file is not readable (check default ACLs)",
                    f.name
                ));
            }
        }
    }
    if unreadable_files == 0 {
        r.ok(format!(
            "newest rotated file readable in {newest_checked} services"
        ));
    }

    r.section("server");
    let srv = &s.raw.server;
    match srv.transport {
        Transport::Stdio => r.info("transport = stdio"),
        Transport::Https => {
            if let Some(tls) = &srv.tls {
                if tls.client_ca.is_none() {
                    r.warn(format!(
                        "no client authentication on {}: anyone who can reach this port can search the logs; restrict it with a firewall/VPN or set [server.tls] client_ca",
                        srv.bind
                    ));
                } else {
                    r.ok("client certificates required (mTLS)");
                }
                if let Err(e) = crate::transport::tls::check_key_permissions(&tls.key) {
                    r.warn(format!("{e:#}"));
                }
                match crate::transport::tls::load_certs(&tls.cert)
                    .and_then(|c| crate::transport::tls::not_after(&c[0]))
                {
                    Ok(na) => {
                        let days = (na - now).num_days();
                        if days < 0 {
                            r.warn(format!("certificate EXPIRED at {na}"));
                        } else if days < 14 {
                            r.warn(format!("certificate expires in {days} days ({na})"));
                        } else {
                            r.ok(format!("certificate valid until {na} ({days} days)"));
                        }
                    }
                    Err(e) => r.warn(format!("{e:#}")),
                }
            }
        }
    }

    let _ = writeln!(r.out, "\n{} warning(s)", r.warnings);
    Ok((r.out, r.warnings))
}

/// First and last parseable timestamps of a file (streams the whole file).
fn first_last_ts(
    f: &LogFile,
    p: &crate::parse::line::LineParser,
    now: Ts,
    guard: &Guard,
) -> Option<(Ts, Ts)> {
    let opened = reader::open(f, 0, guard, false).ok()?;
    let mut rd = BufReader::with_capacity(256 * 1024, opened.reader);
    let mut buf = Vec::new();
    let mut first = None;
    let mut last = None;
    loop {
        buf.clear();
        match rd.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if let Some(t) = p.parse_ts(&buf, now) {
                    first.get_or_insert(t);
                    last = Some(t);
                }
            }
        }
    }
    Some((first?, last?))
}
