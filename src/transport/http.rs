//! HTTPS transport: rustls served directly (no plain-HTTP listener), MCP Streamable HTTP at `/mcp`,
//! per-client-IP rate limit, Origin/Host checks, certificate hot reload (file watch and/or SIGHUP),
//! graceful shutdown.
//!
//! There is no application-level authentication: access control is the network (firewall, VPN,
//! or a fronting proxy) plus optional mTLS (`[server.tls] client_ca`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_server::tls_rustls::RustlsConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio_util::sync::CancellationToken;

use crate::app::App;
use crate::config::{TlsReload, TlsSection};
use crate::transport::server::{Caller, GrepServer};

/// Rate-limit entries kept before stale ones (older than a minute) are pruned.
const RATE_TABLE_PRUNE_AT: usize = 10_000;

#[derive(Clone)]
struct ClientState {
    rate: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
    per_minute: u32,
}

/// Identifies the caller by client IP (audit log, rate limit). Requests without connection info
/// (in-process tests) share the key "unknown".
async fn client(State(st): State<ClientState>, mut req: Request, next: Next) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    {
        let mut rate = st.rate.lock().unwrap();
        if rate.len() >= RATE_TABLE_PRUNE_AT {
            rate.retain(|_, (start, _)| start.elapsed() < Duration::from_secs(60));
        }
        let e = rate.entry(ip.clone()).or_insert((Instant::now(), 0));
        if e.0.elapsed() >= Duration::from_secs(60) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        if e.1 > st.per_minute {
            let retry = 60u64.saturating_sub(e.0.elapsed().as_secs()).max(1);
            let mut r = (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
            if let Ok(v) = HeaderValue::from_str(&retry.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            return r;
        }
    }
    req.extensions_mut().insert(Caller(format!("https:{ip}")));
    next.run(req).await
}

async fn reload_tls(rustls: &RustlsConfig, t: &TlsSection) {
    match crate::transport::tls::load(t) {
        Ok(l) => {
            rustls.reload_from_config(Arc::new(l.config));
            tracing::info!(not_after = %l.not_after, "TLS certificate reloaded");
            warn_expiry(l.not_after);
        }
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "TLS reload failed; keeping the previous certificate")
        }
    }
}

fn warn_expiry(not_after: chrono::DateTime<chrono::Utc>) {
    let left = not_after - chrono::Utc::now();
    if left < chrono::Duration::days(14) {
        tracing::warn!(%not_after, days_left = left.num_days(), "TLS certificate expires soon");
    }
}

/// Watches the cert/key parent directories (renewals usually replace files by rename).
fn spawn_cert_watcher(t: TlsSection, rustls: RustlsConfig) -> anyhow::Result<()> {
    use notify::{RecursiveMode, Watcher};
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let targets: Vec<PathBuf> = [&t.cert, &t.key]
        .iter()
        .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()))
        .collect();
    let names: Vec<std::ffi::OsString> = [&t.cert, &t.key]
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_owned()))
        .collect();
    let mut watcher = notify::recommended_watcher(move |ev: notify::Result<notify::Event>| {
        if let Ok(ev) = ev
            && ev.paths.iter().any(|p| {
                targets.contains(p) || p.file_name().is_some_and(|n| names.iter().any(|x| x == n))
            })
        {
            let _ = tx.send(());
        }
    })?;
    let mut dirs: Vec<PathBuf> = [&t.cert, &t.key]
        .iter()
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect();
    dirs.sort();
    dirs.dedup();
    for d in &dirs {
        watcher
            .watch(d, RecursiveMode::NonRecursive)
            .with_context(|| format!("watching {}", d.display()))?;
    }
    tokio::spawn(async move {
        let _watcher = watcher; // keep alive
        while rx.recv().await.is_some() {
            // Debounce: renewals touch cert and key in quick succession.
            tokio::time::sleep(Duration::from_secs(2)).await;
            while rx.try_recv().is_ok() {}
            reload_tls(&rustls, &t).await;
        }
    });
    Ok(())
}

#[cfg(unix)]
fn spawn_sighup(t: TlsSection, rustls: RustlsConfig) -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            tracing::info!("SIGHUP: reloading TLS certificate");
            if t.reload != TlsReload::Off {
                reload_tls(&rustls, &t).await;
            }
        }
    });
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

/// Builds the axum router (exposed for tests).
pub fn router(app: Arc<App>, ct: CancellationToken) -> Router {
    let srv = &app.settings.raw.server;
    let mut cfg = StreamableHttpServerConfig::default()
        .with_cancellation_token(ct)
        .with_allowed_origins(srv.allowed_origins.clone());
    cfg = if srv.allowed_hosts.is_empty() {
        cfg.disable_allowed_hosts()
    } else {
        cfg.with_allowed_hosts(srv.allowed_hosts.clone())
    };
    let client_state = ClientState {
        rate: Arc::new(Mutex::new(HashMap::new())),
        per_minute: srv.rate_limit_per_minute.max(1),
    };
    let app2 = app.clone();
    let mcp = StreamableHttpService::new(
        move || Ok(GrepServer::new(app2.clone(), "https:unknown")),
        Arc::new(LocalSessionManager::default()),
        cfg,
    );
    Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(client_state, client))
        .route("/healthz", get(|| async { "ok" }))
}

pub async fn serve_https(app: Arc<App>) -> anyhow::Result<()> {
    let s = app.settings.clone();
    let srv = &s.raw.server;
    let tls = srv
        .tls
        .clone()
        .ok_or_else(|| anyhow!("https transport requires [server.tls]"))?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    let loaded = crate::transport::tls::load(&tls)?;
    warn_expiry(loaded.not_after);
    let rustls = RustlsConfig::from_config(Arc::new(loaded.config));

    if tls.reload == TlsReload::Watch {
        spawn_cert_watcher(tls.clone(), rustls.clone())?;
    }
    #[cfg(unix)]
    spawn_sighup(tls.clone(), rustls.clone())?;

    let addr: SocketAddr = srv
        .bind
        .parse()
        .with_context(|| format!("server.bind '{}'", srv.bind))?;
    let ct = CancellationToken::new();
    let router = router(app.clone(), ct.clone());

    let handle = axum_server::Handle::new();
    {
        let handle = handle.clone();
        let ct = ct.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutting down");
            ct.cancel();
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });
    }
    tracing::info!(%addr, box_name = s.box_name(), "grepcp listening (https, MCP at /mcp)");
    if tls.client_ca.is_none() {
        tracing::warn!(
            "no client authentication: anyone who can reach {addr} can search these logs; restrict it with a firewall/VPN or set [server.tls] client_ca"
        );
    }
    axum_server::bind_rustls(addr, rustls)
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("https server")?;
    Ok(())
}
