//! HTTPS transport: rustls served directly (no plain-HTTP listener), MCP Streamable HTTP at `/mcp`,
//! bearer-token auth (SHA-256 hashes, constant-time compare), per-token rate limit, Origin/Host
//! checks, certificate hot reload (file watch and/or SIGHUP), graceful shutdown.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_server::tls_rustls::RustlsConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

use crate::app::App;
use crate::config::{TlsReload, TlsSection};
use crate::transport::server::{Caller, GrepServer};

pub type TokenTable = Vec<(String, [u8; 32])>;

pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Parses a tokens file: lines `<name>:<sha256-hex>`; blank lines and `#` comments are ignored.
pub fn parse_tokens(text: &str) -> anyhow::Result<TokenTable> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, hex_hash) = line
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("tokens line {}: expected <name>:<sha256-hex>", i + 1))?;
        let name = name.trim();
        if name.is_empty() {
            bail!("tokens line {}: empty name", i + 1);
        }
        let bytes = hex::decode(hex_hash.trim())
            .with_context(|| format!("tokens line {}: invalid hex", i + 1))?;
        let hash: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow!(
                "tokens line {}: hash must be 32 bytes (64 hex chars)",
                i + 1
            )
        })?;
        out.push((name.to_string(), hash));
    }
    Ok(out)
}

pub fn load_tokens(path: &Path) -> anyhow::Result<TokenTable> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let t = parse_tokens(&text).with_context(|| path.display().to_string())?;
    if t.is_empty() {
        bail!("{}: no tokens configured", path.display());
    }
    Ok(t)
}

/// Returns the token's name if it matches. Compares against every entry in constant time.
pub fn check_token(table: &TokenTable, token: &str) -> Option<String> {
    let h = hash_token(token);
    let mut found = None;
    for (name, expected) in table {
        if bool::from(expected.ct_eq(&h)) {
            found = Some(name.clone());
        }
    }
    found
}

#[derive(Clone)]
struct AuthState {
    tokens: Arc<RwLock<TokenTable>>,
    rate: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
    per_minute: u32,
}

fn unauthorized() -> Response {
    let mut r = (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response();
    r.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    r
}

async fn auth(State(st): State<AuthState>, mut req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
        });
    let Some(token) = token else {
        return unauthorized();
    };
    let Some(name) = check_token(&st.tokens.read().unwrap(), token) else {
        tracing::warn!(target: "grepcp::audit", outcome = "auth_failed", "rejected bearer token");
        return unauthorized();
    };
    {
        let mut rate = st.rate.lock().unwrap();
        let e = rate.entry(name.clone()).or_insert((Instant::now(), 0));
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
    req.extensions_mut().insert(Caller(name));
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
fn spawn_sighup(
    t: TlsSection,
    rustls: RustlsConfig,
    tokens_path: PathBuf,
    tokens: Arc<RwLock<TokenTable>>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            tracing::info!("SIGHUP: reloading tokens and TLS certificate");
            match load_tokens(&tokens_path) {
                Ok(t) => *tokens.write().unwrap() = t,
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "token reload failed; keeping previous tokens")
                }
            }
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
pub fn router(app: Arc<App>, tokens: Arc<RwLock<TokenTable>>, ct: CancellationToken) -> Router {
    let srv = &app.settings.raw.server;
    let mut cfg = StreamableHttpServerConfig::default()
        .with_cancellation_token(ct)
        .with_allowed_origins(srv.allowed_origins.clone());
    cfg = if srv.allowed_hosts.is_empty() {
        cfg.disable_allowed_hosts()
    } else {
        cfg.with_allowed_hosts(srv.allowed_hosts.clone())
    };
    let auth_state = AuthState {
        tokens,
        rate: Arc::new(Mutex::new(HashMap::new())),
        per_minute: srv.rate_limit_per_minute.max(1),
    };
    let app2 = app.clone();
    let mcp = StreamableHttpService::new(
        move || Ok(GrepServer::new(app2.clone(), "https:unauthenticated")),
        Arc::new(LocalSessionManager::default()),
        cfg,
    );
    Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(auth_state, auth))
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

    let tokens = Arc::new(RwLock::new(load_tokens(&srv.tokens_file)?));
    let loaded = crate::transport::tls::load(&tls)?;
    warn_expiry(loaded.not_after);
    let rustls = RustlsConfig::from_config(Arc::new(loaded.config));

    if tls.reload == TlsReload::Watch {
        spawn_cert_watcher(tls.clone(), rustls.clone())?;
    }
    #[cfg(unix)]
    spawn_sighup(
        tls.clone(),
        rustls.clone(),
        srv.tokens_file.clone(),
        tokens.clone(),
    )?;

    let addr: SocketAddr = srv
        .bind
        .parse()
        .with_context(|| format!("server.bind '{}'", srv.bind))?;
    let ct = CancellationToken::new();
    let router = router(app.clone(), tokens, ct.clone());

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
    axum_server::bind_rustls(addr, rustls)
        .handle(handle)
        .serve(router.into_make_service())
        .await
        .context("https server")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_roundtrip() {
        let h = hex::encode(hash_token("s3cret"));
        let t = parse_tokens(&format!("# comment\n\nalice:{h}\nbob:{}\n", "0".repeat(64))).unwrap();
        assert_eq!(check_token(&t, "s3cret").as_deref(), Some("alice"));
        assert_eq!(check_token(&t, "wrong"), None);
        assert!(parse_tokens("alice:zz").is_err());
        assert!(parse_tokens("nocolon").is_err());
        assert!(parse_tokens(":abcd").is_err());
    }
}
