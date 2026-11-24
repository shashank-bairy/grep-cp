//! In-process service tests: HTTPS layer (per-client-IP rate limit, Host + Origin checks; axum
//! router driven with tower's `oneshot`), MCP cancellation, the busy path, and the DST-aware range
//! check.

#[path = "fixtures/gen.rs"]
mod fixtures;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use grep_cp::app::App;
use grep_cp::config::Settings;
use grep_cp::errors::ToolError;
use grep_cp::tools::search::GrepLogsParams;
use grep_cp::tools::{CallCtx, TimeParams};
use grep_cp::transport::http::router;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

fn app_with(fx: &fixtures::Fixture, edit: impl Fn(String) -> String) -> Arc<App> {
    let text = edit(std::fs::read_to_string(&fx.config).unwrap());
    App::new(Arc::new(Settings::from_toml(&text).unwrap())).unwrap()
}

fn init_request(ip: &str, host: &str, origin: Option<&str>) -> Request<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}
    });
    let mut b = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, host)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(o) = origin {
        b = b.header(header::ORIGIN, o);
    }
    let mut req = b.body(Body::from(body.to_string())).unwrap();
    // What axum-server's connect-info service inserts for a real connection.
    let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

async fn status(r: &axum::Router, req: Request<Body>) -> StatusCode {
    r.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn http_rate_limit_host_and_origin() {
    let fx = fixtures::build();
    let app = app_with(&fx, |t| {
        t.replace(
            "transport = \"stdio\"",
            "transport = \"stdio\"\nrate_limit_per_minute = 3\nallowed_hosts = [\"logs.example.com\"]\nallowed_origins = [\"https://app.example.com:443\"]",
        )
    });
    let host = "logs.example.com";

    let r = router(app.clone(), CancellationToken::new());
    let health = Request::builder()
        .uri("/healthz")
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap();
    assert_eq!(status(&r, health).await, StatusCode::OK);

    // No credentials needed; the rate limit is per client IP.
    for _ in 0..3 {
        assert_eq!(
            status(&r, init_request("10.0.0.1", host, None)).await,
            StatusCode::OK
        );
    }
    let resp = r
        .clone()
        .oneshot(init_request("10.0.0.1", host, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(
        status(&r, init_request("10.0.0.2", host, None)).await,
        StatusCode::OK,
        "another client IP has its own budget"
    );

    // Host (DNS rebinding) and Origin checks.
    let r = router(app.clone(), CancellationToken::new());
    assert_eq!(
        status(&r, init_request("10.0.0.3", "evil.example.com", None)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(
            &r,
            init_request("10.0.0.3", host, Some("https://evil.example.com"))
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(
            &r,
            init_request("10.0.0.3", host, Some("https://app.example.com"))
        )
        .await,
        StatusCode::OK
    );
}

fn grep_params() -> GrepLogsParams {
    GrepLogsParams {
        service: Some("orders".into()),
        pattern: "ERROR".into(),
        time: TimeParams {
            last: Some("3h".into()),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn cancelled_request_stops() {
    let fx = fixtures::build();
    let app = app_with(&fx, |t| t);
    let ctx = CallCtx::local("test");
    ctx.cancel.cancel();
    let r = grep_cp::tools::search::grep_logs(&app, grep_params(), &ctx).await;
    match r {
        Err(ToolError::Stopped(m)) => assert!(m.contains("cancelled"), "{m}"),
        Ok(out) => {
            // Cancellation raced past planning: the search itself must report it.
            assert_eq!(out.json["truncated"], true);
            assert!(out.text.contains("cancelled"), "{}", out.text);
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[tokio::test]
async fn busy_when_all_slots_are_taken() {
    let fx = fixtures::build();
    let app = app_with(&fx, |t| {
        t.replace(
            "[limits]",
            "[limits]\nmax_concurrent_requests = 1\nqueue_wait_secs = 0",
        )
    });
    let held = app.acquire().await.unwrap();
    let r = grep_cp::tools::search::grep_logs(&app, grep_params(), &CallCtx::local("test")).await;
    assert!(matches!(r, Err(ToolError::Busy(1))), "{r:?}");
    drop(held);
    let r = grep_cp::tools::search::grep_logs(&app, grep_params(), &CallCtx::local("test")).await;
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn dst_day_counts_as_24_hours() {
    let tz: chrono_tz::Tz = "Europe/Berlin".parse().unwrap();
    let now = grep_cp::parse::time::parse_instant("2026-12-01T00:00:00Z", &tz).unwrap();
    let w = grep_cp::parse::time::resolve(
        &grep_cp::parse::time::TimeSpec {
            date: Some("2026-10-25".into()),
            ..Default::default()
        },
        &tz,
        now,
    )
    .unwrap()
    .unwrap();
    assert_eq!(w.total_len(), chrono::Duration::hours(25));
    assert!(grep_cp::tools::check_range(&w, 24, "grep_logs", &tz).is_ok());
    assert!(grep_cp::tools::check_range(&w, 23, "grep_logs", &tz).is_err());
}
