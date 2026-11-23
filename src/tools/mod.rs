//! MCP tool implementations. Transport-agnostic: each tool takes parsed params and a call
//! context and returns structured JSON plus a compact text rendering.

pub mod direct;
pub mod info;
pub mod pipeline;
pub mod search;

pub(crate) const NO_LINE_CFG_WARNING: &str = "no [line] config: whole files overlapping the window are searched; lines are not time-filtered";

use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use chrono::{Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::app::App;
use crate::engine::{Guard, StopReason};
use crate::errors::{ToolError, ToolResult};
use crate::parse::id_decode;
use crate::parse::time::{Interval, TimeSpec, Ts, Window, fmt_local};

/// Per-call context supplied by the transport.
#[derive(Clone, Debug)]
pub struct CallCtx {
    pub cancel: CancellationToken,
    /// Token name (HTTPS) or `stdio:<user>`; recorded in the audit log.
    pub caller: String,
}

impl CallCtx {
    pub fn local(caller: &str) -> Self {
        Self {
            cancel: CancellationToken::new(),
            caller: caller.to_string(),
        }
    }
}

/// Numbers recorded in the audit log for each call.
#[derive(Clone, Debug, Default)]
pub struct AuditStats {
    pub files: usize,
    pub bytes: u64,
    pub matches: u64,
}

#[derive(Debug)]
pub struct ToolOutput {
    pub json: serde_json::Value,
    pub text: String,
    pub stats: AuditStats,
}

/// Time selector shared by the search tools. Use one style: `from`/`to`, `last`, or `date`
/// (+ `hours`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct TimeParams {
    /// Window start: RFC3339 (`2026-06-02T10:00:00Z`) or `YYYY-MM-DD HH:MM` in the box timezone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Window end (exclusive), same formats as `from`. Defaults to now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Relative window ending now, e.g. `30m`, `2h`, `1d`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    /// A day `YYYY-MM-DD` (box timezone). Alone it selects the whole day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// Hours of `date` to search (0-23), e.g. `[10, 11]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hours: Option<Vec<u32>>,
}

impl TimeParams {
    pub fn spec(&self) -> TimeSpec {
        TimeSpec {
            from: self.from.clone(),
            to: self.to.clone(),
            last: self.last.clone(),
            date: self.date.clone(),
            hours: self.hours.clone(),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct WindowOut {
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts: Option<Vec<[String; 2]>>,
}

pub fn window_out(w: &Window, app: &App) -> WindowOut {
    let tz = &app.settings.tz;
    let span = w.span();
    WindowOut {
        from: fmt_local(span.from, tz),
        to: fmt_local(span.to, tz),
        parts: (w.parts().len() > 1).then(|| {
            w.parts()
                .iter()
                .map(|p| [fmt_local(p.from, tz), fmt_local(p.to, tz)])
                .collect()
        }),
    }
}

/// Result of resolving the time inputs of a call.
pub struct ResolvedWindow {
    pub window: Window,
    /// Services suggested by an ID decoder, if the window came from an ID.
    pub id_services: Vec<String>,
}

/// Resolves the window from explicit time params, else from a decodable `id`, else `default`.
pub fn resolve_window(
    app: &App,
    time: &TimeParams,
    id: Option<&str>,
    default: Option<Duration>,
    now: Ts,
    warnings: &mut Vec<String>,
) -> ToolResult<ResolvedWindow> {
    let s = &app.settings;
    let mut id_services = Vec::new();
    let decoded = id.and_then(|id| id_decode::decode(&s.id_decoders, id, &s.tz));
    if let Some(d) = &decoded {
        id_services = d.decoder.services.clone();
    }
    if let Some(w) =
        crate::parse::time::resolve(&time.spec(), &s.tz, now).map_err(ToolError::InvalidArgument)?
    {
        return Ok(ResolvedWindow {
            window: w,
            id_services,
        });
    }
    if let Some(d) = decoded {
        warnings.push(format!(
            "window derived from id ({} decoder: {})",
            d.decoder.name,
            fmt_local(d.at, &s.tz)
        ));
        return Ok(ResolvedWindow {
            window: Window::single(d.interval()),
            id_services,
        });
    }
    if id.is_some() && default.is_none() {
        return Err(ToolError::InvalidArgument(
            "could not decode a time from this id; pass from/to, last or date".into(),
        ));
    }
    match default {
        Some(d) => {
            warnings.push(format!(
                "no time window given; defaulted to the last {}",
                fmt_dur(d)
            ));
            Ok(ResolvedWindow {
                window: Window::single(Interval::new(now - d, now + Duration::minutes(1))),
                id_services,
            })
        }
        None => Err(ToolError::InvalidArgument(
            "a time window is required: pass from/to, last or date".into(),
        )),
    }
}

pub fn fmt_dur(d: Duration) -> String {
    let m = d.num_minutes();
    if m % (60 * 24) == 0 {
        format!("{}d", m / (60 * 24))
    } else if m % 60 == 0 {
        format!("{}h", m / 60)
    } else {
        format!("{m}m")
    }
}

/// Rejects windows longer than `max_hours`, measured in local wall-clock time so a DST day
/// (23h or 25h of real time) counts as the 24 hours it looks like.
pub fn check_range(w: &Window, max_hours: u32, tool: &str, tz: &chrono_tz::Tz) -> ToolResult<()> {
    let max = Duration::hours(max_hours as i64);
    let wall: Duration = w
        .parts()
        .iter()
        .map(|p| p.to.with_timezone(tz).naive_local() - p.from.with_timezone(tz).naive_local())
        .fold(Duration::zero(), |a, b| a + b);
    if wall > max + Duration::minutes(1) {
        return Err(ToolError::WindowRejected(format!(
            "window is {} long; {tool} allows at most {max_hours}h. Narrow it, or use count_matches to find the busy hours first",
            fmt_dur(wall)
        )));
    }
    Ok(())
}

/// Validates `service` / `services` (at least one; falls back to `fallback`).
pub fn resolve_services(
    app: &App,
    service: Option<&str>,
    services: Option<&[String]>,
    fallback: &[String],
) -> ToolResult<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    if let Some(s) = service {
        names.push(s.to_string());
    }
    if let Some(ss) = services {
        names.extend(ss.iter().cloned());
    }
    if names.is_empty() {
        names.extend(fallback.iter().cloned());
    }
    if names.is_empty() {
        return Err(ToolError::InvalidArgument(
            "give 'service' or 'services' (use list_services, or locate to find where an identifier appears)".into(),
        ));
    }
    if names.len() > 20 {
        return Err(ToolError::InvalidArgument(
            "at most 20 services per call".into(),
        ));
    }
    let mut out = Vec::new();
    for n in names {
        let r = app.catalog.resolve_service(&n)?;
        if !out.contains(&r) {
            out.push(r);
        }
    }
    Ok(out)
}

pub fn timeout(app: &App, secs: Option<u64>) -> StdDuration {
    let l = app.settings.limits();
    StdDuration::from_secs(
        secs.unwrap_or(l.timeout_secs_default)
            .clamp(1, l.timeout_secs_max),
    )
}

/// Runs blocking work under a global slot, with cancellation wired to the guard.
pub async fn run_blocking<T: Send + 'static>(
    app: &Arc<App>,
    ctx: &CallCtx,
    timeout: StdDuration,
    f: impl FnOnce(Guard) -> T + Send + 'static,
) -> ToolResult<T> {
    let permit = app.acquire().await?;
    let guard = Guard::new(Instant::now() + timeout);
    // If this future is dropped (client gone, transport aborts the handler), stop the blocking
    // work too instead of letting it run on unobserved.
    let on_drop = StopOnDrop(Some(guard.stop.clone()));
    let stop = guard.stop.clone();
    let ct = ctx.cancel.clone();
    let watcher = tokio::spawn(async move {
        ct.cancelled().await;
        stop.set(StopReason::Cancelled);
    });
    // The permit moves into the blocking task, so the concurrency limit covers the work itself,
    // not just this future.
    let r = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f(guard)
    })
    .await;
    watcher.abort();
    on_drop.disarm();
    r.map_err(|e| ToolError::Internal(format!("search task failed: {e}")))
}

struct StopOnDrop(Option<Arc<crate::engine::reader::Stop>>);

impl StopOnDrop {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        if let Some(s) = &self.0 {
            s.set(StopReason::Cancelled);
        }
    }
}

/// Runs quick blocking work (catalog listings) off the async threads, without taking a search
/// slot.
pub async fn run_meta<T: Send + 'static>(
    f: impl FnOnce() -> ToolResult<T> + Send + 'static,
) -> ToolResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ToolError::Internal(format!("task failed: {e}")))?
}

pub fn now() -> Ts {
    Utc::now()
}

pub fn stop_warning(stopped: Option<StopReason>) -> Option<String> {
    match stopped {
        Some(StopReason::Timeout) => Some(
            "timeout: search stopped early; results are partial. Narrow the window or hosts, or raise timeout_secs".into(),
        ),
        Some(StopReason::Cancelled) => Some("cancelled by client; results are partial".into()),
        Some(StopReason::Enough) | None => None,
    }
}
