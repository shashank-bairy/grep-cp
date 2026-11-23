//! The one search pipeline shared by grep_logs, count_matches, grep_by_id and locate:
//! resolve window and services → validate → compile → plan → run on the shared pool.
//!
//! Everything after the request's arguments are parsed — including catalog scans (directory
//! listings and stats) and planning — runs on a blocking thread, under the global concurrency
//! permit and the request deadline, never on the async runtime threads.

use std::sync::Arc;

use chrono::Duration;

use super::{
    CallCtx, NO_LINE_CFG_WARNING, TimeParams, check_range, now, resolve_services, resolve_window,
    run_blocking, stop_warning, timeout,
};
use crate::app::App;
use crate::engine::output::human_bytes;
use crate::engine::{self, Guard, Job, Mode, Outcome, PatternSpec, build_matcher};
use crate::errors::{ToolError, ToolResult};
use crate::logs::planner;
use crate::parse::time::Window;

/// Which services to search.
pub enum Services {
    /// `service` / `services` from the caller, falling back to the ID decoder's services.
    Given {
        service: Option<String>,
        services: Option<Vec<String>>,
    },
    /// The given services, or every readable service when none are given (`locate`).
    GivenOrAll(Option<Vec<String>>),
}

/// What to do when the planned files exceed the scan budget.
pub enum Budget {
    /// Refuse the request (grep_logs, count_matches).
    Refuse(u64),
    /// Search newest files first and drop the rest (locate).
    NewestFirst(u64),
}

pub struct SearchSpec {
    pub tool: &'static str,
    pub services: Services,
    pub time: TimeParams,
    pub id: Option<String>,
    pub default_window: Duration,
    pub max_range_hours: u32,
    pub pattern: PatternSpec,
    pub invert: bool,
    pub hosts: Option<Vec<String>>,
    pub budget: Budget,
    pub mode: Mode,
    pub keep_bytes: usize,
    pub timeout_secs: Option<u64>,
}

pub struct Searched {
    pub services: Vec<String>,
    /// Window after retention clamping.
    pub window: Window,
    pub skipped_by_time: usize,
    /// Files dropped by a NewestFirst budget.
    pub budget_hit: bool,
    pub outcome: Outcome,
    /// Planner, engine and stop warnings, in that order.
    pub warnings: Vec<String>,
}

pub async fn search(app: &Arc<App>, ctx: &CallCtx, spec: SearchSpec) -> ToolResult<Searched> {
    let t = timeout(app, spec.timeout_secs);
    let app2 = app.clone();
    run_blocking(app, ctx, t, move |guard| {
        prepare_and_run(&app2, spec, guard)
    })
    .await?
}

fn prepare_and_run(app: &App, spec: SearchSpec, guard: Guard) -> ToolResult<Searched> {
    let s = &app.settings;
    let l = s.limits();
    let now = now();
    let mut warnings = Vec::new();

    let rw = resolve_window(
        app,
        &spec.time,
        spec.id.as_deref(),
        Some(spec.default_window),
        now,
        &mut warnings,
    )?;
    let services = match spec.services {
        Services::Given { service, services } => resolve_services(
            app,
            service.as_deref(),
            services.as_deref(),
            &rw.id_services,
        )?,
        Services::GivenOrAll(Some(v)) if !v.is_empty() => {
            resolve_services(app, None, Some(&v), &[])?
        }
        Services::GivenOrAll(_) => app
            .catalog
            .list_services()?
            .iter()
            .filter(|e| e.readable)
            .map(|e| e.name.clone())
            .collect(),
    };
    check_range(&rw.window, spec.max_range_hours, spec.tool, &s.tz)?;
    let matcher = build_matcher(&spec.pattern, l.regex_size_limit)?;

    let refuse_over = match spec.budget {
        Budget::Refuse(b) => Some(b),
        Budget::NewestFirst(_) => None,
    };
    let mut plan = planner::plan(
        &app.catalog,
        &services,
        &rw.window,
        spec.hosts.as_deref(),
        now,
        refuse_over,
    )?;
    if guard.stopped() {
        // The deadline passed while scanning directories.
        return Err(ToolError::Stopped(
            stop_warning(guard.stop.get()).unwrap_or_else(|| "stopped".into()),
        ));
    }

    let mut budget_hit = false;
    if let Budget::NewestFirst(limit) = spec.budget {
        // A recent ID is most likely in the newest files (live files sort last, so reverse).
        plan.files.sort_by(|a, b| {
            b.group_key()
                .cmp(&a.group_key())
                .then_with(|| a.service.cmp(&b.service))
        });
        let mut used = 0u64;
        let total = plan.files.len();
        plan.files.retain(|f| {
            used += f.size;
            used <= limit
        });
        budget_hit = plan.files.len() < total;
        if budget_hit {
            warnings.push(format!(
                "scan budget ({}) reached: {} of {total} files searched (newest first); pass services or a narrower window",
                human_bytes(limit),
                plan.files.len()
            ));
        }
    }
    warnings.extend(plan.warnings.iter().cloned());
    if s.line.is_none() {
        warnings.push(NO_LINE_CFG_WARNING.into());
    }

    let job = Job {
        files: plan.files.clone(),
        matcher,
        invert: spec.invert,
        window: plan.window.clone(),
        mode: spec.mode,
        parser: s.line.clone(),
        workers: l.workers_per_request,
        guard,
        keep_bytes: spec.keep_bytes,
        copytruncate: s.raw.rotation.live_file_copytruncate,
        now,
    };
    let outcome = engine::run(job, &app.pool);
    warnings.extend(outcome.warnings.iter().cloned());
    warnings.extend(stop_warning(outcome.stopped));

    Ok(Searched {
        services,
        window: plan.window,
        skipped_by_time: plan.skipped_by_time,
        budget_hit,
        outcome,
        warnings,
    })
}
