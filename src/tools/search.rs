//! grep_logs, count_matches, grep_by_id, locate.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Instant;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::pipeline::{Budget, SearchSpec, Services, search};
use super::{AuditStats, CallCtx, TimeParams, ToolOutput, WindowOut, window_out};
use crate::app::App;
use crate::engine::output::{clean, human_bytes};
use crate::engine::{Found, Mode, Order, PatternSpec};
use crate::errors::{ToolError, ToolResult};
use crate::parse::time::{Ts, fmt_local, fmt_minute};

/// Most groups count_matches returns (keeps results readable for a model).
const MAX_GROUPS: usize = 200;
/// Candidate widths (minutes) for group_by = minute, finest first.
const MINUTE_STEPS: [i64; 9] = [1, 5, 15, 30, 60, 120, 360, 720, 1440];

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OrderParam {
    /// Earliest matches first (stops early once enough are found).
    #[default]
    First,
    /// Latest matches (reads the whole window).
    Last,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct GrepLogsParams {
    /// Service (directory) to search. Use `services` for several.
    #[serde(default)]
    pub service: Option<String>,
    /// Several services to search in one call.
    #[serde(default)]
    pub services: Option<Vec<String>>,
    /// Text to search for. A literal unless `fixed_string` is false.
    pub pattern: String,
    /// Treat `pattern` as a literal (default true). Set false for a regex.
    #[serde(default)]
    pub fixed_string: Option<bool>,
    #[serde(default)]
    pub ignore_case: Option<bool>,
    /// Return lines that do NOT match.
    #[serde(default)]
    pub invert: Option<bool>,
    #[serde(flatten)]
    pub time: TimeParams,
    /// Only these hosts (as shown by list_files).
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    /// Context lines before each match.
    #[serde(default)]
    pub before: Option<usize>,
    /// Context lines after each match.
    #[serde(default)]
    pub after: Option<usize>,
    #[serde(default)]
    pub max_lines: Option<usize>,
    /// `first` (default) or `last`.
    #[serde(default)]
    pub order: Option<OrderParam>,
    /// An identifier with an embedded time; scopes the window when no time is given.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Serialize, Debug)]
pub struct LineOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub host: String,
    pub file: String,
    pub byte_offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    pub text: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context_before: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context_after: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<BTreeMap<String, String>>,
}

#[derive(Serialize, Debug)]
pub struct GrepResult {
    #[serde(rename = "box")]
    pub box_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
    pub window: WindowOut,
    pub files_scanned: usize,
    pub files_skipped_by_time: usize,
    pub bytes_scanned: u64,
    pub matched_lines: usize,
    pub truncated: bool,
    pub elapsed_ms: u128,
    pub lines: Vec<LineOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

fn svc_fields(services: &[String]) -> (Option<String>, Option<Vec<String>>) {
    if services.len() == 1 {
        (Some(services[0].clone()), None)
    } else {
        (None, Some(services.to_vec()))
    }
}

pub async fn grep_logs(app: &Arc<App>, p: GrepLogsParams, ctx: &CallCtx) -> ToolResult<ToolOutput> {
    let started = Instant::now();
    let s = &app.settings;
    let l = s.limits();
    let pattern = if p.pattern.is_empty() {
        p.id.clone().unwrap_or_default()
    } else {
        p.pattern.clone()
    };
    let order = match p.order.unwrap_or_default() {
        OrderParam::First => Order::First,
        OrderParam::Last => Order::Last,
    };
    let r = search(
        app,
        ctx,
        SearchSpec {
            tool: "grep_logs",
            services: Services::Given {
                service: p.service.clone(),
                services: p.services.clone(),
            },
            time: p.time.clone(),
            id: p.id.clone(),
            default_window: chrono::Duration::hours(1),
            max_range_hours: l.max_range_hours,
            pattern: PatternSpec {
                pattern,
                fixed_string: p.fixed_string.unwrap_or(true),
                ignore_case: p.ignore_case.unwrap_or(false),
            },
            invert: p.invert.unwrap_or(false),
            hosts: p.hosts.clone(),
            budget: Budget::Refuse(l.max_scan_bytes),
            mode: Mode::Lines {
                order,
                max_lines: p
                    .max_lines
                    .unwrap_or(l.max_lines_default)
                    .clamp(1, l.max_lines_hard),
                max_bytes: l.max_bytes,
                before: p.before.unwrap_or(0).min(l.max_context),
                after: p.after.unwrap_or(0).min(l.max_context),
            },
            keep_bytes: l.max_line_bytes * 2,
            timeout_secs: p.timeout_secs,
        },
    )
    .await?;
    let (services, outcome, warnings) = (r.services, r.outcome, r.warnings);

    let multi = services.len() > 1;
    let lines: Vec<LineOut> = outcome
        .hits
        .iter()
        .map(|f| line_out(app, f, multi))
        .collect();
    let (service, services_out) = svc_fields(&services);
    let res = GrepResult {
        box_name: s.box_name().to_string(),
        service,
        services: services_out,
        window: window_out(&r.window, app),
        files_scanned: outcome.files_scanned,
        files_skipped_by_time: r.skipped_by_time,
        bytes_scanned: outcome.bytes_scanned,
        matched_lines: lines.len(),
        truncated: outcome.truncated,
        elapsed_ms: started.elapsed().as_millis(),
        lines,
        warnings,
    };
    let text = render_grep(&res);
    Ok(ToolOutput {
        stats: AuditStats {
            files: res.files_scanned,
            bytes: res.bytes_scanned,
            matches: res.matched_lines as u64,
        },
        json: serde_json::to_value(&res).map_err(|e| ToolError::Internal(e.to_string()))?,
        text,
    })
}

fn line_out(app: &App, f: &Found, multi: bool) -> LineOut {
    let s = &app.settings;
    // Everything returned, fields included, is derived from the cleaned (ANSI-stripped,
    // redacted, truncated) text, never from the raw bytes.
    let text = clean(&f.hit.text, s);
    let fields = s
        .line
        .as_ref()
        .filter(|p| p.has_fields())
        .and_then(|p| p.fields(text.as_bytes()));
    LineOut {
        service: multi.then(|| f.file.service.clone()),
        host: f.file.host.clone(),
        file: f.file.name.clone(),
        byte_offset: f.hit.byte_offset,
        ts: f.hit.ts.map(|t| fmt_local(t, &s.tz)),
        context_before: f.hit.before.iter().map(|l| clean(l, s)).collect(),
        context_after: f.hit.after.iter().map(|l| clean(l, s)).collect(),
        fields,
        text,
    }
}

fn header(
    out: &mut String,
    box_name: &str,
    service: &Option<String>,
    services: &Option<Vec<String>>,
    w: &WindowOut,
) {
    let svc = match (service, services) {
        (Some(s), _) => s.clone(),
        (None, Some(v)) => v.join(","),
        _ => String::new(),
    };
    let _ = write!(
        out,
        "box={box_name} service={svc} window={} → {}",
        w.from, w.to
    );
}

fn render_grep(r: &GrepResult) -> String {
    let mut out = String::new();
    header(&mut out, &r.box_name, &r.service, &r.services, &r.window);
    let _ = writeln!(
        out,
        " | files={} (skipped {}) scanned={} lines={}{} | {}ms",
        r.files_scanned,
        r.files_skipped_by_time,
        human_bytes(r.bytes_scanned),
        r.matched_lines,
        if r.truncated { " (truncated)" } else { "" },
        r.elapsed_ms
    );
    for w in &r.warnings {
        let _ = writeln!(out, "! {w}");
    }
    let has_ctx = r
        .lines
        .iter()
        .any(|l| !l.context_before.is_empty() || !l.context_after.is_empty());
    for l in &r.lines {
        let svc = l
            .service
            .as_deref()
            .map(|s| format!("{s}/"))
            .unwrap_or_default();
        if has_ctx {
            let _ = writeln!(out, "--- {svc}{} {}@{}", l.host, l.file, l.byte_offset);
            for c in &l.context_before {
                let _ = writeln!(out, "  {c}");
            }
            let _ = writeln!(out, "> {}", l.text);
            for c in &l.context_after {
                let _ = writeln!(out, "  {c}");
            }
        } else {
            let _ = writeln!(
                out,
                "[{svc}{} {}@{}] {}",
                l.host, l.file, l.byte_offset, l.text
            );
        }
    }
    if r.lines.is_empty() {
        out.push_str("(no matches)\n");
    }
    out
}

// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GroupBy {
    File,
    Host,
    /// Rotation bucket (e.g. hour) of the file.
    #[default]
    Bucket,
    /// Minute of the line timestamp (needs [line] config).
    Minute,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct CountParams {
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub services: Option<Vec<String>>,
    pub pattern: String,
    /// Treat `pattern` as a literal (default true).
    #[serde(default)]
    pub fixed_string: Option<bool>,
    #[serde(default)]
    pub ignore_case: Option<bool>,
    #[serde(default)]
    pub invert: Option<bool>,
    #[serde(flatten)]
    pub time: TimeParams,
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    /// `bucket` (default), `file`, `host` or `minute`. Minute counts are coarsened automatically
    /// (5m, 15m, 1h, ...) to stay within 200 groups.
    #[serde(default)]
    pub group_by: Option<GroupBy>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Serialize, Debug)]
pub struct CountGroup {
    pub key: String,
    pub count: u64,
}

#[derive(Serialize, Debug)]
pub struct CountResult {
    #[serde(rename = "box")]
    pub box_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
    pub window: WindowOut,
    pub group_by: GroupBy,
    /// Group width in minutes when group_by = minute (after automatic coarsening).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_minutes: Option<i64>,
    pub total: u64,
    pub groups: Vec<CountGroup>,
    pub files_scanned: usize,
    pub files_skipped_by_time: usize,
    pub bytes_scanned: u64,
    pub truncated: bool,
    pub elapsed_ms: u128,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub async fn count_matches(
    app: &Arc<App>,
    p: CountParams,
    ctx: &CallCtx,
) -> ToolResult<ToolOutput> {
    let started = Instant::now();
    let s = &app.settings;
    let l = s.limits();
    let group_by = p.group_by.unwrap_or_default();
    if group_by == GroupBy::Minute && s.line.is_none() {
        return Err(ToolError::InvalidArgument(
            "group_by=minute needs line timestamp parsing ([line] config)".into(),
        ));
    }

    let r = search(
        app,
        ctx,
        SearchSpec {
            tool: "count_matches",
            services: Services::Given {
                service: p.service.clone(),
                services: p.services.clone(),
            },
            time: p.time.clone(),
            id: p.id.clone(),
            default_window: chrono::Duration::hours(1),
            max_range_hours: l.max_range_hours_count,
            pattern: PatternSpec {
                pattern: p.pattern.clone(),
                fixed_string: p.fixed_string.unwrap_or(true),
                ignore_case: p.ignore_case.unwrap_or(false),
            },
            invert: p.invert.unwrap_or(false),
            hosts: p.hosts.clone(),
            budget: Budget::Refuse(l.max_scan_bytes),
            mode: Mode::Count {
                per_minute: group_by == GroupBy::Minute,
                first_file_per_host: false,
            },
            keep_bytes: l.max_line_bytes,
            timeout_secs: p.timeout_secs,
        },
    )
    .await?;
    let services = r.services;
    let outcome = r.outcome;
    let mut warnings = r.warnings;

    let multi = services.len() > 1;
    let mut groups: BTreeMap<String, u64> = BTreeMap::new();
    let mut minutes: BTreeMap<i64, u64> = BTreeMap::new();
    let mut no_ts = 0u64;
    let mut total = 0u64;
    for c in &outcome.counts {
        total += c.count;
        let prefix = if multi {
            format!("{}/", c.file.service)
        } else {
            String::new()
        };
        match group_by {
            GroupBy::File => {
                *groups
                    .entry(format!("{prefix}{}", c.file.name))
                    .or_default() += c.count
            }
            GroupBy::Host => {
                *groups
                    .entry(format!("{prefix}{}", c.file.host))
                    .or_default() += c.count
            }
            GroupBy::Bucket => {
                let k = match c.file.bucket {
                    Some(b) => fmt_minute(b.from, &s.tz),
                    None => "live".to_string(),
                };
                *groups.entry(k).or_default() += c.count;
            }
            GroupBy::Minute => {
                if let Some(pm) = &c.per_minute {
                    for (m, n) in pm {
                        *minutes.entry(*m).or_default() += n;
                    }
                }
                no_ts += c.no_ts;
            }
        }
    }

    let mut step_minutes = None;
    if group_by == GroupBy::Minute {
        let step = MINUTE_STEPS
            .iter()
            .copied()
            .find(|st| {
                let mut keys: Vec<i64> = minutes.keys().map(|m| m.div_euclid(*st)).collect();
                keys.dedup();
                keys.len() <= MAX_GROUPS
            })
            .unwrap_or(*MINUTE_STEPS.last().unwrap());
        step_minutes = Some(step);
        if step > 1 {
            warnings.push(format!(
                "minute counts coarsened to {step}m groups to stay within {MAX_GROUPS} groups"
            ));
        }
        for (m, n) in &minutes {
            let start = m.div_euclid(step) * step;
            let t: Ts = chrono::DateTime::from_timestamp(start * 60, 0).unwrap_or_default();
            *groups.entry(fmt_minute(t, &s.tz)).or_default() += n;
        }
        if no_ts > 0 {
            *groups.entry("no-timestamp".into()).or_default() += no_ts;
        }
    }

    let mut groups: Vec<CountGroup> = groups
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(key, count)| CountGroup { key, count })
        .collect();
    if groups.len() > MAX_GROUPS {
        // Keep the largest groups (in key order) and fold the rest into one.
        let n = groups.len();
        let mut by_count: Vec<usize> = (0..n).collect();
        by_count.sort_by(|a, b| groups[*b].count.cmp(&groups[*a].count));
        let keep: std::collections::HashSet<usize> =
            by_count[..MAX_GROUPS - 1].iter().copied().collect();
        let mut rest = 0u64;
        let mut kept = Vec::with_capacity(MAX_GROUPS);
        for (i, g) in groups.into_iter().enumerate() {
            if keep.contains(&i) {
                kept.push(g);
            } else {
                rest += g.count;
            }
        }
        kept.push(CountGroup {
            key: format!("(other {} groups)", n - (MAX_GROUPS - 1)),
            count: rest,
        });
        warnings.push(format!(
            "{n} groups; showing the {} largest. Narrow the window/hosts or use group_by=bucket",
            MAX_GROUPS - 1
        ));
        groups = kept;
    }

    let (service, services_out) = svc_fields(&services);
    let res = CountResult {
        box_name: s.box_name().to_string(),
        service,
        services: services_out,
        window: window_out(&r.window, app),
        group_by,
        step_minutes,
        total,
        groups,
        files_scanned: outcome.files_scanned,
        files_skipped_by_time: r.skipped_by_time,
        bytes_scanned: outcome.bytes_scanned,
        truncated: outcome.truncated,
        elapsed_ms: started.elapsed().as_millis(),
        warnings,
    };
    let mut text = String::new();
    header(
        &mut text,
        &res.box_name,
        &res.service,
        &res.services,
        &res.window,
    );
    let _ = writeln!(
        text,
        " | total={}{} files={} (skipped {}) scanned={} | {}ms",
        res.total,
        if res.truncated { " (partial)" } else { "" },
        res.files_scanned,
        res.files_skipped_by_time,
        human_bytes(res.bytes_scanned),
        res.elapsed_ms
    );
    for w in &res.warnings {
        let _ = writeln!(text, "! {w}");
    }
    for g in &res.groups {
        let _ = writeln!(text, "{:>8}  {}", g.count, g.key);
    }
    Ok(ToolOutput {
        stats: AuditStats {
            files: res.files_scanned,
            bytes: res.bytes_scanned,
            matches: res.total,
        },
        json: serde_json::to_value(&res).map_err(|e| ToolError::Internal(e.to_string()))?,
        text,
    })
}

// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct GrepByIdParams {
    /// The identifier to look up (searched as a literal).
    pub id: String,
    /// Service to search. Defaults to the services configured for the matching ID decoder.
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub services: Option<Vec<String>>,
    /// Optional explicit window; overrides the decoded one.
    #[serde(flatten)]
    pub time: TimeParams,
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    #[serde(default)]
    pub before: Option<usize>,
    #[serde(default)]
    pub after: Option<usize>,
    #[serde(default)]
    pub max_lines: Option<usize>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

pub async fn grep_by_id(
    app: &Arc<App>,
    p: GrepByIdParams,
    ctx: &CallCtx,
) -> ToolResult<ToolOutput> {
    let id = p.id.trim().to_string();
    if id.is_empty() {
        return Err(ToolError::InvalidArgument("id must not be empty".into()));
    }
    let s = &app.settings;
    let decoded = crate::parse::id_decode::decode(&s.id_decoders, &id, &s.tz);
    if decoded.is_none() && p.time.spec().is_empty() {
        return Err(ToolError::InvalidArgument(format!(
            "no id_decoder matches '{id}', so no time can be derived. Pass from/to or last, or use locate to find it"
        )));
    }
    let gp = GrepLogsParams {
        service: p.service,
        services: p.services,
        pattern: id.clone(),
        fixed_string: Some(true),
        ignore_case: Some(false),
        invert: None,
        time: p.time,
        hosts: p.hosts,
        before: p.before,
        after: p.after,
        max_lines: p.max_lines,
        order: Some(OrderParam::First),
        id: Some(id),
        timeout_secs: p.timeout_secs,
    };
    grep_logs(app, gp, ctx).await
}

// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct LocateParams {
    /// A concrete literal to find: order ID, trace ID, account ID, ...
    pub pattern: String,
    #[serde(flatten)]
    pub time: TimeParams,
    /// An identifier with an embedded time; scopes the window (defaults to `pattern`).
    #[serde(default)]
    pub id: Option<String>,
    /// Restrict to these services (default: all readable services).
    #[serde(default)]
    pub services: Option<Vec<String>>,
    #[serde(default)]
    pub ignore_case: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Serialize, Debug)]
pub struct LocateHit {
    pub service: String,
    pub host: String,
    pub count: u64,
    pub file: String,
}

#[derive(Serialize, Debug)]
pub struct LocateResult {
    #[serde(rename = "box")]
    pub box_name: String,
    pub window: WindowOut,
    pub services_searched: usize,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub hits: Vec<LocateHit>,
    pub truncated: bool,
    pub elapsed_ms: u128,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub async fn locate(app: &Arc<App>, p: LocateParams, ctx: &CallCtx) -> ToolResult<ToolOutput> {
    let started = Instant::now();
    let s = &app.settings;
    let l = s.limits();
    let pattern = p.pattern.trim().to_string();
    if pattern.len() < 4 {
        return Err(ToolError::InvalidArgument(
            "locate needs a specific literal of at least 4 characters".into(),
        ));
    }
    let id = p.id.clone().unwrap_or_else(|| pattern.clone());
    let r = search(
        app,
        ctx,
        SearchSpec {
            tool: "locate",
            services: Services::GivenOrAll(p.services.clone()),
            time: p.time.clone(),
            id: Some(id),
            default_window: s.locate_window,
            max_range_hours: l.max_range_hours,
            pattern: PatternSpec {
                pattern,
                fixed_string: true,
                ignore_case: p.ignore_case.unwrap_or(false),
            },
            invert: false,
            hosts: None,
            budget: Budget::NewestFirst(s.raw.locate.max_scan_bytes),
            mode: Mode::Count {
                per_minute: false,
                first_file_per_host: true,
            },
            keep_bytes: l.max_line_bytes,
            timeout_secs: p.timeout_secs,
        },
    )
    .await?;
    let (outcome, warnings, budget_hit) = (r.outcome, r.warnings, r.budget_hit);
    let services = r.services;

    let mut by_host: BTreeMap<(String, String), LocateHit> = BTreeMap::new();
    for c in outcome.counts.iter().filter(|c| c.count > 0) {
        let k = (c.file.service.clone(), c.file.host.clone());
        by_host
            .entry(k)
            .and_modify(|h| h.count += c.count)
            .or_insert_with(|| LocateHit {
                service: c.file.service.clone(),
                host: c.file.host.clone(),
                count: c.count,
                file: c.file.name.clone(),
            });
    }
    let hits: Vec<LocateHit> = by_host.into_values().collect();
    let res = LocateResult {
        box_name: s.box_name().to_string(),
        window: window_out(&r.window, app),
        services_searched: services.len(),
        files_scanned: outcome.files_scanned,
        bytes_scanned: outcome.bytes_scanned,
        truncated: outcome.truncated || budget_hit,
        elapsed_ms: started.elapsed().as_millis(),
        hits,
        warnings,
    };
    let mut text = format!(
        "box={} window={} → {} | services={} files={} scanned={} | {}ms\n",
        res.box_name,
        res.window.from,
        res.window.to,
        res.services_searched,
        res.files_scanned,
        human_bytes(res.bytes_scanned),
        res.elapsed_ms
    );
    for w in &res.warnings {
        let _ = writeln!(text, "! {w}");
    }
    if res.hits.is_empty() {
        text.push_str("(not found)\n");
    }
    for h in &res.hits {
        let _ = writeln!(
            text,
            "{} {} count={} first_file={}",
            h.service, h.host, h.count, h.file
        );
    }
    Ok(ToolOutput {
        stats: AuditStats {
            files: res.files_scanned,
            bytes: res.bytes_scanned,
            matches: res.hits.iter().map(|h| h.count).sum(),
        },
        json: serde_json::to_value(&res).map_err(|e| ToolError::Internal(e.to_string()))?,
        text,
    })
}
