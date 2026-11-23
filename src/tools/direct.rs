//! tail_live and read_context: direct reads without a full search.

use std::fmt::Write as _;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{AuditStats, CallCtx, ToolOutput, now, run_blocking, stop_warning, timeout};
use crate::app::App;
use crate::engine::extract::{self, Line};
use crate::engine::output::clean;
use crate::engine::{PatternSpec, build_matcher};
use crate::errors::{ToolError, ToolResult};
use crate::parse::time::fmt_local;

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct TailLiveParams {
    pub service: String,
    /// Only these hosts.
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    /// Lines per host (default 50).
    #[serde(default)]
    pub lines: Option<usize>,
    /// Only lines containing this text.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Treat `pattern` as a literal (default true).
    #[serde(default)]
    pub fixed_string: Option<bool>,
    #[serde(default)]
    pub ignore_case: Option<bool>,
}

#[derive(Serialize, Debug)]
struct OutLine {
    byte_offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ts: Option<String>,
    text: String,
}

#[derive(Serialize, Debug)]
struct TailFile {
    host: String,
    file: String,
    lines: Vec<OutLine>,
    /// Scan limit reached before enough matching lines were found.
    partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn out_line(app: &App, l: &Line) -> OutLine {
    let s = &app.settings;
    OutLine {
        byte_offset: l.byte_offset,
        ts: s
            .line
            .as_ref()
            .and_then(|p| p.parse_ts(&l.text, now()))
            .map(|t| fmt_local(t, &s.tz)),
        text: clean(&l.text, s),
    }
}

pub async fn tail_live(app: &Arc<App>, p: TailLiveParams, ctx: &CallCtx) -> ToolResult<ToolOutput> {
    let s = app.settings.clone();
    let l = s.limits();
    let n = p.lines.unwrap_or(50).clamp(1, l.tail_max_lines);
    let keep = l.max_line_bytes * 2;
    let max_scan_total = l.tail_max_scan_bytes;
    let max_out = l.max_bytes;
    let app2 = app.clone();
    let p2 = p.clone();
    // Catalog listing, matcher compile and the reads all run on the blocking thread.
    let (service, files, results, stopped, bytes) = run_blocking(
        app,
        ctx,
        timeout(app, None),
        move |guard| -> ToolResult<_> {
            let sf = app2.catalog.files(&p2.service)?;
            let files: Vec<_> = sf
                .files
                .iter()
                .filter(|f| f.live)
                .filter(|f| p2.hosts.as_ref().is_none_or(|hs| hs.contains(&f.host)))
                .cloned()
                .collect();
            if files.is_empty() {
                return Err(ToolError::InvalidArgument(format!(
                    "no live files in '{}' for the given hosts; see list_files",
                    sf.service
                )));
            }
            let matcher = match p2.pattern.as_deref().filter(|x| !x.is_empty()) {
                Some(pat) => Some(build_matcher(
                    &PatternSpec {
                        pattern: pat.to_string(),
                        fixed_string: p2.fixed_string.unwrap_or(true),
                        ignore_case: p2.ignore_case.unwrap_or(false),
                    },
                    app2.settings.limits().regex_size_limit,
                )?),
                None => None,
            };
            // One scan budget and one output budget shared by all hosts.
            let mut results = Vec::with_capacity(files.len());
            let mut out_bytes = 0usize;
            for f in &files {
                let scanned = guard.bytes_scanned();
                let budget = max_scan_total.saturating_sub(scanned);
                if budget == 0 || out_bytes >= max_out {
                    results.push(Ok((Vec::new(), true)));
                    continue;
                }
                let r = extract::tail(f, n, matcher.as_ref(), budget, keep, &guard).map(
                    |(mut lines, partial)| {
                        // Keep the newest lines that fit the remaining output budget.
                        let mut used = 0usize;
                        let mut cut = lines.len();
                        for (i, line) in lines.iter().enumerate().rev() {
                            if out_bytes + used + line.text.len() > max_out && used > 0 {
                                break;
                            }
                            used += line.text.len();
                            cut = i;
                        }
                        let dropped = cut > 0;
                        lines.drain(..cut);
                        out_bytes += used;
                        (lines, partial || dropped)
                    },
                );
                results.push(r);
            }
            Ok((
                sf.service.clone(),
                files,
                results,
                guard.stop.get(),
                guard.bytes_scanned(),
            ))
        },
    )
    .await??;

    let mut out = Vec::new();
    let mut total = 0usize;
    for (f, r) in files.iter().zip(results) {
        let (lines, partial, error) = match r {
            Ok((lines, partial)) => (lines, partial, None),
            Err(e) if crate::engine::reader::is_stop_error(&e) => (vec![], true, None),
            Err(e) => (vec![], false, Some(e.to_string())),
        };
        total += lines.len();
        out.push(TailFile {
            host: f.host.clone(),
            file: f.name.clone(),
            lines: lines.iter().map(|l| out_line(app, l)).collect(),
            partial,
            error,
        });
    }
    let warnings: Vec<String> = stop_warning(stopped).into_iter().collect();

    let mut text = format!(
        "box={} service={} live files={} lines={}\n",
        s.box_name(),
        service,
        out.len(),
        total
    );
    for w in &warnings {
        let _ = writeln!(text, "! {w}");
    }
    for f in &out {
        let _ = writeln!(
            text,
            "--- {} {}{}{}",
            f.host,
            f.file,
            if f.partial {
                " (partial: scan or output budget)"
            } else {
                ""
            },
            f.error
                .as_deref()
                .map(|e| format!(" error: {e}"))
                .unwrap_or_default()
        );
        for l in &f.lines {
            let _ = writeln!(text, "@{} {}", l.byte_offset, l.text);
        }
    }
    let json = serde_json::json!({
        "box": s.box_name(),
        "service": service,
        "files": serde_json::to_value(&out).map_err(|e| ToolError::Internal(e.to_string()))?,
        "warnings": warnings,
    });
    Ok(ToolOutput {
        json,
        text,
        stats: AuditStats {
            files: out.len(),
            bytes,
            matches: total as u64,
        },
    })
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ReadContextParams {
    pub service: String,
    /// A filename returned by list_files / grep_logs (never a path).
    pub file: String,
    /// `byte_offset` of a line from a grep_logs result.
    pub byte_offset: u64,
    /// Lines before (default 10).
    #[serde(default)]
    pub before: Option<usize>,
    /// Lines after (default 10).
    #[serde(default)]
    pub after: Option<usize>,
}

pub async fn read_context(
    app: &Arc<App>,
    p: ReadContextParams,
    ctx: &CallCtx,
) -> ToolResult<ToolOutput> {
    let s = app.settings.clone();
    let l = s.limits();
    let cap = (l.max_context * 5).max(1);
    let before = p.before.unwrap_or(10).min(cap);
    let after = p.after.unwrap_or(10).min(cap);
    let keep = l.max_line_bytes * 2;
    let offset = p.byte_offset;
    let app2 = app.clone();
    let (service, name) = (p.service.clone(), p.file.clone());
    let (file, r, stopped) = run_blocking(
        app,
        ctx,
        timeout(app, None),
        move |guard| -> ToolResult<_> {
            let file = app2.catalog.resolve_file(&service, &name)?;
            let r = extract::read_context(&file, offset, before, after, keep, &guard);
            Ok((file, r, guard.stop.get()))
        },
    )
    .await??;
    let c = match r {
        Ok(c) => c,
        Err(e) if crate::engine::reader::is_stop_error(&e) => {
            return Err(ToolError::Stopped(
                stop_warning(stopped).unwrap_or_else(|| "stopped".into()),
            ));
        }
        Err(e) => return Err(ToolError::Internal(format!("reading {}: {e}", file.name))),
    };
    let Some(line) = c.line.as_ref() else {
        return Err(ToolError::InvalidArgument(format!(
            "byte_offset {offset} is past the end of {} (it may have been rotated or truncated)",
            file.name
        )));
    };
    let before_l: Vec<OutLine> = c.before.iter().map(|l| out_line(app, l)).collect();
    let line_o = out_line(app, line);
    let after_l: Vec<OutLine> = c.after.iter().map(|l| out_line(app, l)).collect();

    let mut text = format!(
        "--- {} {} {}@{}\n",
        s.box_name(),
        file.host,
        file.name,
        line.byte_offset
    );
    for l in &before_l {
        let _ = writeln!(text, "  {}", l.text);
    }
    let _ = writeln!(text, "> {}", line_o.text);
    for l in &after_l {
        let _ = writeln!(text, "  {}", l.text);
    }
    let json = serde_json::json!({
        "box": s.box_name(),
        "service": file.service,
        "host": file.host,
        "file": file.name,
        "line": serde_json::to_value(&line_o).unwrap_or_default(),
        "before": serde_json::to_value(&before_l).unwrap_or_default(),
        "after": serde_json::to_value(&after_l).unwrap_or_default(),
    });
    Ok(ToolOutput {
        json,
        text,
        stats: AuditStats {
            files: 1,
            bytes: 0,
            matches: 1,
        },
    })
}
