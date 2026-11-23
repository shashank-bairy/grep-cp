//! server_info, list_services, list_files.

use std::fmt::Write as _;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{AuditStats, TimeParams, ToolOutput, now};
use crate::app::App;
use crate::engine::output::human_bytes;
use crate::errors::{ToolError, ToolResult};
use crate::logs::catalog::Compression;
use crate::parse::time::{Ts, fmt_local};

const LIST_FILES_CAP: usize = 500;

fn to_json<T: Serialize>(v: &T) -> ToolResult<serde_json::Value> {
    serde_json::to_value(v).map_err(|e| ToolError::Internal(e.to_string()))
}

pub fn server_info(app: &Arc<App>) -> ToolResult<ToolOutput> {
    let s = &app.settings;
    let l = s.limits();
    let json = serde_json::json!({
        "box": s.box_name(),
        "version": env!("CARGO_PKG_VERSION"),
        "timezone": s.raw.timezone,
        "now": fmt_local(now(), &s.tz),
        "root": s.root.display().to_string(),
        "retention_days": s.raw.rotation.retention_days,
        "bucket": s.raw.rotation.bucket,
        "line_parsing": s.line.is_some(),
        "line_fields": s.line.as_ref().is_some_and(|p| p.has_fields()),
        "id_decoders": s.id_decoders.iter().map(|d| serde_json::json!({
            "name": d.name, "regex": d.re.as_str(), "services": d.services,
        })).collect::<Vec<_>>(),
        "limits": {
            "max_range_hours": l.max_range_hours,
            "max_range_hours_count": l.max_range_hours_count,
            "max_lines_default": l.max_lines_default,
            "max_lines_hard": l.max_lines_hard,
            "max_bytes": l.max_bytes,
            "max_line_bytes": l.max_line_bytes,
            "max_context": l.max_context,
            "max_scan_bytes": l.max_scan_bytes,
            "timeout_secs_default": l.timeout_secs_default,
            "timeout_secs_max": l.timeout_secs_max,
        },
    });
    let text = format!(
        "box={} tz={} now={} retention={}d bucket={} line_parsing={} id_decoders=[{}]\nlimits: grep ≤{}h, count ≤{}h, lines ≤{} (default {}), context ≤{}, scan ≤{}, timeout ≤{}s",
        s.box_name(),
        s.raw.timezone,
        json["now"].as_str().unwrap_or(""),
        s.raw.rotation.retention_days,
        s.raw.rotation.bucket,
        s.line.is_some(),
        s.id_decoders
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>()
            .join(","),
        l.max_range_hours,
        l.max_range_hours_count,
        l.max_lines_hard,
        l.max_lines_default,
        l.max_context,
        human_bytes(l.max_scan_bytes),
        l.timeout_secs_max,
    );
    Ok(ToolOutput {
        json,
        text,
        stats: AuditStats::default(),
    })
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ListServicesParams {
    /// Case-insensitive substring filter on the service name or description.
    #[serde(default)]
    pub filter: Option<String>,
}

pub fn list_services(app: &Arc<App>, p: ListServicesParams) -> ToolResult<ToolOutput> {
    let all = app.catalog.list_services()?;
    let f = p.filter.as_deref().map(|f| f.to_lowercase());
    let list: Vec<_> = all
        .iter()
        .filter(|e| match &f {
            None => true,
            Some(f) => {
                e.name.to_lowercase().contains(f)
                    || e.description
                        .as_deref()
                        .is_some_and(|d| d.to_lowercase().contains(f))
            }
        })
        .cloned()
        .collect();
    let mut text = format!(
        "box={} services={} (of {})\n",
        app.settings.box_name(),
        list.len(),
        all.len()
    );
    for e in &list {
        let _ = write!(text, "{}", e.name);
        if !e.readable {
            text.push_str(" (unreadable)");
        }
        if let Some(d) = &e.description {
            let _ = write!(text, " — {d}");
        }
        text.push('\n');
    }
    let json = serde_json::json!({
        "box": app.settings.box_name(),
        "services": to_json(&list)?,
    });
    Ok(ToolOutput {
        json,
        text,
        stats: AuditStats::default(),
    })
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ListFilesParams {
    pub service: String,
    /// Optional window: only files that may contain lines in it.
    #[serde(flatten)]
    pub time: TimeParams,
    /// Only files of this host.
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Serialize, Debug)]
struct FileOut {
    file: String,
    host: String,
    live: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_to: Option<String>,
    compression: Compression,
    size: u64,
    mtime: String,
}

pub fn list_files(app: &Arc<App>, p: ListFilesParams) -> ToolResult<ToolOutput> {
    let s = &app.settings;
    let sf = app.catalog.files(&p.service)?;
    let window = crate::parse::time::resolve(&p.time.spec(), &s.tz, now())
        .map_err(ToolError::InvalidArgument)?;
    let fmt = |t: Ts| fmt_local(t, &s.tz);
    let mut selected: Vec<FileOut> = sf
        .files
        .iter()
        .filter(|f| p.host.as_ref().is_none_or(|h| &f.host == h))
        .filter(|f| window.as_ref().is_none_or(|w| w.overlaps(&f.coverage)))
        .map(|f| FileOut {
            file: f.name.clone(),
            host: f.host.clone(),
            live: f.live,
            bucket_from: f.bucket.map(|b| fmt(b.from)),
            bucket_to: f.bucket.map(|b| fmt(b.to)),
            compression: f.compression,
            size: f.size,
            mtime: fmt(f.mtime),
        })
        .collect();
    let total = selected.len();
    let total_bytes: u64 = selected.iter().map(|f| f.size).sum();
    let truncated = total > LIST_FILES_CAP;
    if truncated {
        // Keep the newest files (live files sort last).
        selected.drain(..total - LIST_FILES_CAP);
    }
    let mut hosts: Vec<&str> = sf.files.iter().map(|f| f.host.as_str()).collect();
    hosts.sort();
    hosts.dedup();

    let mut text = format!(
        "box={} service={} files={}{} total_size={} hosts={}\n",
        s.box_name(),
        sf.service,
        total,
        if truncated {
            format!(" (showing newest {LIST_FILES_CAP}; pass a time window or host)")
        } else {
            String::new()
        },
        human_bytes(total_bytes),
        hosts.len()
    );
    for f in &selected {
        let _ = writeln!(
            text,
            "{} host={} {} {}",
            f.file,
            f.host,
            match (&f.bucket_from, f.live) {
                (_, true) => "live".to_string(),
                (Some(b), _) => format!("bucket={b}"),
                _ => String::new(),
            },
            human_bytes(f.size)
        );
    }
    let json = serde_json::json!({
        "box": s.box_name(),
        "service": sf.service,
        "hosts": hosts,
        "total_files": total,
        "total_bytes": total_bytes,
        "truncated": truncated,
        "files": to_json(&selected)?,
    });
    Ok(ToolOutput {
        json,
        text,
        stats: AuditStats {
            files: total,
            ..Default::default()
        },
    })
}
