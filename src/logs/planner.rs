//! Planner: time window + service/host filters → ordered file list + byte budget check.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::errors::{ToolError, ToolResult};
use crate::logs::catalog::{Catalog, LogFile};
use crate::parse::time::{Ts, Window, fmt_local};

#[derive(Debug)]
pub struct Plan {
    pub files: Vec<Arc<LogFile>>,
    pub total_bytes: u64,
    pub skipped_by_time: usize,
    /// Window after clamping to retention.
    pub window: Window,
    pub warnings: Vec<String>,
}

/// Applies retention to a window: rejects windows entirely past retention, clamps partial ones.
pub fn apply_retention(
    window: &Window,
    catalog: &Catalog,
    now: Ts,
    warnings: &mut Vec<String>,
) -> ToolResult<Window> {
    let s = catalog.settings();
    let oldest = now - s.retention;
    if window.span().to <= oldest {
        return Err(ToolError::WindowRejected(format!(
            "window ends before retention start ({}); logs are kept {} days on this box",
            fmt_local(oldest, &s.tz),
            s.raw.rotation.retention_days
        )));
    }
    if window.span().from < oldest {
        warnings.push(format!(
            "window clamped to retention start {}",
            fmt_local(oldest, &s.tz)
        ));
        return window.clamp_from(oldest).ok_or_else(|| {
            ToolError::WindowRejected("window is empty after retention clamp".into())
        });
    }
    Ok(window.clone())
}

/// Builds a plan over one or more services. `budget` is the max total bytes; `None` disables the
/// check (callers that truncate to a budget themselves, like `locate`).
pub fn plan(
    catalog: &Catalog,
    services: &[String],
    window: &Window,
    hosts: Option<&[String]>,
    now: Ts,
    budget: Option<u64>,
) -> ToolResult<Plan> {
    let mut warnings = Vec::new();
    let window = apply_retention(window, catalog, now, &mut warnings)?;

    let mut files = Vec::new();
    let mut skipped = 0usize;
    let mut seen_hosts = BTreeSet::new();
    for svc in services {
        let sf = catalog.files(svc)?;
        for f in &sf.files {
            seen_hosts.insert(f.host.as_str().to_owned());
            if let Some(hs) = hosts
                && !hs.iter().any(|h| h == &f.host)
            {
                continue;
            }
            if window.overlaps(&f.coverage) {
                files.push(f.clone());
            } else {
                skipped += 1;
            }
        }
    }

    if let Some(hs) = hosts {
        for h in hs {
            if !seen_hosts.contains(h) {
                let sugg = crate::logs::catalog::suggest(h, seen_hosts.iter().map(|s| s.as_str()));
                warnings.push(match sugg {
                    Some(s) => format!("host '{h}' has no files; did you mean '{s}'?"),
                    None => format!("host '{h}' has no files in the selected service(s)"),
                });
            }
        }
    }

    files.sort_by(|a, b| {
        a.group_key()
            .cmp(&b.group_key())
            .then_with(|| a.service.cmp(&b.service))
            .then_with(|| a.host.cmp(&b.host))
    });
    if files.iter().any(|f| f.live) {
        warnings.push("live file(s) included: the current bucket is not rotated yet".into());
    }
    let total_bytes = files.iter().map(|f| f.size).sum();

    if let Some(limit) = budget
        && total_bytes > limit
    {
        return Err(ToolError::PlanTooLarge {
            files: files.len(),
            bytes: total_bytes,
            limit,
        });
    }

    Ok(Plan {
        files,
        total_bytes,
        skipped_by_time: skipped,
        window,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crate::config::tests::sample_toml;
    use crate::parse::time::{Interval, parse_instant};
    use chrono::Duration;

    fn setup(names: &[&str]) -> (tempfile::TempDir, Catalog) {
        let dir = tempfile::tempdir().unwrap();
        let svc = dir.path().join("orders");
        std::fs::create_dir(&svc).unwrap();
        // Old mtimes so the late-rotation extension (mtime-based) does not kick in.
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000);
        for n in names {
            std::fs::write(svc.join(n), b"0123456789").unwrap();
            std::fs::File::options()
                .write(true)
                .open(svc.join(n))
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        let t = sample_toml(dir.path().to_str().unwrap());
        let s = Arc::new(Settings::from_toml(&t).unwrap());
        let cat = Catalog::new(s).unwrap();
        (dir, cat)
    }

    fn w(from: &str, to: &str) -> Window {
        let tz = chrono_tz::UTC;
        Window::single(Interval::new(
            parse_instant(from, &tz).unwrap(),
            parse_instant(to, &tz).unwrap(),
        ))
    }

    fn names(p: &Plan) -> Vec<&str> {
        p.files.iter().map(|f| f.name.as_str()).collect()
    }

    #[test]
    fn selects_by_bucket_and_live() {
        let (_d, cat) = setup(&[
            "a.log.2026-06-02-10-00.gz", // covers 09-10
            "a.log.2026-06-02-11-00.gz", // covers 10-11
            "a.log.2026-06-02-12-00",    // covers 11-12 (delaycompress)
            "a.log",                     // 12-
            "b.log.2026-06-02-11-00.gz",
        ]);
        let now = parse_instant("2026-06-02T12:30:00Z", &chrono_tz::UTC).unwrap();
        let svcs = vec!["orders".to_string()];

        let p = plan(
            &cat,
            &svcs,
            &w("2026-06-02 10:15", "2026-06-02 10:45"),
            None,
            now,
            None,
        )
        .unwrap();
        assert_eq!(
            names(&p),
            ["a.log.2026-06-02-11-00.gz", "b.log.2026-06-02-11-00.gz"]
        );
        assert_eq!(p.skipped_by_time, 3);

        // Midnight-free edge: window starting exactly at a bucket end excludes that bucket.
        let p = plan(
            &cat,
            &svcs,
            &w("2026-06-02 11:00", "2026-06-02 11:30"),
            None,
            now,
            None,
        )
        .unwrap();
        assert_eq!(names(&p), ["a.log.2026-06-02-12-00"]);

        let p = plan(
            &cat,
            &svcs,
            &w("2026-06-02 11:30", "2026-06-02 12:30"),
            None,
            now,
            None,
        )
        .unwrap();
        assert_eq!(names(&p), ["a.log.2026-06-02-12-00", "a.log"]);
        assert!(p.warnings.iter().any(|w| w.contains("live")));

        let hosts = vec!["b".to_string(), "zz".to_string()];
        let p = plan(
            &cat,
            &svcs,
            &w("2026-06-02 09:00", "2026-06-02 13:00"),
            Some(&hosts),
            now,
            None,
        )
        .unwrap();
        assert_eq!(names(&p), ["b.log.2026-06-02-11-00.gz"]);
        assert!(p.warnings.iter().any(|w| w.contains("'zz'")));
    }

    #[test]
    fn budget_and_retention() {
        let (_d, cat) = setup(&["a.log.2026-06-02-11-00.gz", "a.log"]);
        let now = parse_instant("2026-06-02T12:30:00Z", &chrono_tz::UTC).unwrap();
        let svcs = vec!["orders".to_string()];
        let err = plan(
            &cat,
            &svcs,
            &w("2026-06-02 09:00", "2026-06-02 13:00"),
            None,
            now,
            Some(5),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ToolError::PlanTooLarge {
                files: 2,
                bytes: 20,
                ..
            }
        ));

        let later = now + Duration::days(30);
        let err = plan(
            &cat,
            &svcs,
            &w("2026-06-02 09:00", "2026-06-02 13:00"),
            None,
            later,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, ToolError::WindowRejected(_)));

        let p = plan(
            &cat,
            &svcs,
            &w("2026-05-01 00:00", "2026-06-02 13:00"),
            None,
            now,
            None,
        )
        .unwrap();
        assert!(p.warnings.iter().any(|w| w.contains("clamped")));
    }
}
