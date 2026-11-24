//! Engine checks against the fixture tree: identical match counts to `rg -z -c`, and no crash when
//! a live file is truncated mid-search (copytruncate).

#[path = "fixtures/gen.rs"]
mod fixtures;

use std::sync::Arc;
use std::time::{Duration, Instant};

use grep_cp::config::Settings;
use grep_cp::engine::{self, Guard, Job, Mode, Order, PatternSpec, build_matcher};
use grep_cp::logs::catalog::Catalog;
use grep_cp::parse::time::{Interval, Window};

fn pool() -> &'static engine::WorkerPool {
    static POOL: std::sync::OnceLock<engine::WorkerPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| engine::WorkerPool::new(2))
}

fn run(j: Job) -> engine::Outcome {
    engine::run(j, pool())
}

fn settings(fx: &fixtures::Fixture) -> Arc<Settings> {
    Arc::new(Settings::load(&fx.config).unwrap())
}

fn all_time() -> Window {
    let now = chrono::Utc::now();
    Window::single(Interval::new(
        now - chrono::Duration::days(2),
        now + chrono::Duration::hours(1),
    ))
}

fn job(
    s: &Settings,
    files: Vec<Arc<grep_cp::logs::catalog::LogFile>>,
    spec: &PatternSpec,
    mode: Mode,
    parser: bool,
) -> Job {
    Job {
        files,
        matcher: build_matcher(spec, s.limits().regex_size_limit).unwrap(),
        invert: false,
        window: all_time(),
        mode,
        parser: if parser { s.line.clone() } else { None },
        workers: 3,
        guard: Guard::new(Instant::now() + Duration::from_secs(60)),
        keep_bytes: 8192,
        copytruncate: true,
        now: chrono::Utc::now(),
    }
}

fn rg_count(path: &std::path::Path, spec: &PatternSpec) -> Option<u64> {
    let mut cmd = std::process::Command::new("rg");
    cmd.arg("-z").arg("-c").arg("--no-messages").arg("-a");
    if spec.fixed_string {
        cmd.arg("-F");
    }
    if spec.ignore_case {
        cmd.arg("-i");
    }
    cmd.arg("-e").arg(&spec.pattern).arg(path);
    let out = cmd.output().ok()?;
    if out.status.code() == Some(1) {
        return Some(0);
    }
    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
}

#[test]
fn counts_match_ripgrep() {
    if std::process::Command::new("rg")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("rg not installed; skipping");
        return;
    }
    let fx = fixtures::build();
    let s = settings(&fx);
    let cat = Catalog::new(s.clone()).unwrap();
    let files = cat.files("orders").unwrap().files.clone();
    let specs = [
        PatternSpec {
            pattern: "ERROR".into(),
            fixed_string: true,
            ignore_case: false,
        },
        PatternSpec {
            pattern: "error".into(),
            fixed_string: true,
            ignore_case: true,
        },
        PatternSpec {
            pattern: r"latency_ms=4\d\d\b".into(),
            fixed_string: false,
            ignore_case: false,
        },
        PatternSpec {
            pattern: "Pay.java:42)".into(),
            fixed_string: true,
            ignore_case: false,
        },
    ];
    for spec in &specs {
        let out = run(job(
            &s,
            files.clone(),
            spec,
            Mode::Count {
                per_minute: false,
                first_file_per_host: false,
            },
            false,
        ));
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
        assert_eq!(out.counts.len(), files.len());
        for c in &out.counts {
            let expected = rg_count(&c.file.path, spec).unwrap();
            assert_eq!(
                c.count, expected,
                "{} pattern {:?}",
                c.file.name, spec.pattern
            );
        }
    }

    // Lines mode returns the same set as counts when uncapped.
    let spec = &specs[0];
    let total: u64 = run(job(
        &s,
        files.clone(),
        spec,
        Mode::Count {
            per_minute: false,
            first_file_per_host: false,
        },
        false,
    ))
    .counts
    .iter()
    .map(|c| c.count)
    .sum();
    let out = run(job(
        &s,
        files.clone(),
        spec,
        Mode::Lines {
            order: Order::First,
            max_lines: 100_000,
            max_bytes: 1 << 30,
            before: 0,
            after: 0,
        },
        false,
    ));
    assert_eq!(out.hits.len() as u64, total);
    assert!(!out.truncated);
}

#[test]
fn caps_are_exact_and_flag_truncation() {
    let fx = fixtures::build();
    let s = settings(&fx);
    let cat = Catalog::new(s.clone()).unwrap();
    let files = cat.files("orders").unwrap().files.clone();
    let spec = PatternSpec {
        pattern: "status=200".into(),
        fixed_string: true,
        ignore_case: false,
    };
    for order in [Order::First, Order::Last] {
        let out = run(job(
            &s,
            files.clone(),
            &spec,
            Mode::Lines {
                order,
                max_lines: 7,
                max_bytes: 1 << 20,
                before: 1,
                after: 1,
            },
            true,
        ));
        assert_eq!(out.hits.len(), 7);
        assert!(out.truncated);
    }
    // Byte cap.
    let out = run(job(
        &s,
        files.clone(),
        &spec,
        Mode::Lines {
            order: Order::First,
            max_lines: 10_000,
            max_bytes: 2000,
            before: 0,
            after: 0,
        },
        true,
    ));
    let bytes: usize = out.hits.iter().map(|h| h.hit.text.len()).sum();
    assert!(bytes <= 2000 && !out.hits.is_empty());
    assert!(out.truncated);
}

#[test]
fn deadline_stops_search() {
    let fx = fixtures::build();
    let s = settings(&fx);
    let cat = Catalog::new(s.clone()).unwrap();
    let files = cat.files("orders").unwrap().files.clone();
    let spec = PatternSpec {
        pattern: "status".into(),
        fixed_string: true,
        ignore_case: false,
    };
    let mut j = job(
        &s,
        files,
        &spec,
        Mode::Count {
            per_minute: false,
            first_file_per_host: false,
        },
        false,
    );
    j.guard = Guard::new(Instant::now()); // already expired
    let out = run(j);
    assert_eq!(out.stopped, Some(engine::StopReason::Timeout));
    assert!(out.truncated);
}

#[test]
fn live_file_truncated_during_search() {
    let fx = fixtures::build();
    let s = settings(&fx);
    // Make the live file big enough that the search is still running when it is truncated.
    let live = fx.root.join("orders").join("web-1.log");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&live)
            .unwrap();
        let chunk = format!(
            "{} web-1 orders[42]: INFO filler line status=200\n",
            chrono::Utc::now().to_rfc3339()
        )
        .repeat(10_000);
        for _ in 0..60 {
            f.write_all(chunk.as_bytes()).unwrap();
        }
    }
    let cat = Catalog::new(s.clone()).unwrap();
    let files: Vec<_> = cat
        .files("orders")
        .unwrap()
        .files
        .iter()
        .filter(|f| f.name == "web-1.log")
        .cloned()
        .collect();
    assert_eq!(files.len(), 1);
    let live2 = live.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(5));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&live2)
            .unwrap()
            .set_len(0)
            .unwrap();
    });
    let spec = PatternSpec {
        pattern: "status=200".into(),
        fixed_string: true,
        ignore_case: false,
    };
    let out = run(job(
        &s,
        files,
        &spec,
        Mode::Count {
            per_minute: false,
            first_file_per_host: false,
        },
        false,
    ));
    t.join().unwrap();
    // Must not crash; either finished before the truncate or reported it.
    assert!(out.files_scanned == 1);
    for w in &out.warnings {
        assert!(w.contains("truncated"), "{w}");
    }
}

#[test]
fn continuation_lines_respect_the_window() {
    // With include_adjacent_bucket = true the neighbouring hours are opened too; lines without a
    // timestamp (the exception line after each ERROR) must not leak in from them.
    let fx = fixtures::build();
    let text = std::fs::read_to_string(&fx.config).unwrap().replace(
        "include_adjacent_bucket = false",
        "include_adjacent_bucket = true",
    );
    let s = Arc::new(Settings::from_toml(&text).unwrap());
    let cat = Catalog::new(s.clone()).unwrap();
    let hour = fx.h0 - chrono::Duration::hours(2);
    let window = Window::single(Interval::new(
        hour + chrono::Duration::minutes(15),
        hour + chrono::Duration::minutes(45),
    ));
    let plan =
        grep_cp::logs::planner::plan(&cat, &["orders".to_string()], &window, None, fx.now, None)
            .unwrap();
    assert!(
        plan.files.len() >= 6,
        "adjacent buckets should be planned: {}",
        plan.files.len()
    );
    let spec = PatternSpec {
        pattern: "IllegalStateException".into(),
        fixed_string: true,
        ignore_case: false,
    };

    let mut j = job(
        &s,
        plan.files.clone(),
        &spec,
        Mode::Lines {
            order: Order::First,
            max_lines: 200,
            max_bytes: 1 << 20,
            before: 0,
            after: 0,
        },
        true,
    );
    j.window = window.clone();
    let out = run(j);
    // Errors every 10 minutes at :05, :15, ... → :15, :25, :35 for each of 2 hosts.
    assert_eq!(
        out.hits.len(),
        6,
        "{:?}",
        out.hits.iter().map(|h| h.hit.sort_ts).collect::<Vec<_>>()
    );
    for h in &out.hits {
        assert!(h.hit.ts.is_none(), "continuation line has no own timestamp");
        assert!(window.contains(h.hit.sort_ts.expect("inherited timestamp")));
    }

    let mut j = job(
        &s,
        plan.files,
        &spec,
        Mode::Count {
            per_minute: true,
            first_file_per_host: false,
        },
        true,
    );
    j.window = window;
    let total: u64 = run(j).counts.iter().map(|c| c.count).sum();
    assert_eq!(total, 6);
}

#[test]
fn offsets_ignore_byte_order_marks() {
    let fx = fixtures::build_with(false);
    let svc = fx.root.join("orders");
    std::fs::write(svc.join("bom-1.log"), b"\xEF\xBB\xBFfirst\nneedle here\n").unwrap();
    let s = settings(&fx);
    let cat = Catalog::new(s.clone()).unwrap();
    let files: Vec<_> = cat
        .files("orders")
        .unwrap()
        .files
        .iter()
        .filter(|f| f.name == "bom-1.log")
        .cloned()
        .collect();
    let spec = PatternSpec {
        pattern: "needle".into(),
        fixed_string: true,
        ignore_case: false,
    };
    let out = run(job(
        &s,
        files,
        &spec,
        Mode::Lines {
            order: Order::First,
            max_lines: 10,
            max_bytes: 1 << 20,
            before: 0,
            after: 0,
        },
        false,
    ));
    assert_eq!(out.hits.len(), 1);
    assert_eq!(out.hits[0].hit.byte_offset, 3 + "first\n".len() as u64);
}
