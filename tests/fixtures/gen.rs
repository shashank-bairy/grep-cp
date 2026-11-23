//! Builds a fake log root for integration tests:
//! - `orders/` with hosts web-1, web-2: hourly rotated `.gz` files (one multi-member, pigz-style),
//!   the newest rotation uncompressed (delaycompress), live files (web-2's starts with a NUL hole
//!   like a copytruncate'd file), a non-matching name and a symlink pointing outside the root.
//! - `payments/` with host pay-1, sharing some order IDs with orders.
//! - `billing/` unreadable (mode 000), when not running as root.

#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, DurationRound, Utc};
use flate2::Compression;
use flate2::write::GzEncoder;

pub const HOURS: i64 = 6;
pub const STEP_SECS: i64 = 10;

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub config: PathBuf,
    pub now: DateTime<Utc>,
    /// Start of the current hour.
    pub h0: DateTime<Utc>,
    /// An order ID that appears in orders/web-1 and payments/pay-1, two hours ago.
    pub id: String,
    pub billing_unreadable: bool,
}

pub fn order_id(ts: DateTime<Utc>, seq: u32) -> String {
    format!("TXN-{}-{seq:04}", ts.format("%Y%m%d-%H%M"))
}

fn line(ts: DateTime<Utc>, host: &str, svc: &str, n: i64) -> String {
    let mut s = String::new();
    if n % 60 == 30 {
        let id = order_id(
            ts,
            if host == "web-1" || host == "pay-1" {
                1
            } else {
                2
            },
        );
        s.push_str(&format!(
            "{} {host} {svc}[42]: ERROR payment failed for {id} Authorization: Bearer tok{n}x\n",
            ts.to_rfc3339()
        ));
        s.push_str("java.lang.IllegalStateException: declined\n");
        s.push_str("\tat com.example.Pay.charge(Pay.java:42)\n");
    } else {
        s.push_str(&format!(
            "{} {host} {svc}[42]: INFO GET /api/{svc}/{n} status=200 latency_ms={}\n",
            ts.to_rfc3339(),
            n % 500
        ));
    }
    s
}

/// Lines for [from, to) every STEP_SECS.
fn lines(from: DateTime<Utc>, to: DateTime<Utc>, host: &str, svc: &str) -> String {
    let mut out = String::new();
    let mut t = from;
    let mut n = (from.timestamp() / STEP_SECS) % 3600;
    while t < to {
        out.push_str(&line(t, host, svc, n));
        t += Duration::seconds(STEP_SECS);
        n += 1;
    }
    out
}

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn suffix(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d-%H-%M").to_string()
}

fn write_host(
    dir: &Path,
    host: &str,
    svc: &str,
    h0: DateTime<Utc>,
    now: DateTime<Utc>,
    nul_hole: bool,
) {
    for k in 1..=HOURS {
        // Suffix = rotation time; the file covers the hour before it.
        let t = h0 - Duration::hours(k - 1);
        let data = lines(t - Duration::hours(1), t, host, svc);
        let name = format!("{host}.log.{}", suffix(t));
        if k == 1 {
            fs::write(dir.join(&name), &data).unwrap();
        } else if k == 3 {
            // Multi-member gzip, like pigz output.
            let mid = data.len() / 2;
            let cut = data[..mid].rfind('\n').unwrap() + 1;
            let mut out = gz(&data.as_bytes()[..cut]);
            out.extend(gz(&data.as_bytes()[cut..]));
            fs::write(dir.join(format!("{name}.gz")), out).unwrap();
        } else {
            fs::write(dir.join(format!("{name}.gz")), gz(data.as_bytes())).unwrap();
        }
        let mtime = std::time::SystemTime::from(t);
        let p = if k == 1 {
            dir.join(&name)
        } else {
            dir.join(format!("{name}.gz"))
        };
        fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
    }
    let mut live = Vec::new();
    if nul_hole {
        live.extend(std::iter::repeat_n(0u8, 4096));
    }
    live.extend(lines(h0, now, host, svc).into_bytes());
    fs::write(dir.join(format!("{host}.log")), live).unwrap();
}

pub fn build() -> Fixture {
    build_with(true)
}

pub fn build_with(line_section: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let now = Utc::now();
    // Ensure the live files have lines in the current hour.
    let h0 = (now - Duration::minutes(5))
        .duration_trunc(Duration::hours(1))
        .unwrap();

    let orders = root.join("orders");
    fs::create_dir_all(&orders).unwrap();
    write_host(&orders, "web-1", "orders", h0, now, false);
    write_host(&orders, "web-2", "orders", h0, now, true);
    fs::write(orders.join("junk.txt"), "not a log\n").unwrap();
    let outside = dir.path().join("outside.log");
    fs::write(&outside, "SECRET outside root\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, orders.join("evil.log")).unwrap();

    let payments = root.join("payments");
    fs::create_dir_all(&payments).unwrap();
    write_host(&payments, "pay-1", "payments", h0, now, false);

    let billing = root.join("billing");
    fs::create_dir_all(&billing).unwrap();
    fs::write(billing.join("b-1.log"), "x\n").unwrap();
    #[allow(unused_assignments)]
    let mut billing_unreadable = false;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&billing, fs::Permissions::from_mode(0o000)).unwrap();
        billing_unreadable = fs::read_dir(&billing).is_err();
    }

    // An ERROR line two hours ago at minute :05 (n % 60 == 30 → every 10 minutes at :05, :15, ...).
    let err_ts = find_error_ts(h0 - Duration::hours(2));
    let id = order_id(err_ts, 1);

    let line_cfg = if line_section {
        "[line]\ntimestamp_regex = '^(?P<ts>\\S+)'\ntimestamp_format = \"rfc3339\"\nfields_regex = '^\\S+ (?P<host>\\S+) (?P<program>[^\\[]+)\\[\\d+\\]: (?P<level>[A-Z]+) (?P<msg>.*)$'\n"
    } else {
        ""
    };
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        format!(
            r#"box_name = "test1"
timezone = "UTC"

[server]
transport = "stdio"

[layout]
root = "{root}"
file_regex = '^(?P<host>.+?)\.log(?:\.(?P<Y>\d{{4}})-(?P<m>\d{{2}})-(?P<d>\d{{2}})-(?P<H>\d{{2}})-(?P<M>\d{{2}})(?P<ext>\.gz|\.zst)?)?$'

[rotation]
bucket = "1h"
suffix_marks = "end"
include_adjacent_bucket = false
retention_days = 7

{line_cfg}
[limits]
max_lines_default = 200
max_range_hours = 24

[[id_decoders]]
name = "order"
regex = '^TXN-(?P<Y>\d{{4}})(?P<m>\d{{2}})(?P<d>\d{{2}})-(?P<H>\d{{2}})(?P<M>\d{{2}})'
window = "15m"
services = ["orders"]

[[services]]
name = "orders"
description = "Order API: create / update / cancel / status"

[[redaction]]
name = "bearer"
regex = '(?i)bearer\s+[a-z0-9._-]+'
replace = "bearer <redacted>"
"#,
            root = root.display()
        ),
    )
    .unwrap();

    Fixture {
        dir,
        root,
        config,
        now,
        h0,
        id,
        billing_unreadable,
    }
}

/// First timestamp ≥ `from` whose line is an ERROR line.
fn find_error_ts(from: DateTime<Utc>) -> DateTime<Utc> {
    let mut t = from;
    loop {
        let n = (t.timestamp() / STEP_SECS) % 3600;
        if n % 60 == 30 {
            return t;
        }
        t += Duration::seconds(STEP_SECS);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                fs::set_permissions(self.root.join("billing"), fs::Permissions::from_mode(0o755));
        }
    }
}
