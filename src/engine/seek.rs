//! Binary search over a plain (uncompressed) log file for the first line whose timestamp is at or
//! after `from`. The result is conservative: it may start earlier than necessary (lines before
//! `from` are still filtered per line), but never later.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::parse::line::LineParser;
use crate::parse::time::Ts;

use super::reader::Guard;

const PROBE: usize = 64 * 1024;
/// Stop bisecting once the remaining range is this small; a linear scan is cheaper.
const MIN_RANGE: u64 = 256 * 1024;

/// Returns a byte offset at a line start such that no line at or after `from` precedes it.
pub fn find_start(
    path: &Path,
    from: Ts,
    parser: &LineParser,
    now: Ts,
    guard: &Guard,
) -> io::Result<u64> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let mut lo = 0u64; // invariant: lo is a line start and every line before lo is < from
    let mut hi = len;
    let mut buf = vec![0u8; PROBE];

    while hi.saturating_sub(lo) > MIN_RANGE {
        guard.check()?;
        let mid = lo + (hi - lo) / 2;
        f.seek(SeekFrom::Start(mid))?;
        let n = read_full(&mut f, &mut buf)?;
        let chunk = &buf[..n];
        // Skip the partial line at `mid`.
        let Some(nl) = memchr(b'\n', chunk) else {
            hi = mid;
            continue;
        };
        let mut start = nl + 1;
        let mut probe: Option<(u64, Ts)> = None;
        while start < chunk.len() {
            let end = memchr(b'\n', &chunk[start..]).map(|i| start + i);
            let Some(end) = end else { break };
            if let Some(ts) = parser.parse_ts(&chunk[start..end], now) {
                probe = Some((mid + start as u64, ts));
                break;
            }
            start = end + 1;
        }
        match probe {
            Some((line_start, ts)) if ts < from => lo = line_start,
            // ts >= from, or no parseable line in the probe: search the lower half.
            _ => hi = mid,
        }
    }
    Ok(lo)
}

fn read_full(f: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn memchr(b: u8, hay: &[u8]) -> Option<usize> {
    hay.iter().position(|&c| c == b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::time::parse_instant;
    use std::io::Write;
    use std::time::{Duration, Instant};

    #[test]
    fn finds_start_conservatively() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("live.log");
        let mut f = File::create(&p).unwrap();
        let base = parse_instant("2026-06-02T00:00:00Z", &chrono_tz::UTC).unwrap();
        let mut offsets = Vec::new();
        let mut off = 0u64;
        for i in 0..200_000i64 {
            let ts = base + chrono::Duration::seconds(i);
            let line = format!(
                "{} host app: line {i} padding-padding-padding\n",
                ts.to_rfc3339()
            );
            offsets.push((ts, off));
            off += line.len() as u64;
            f.write_all(line.as_bytes()).unwrap();
        }
        drop(f);
        let parser = LineParser::new(r"^(?P<ts>\S+)", "rfc3339", None, chrono_tz::UTC).unwrap();
        let guard = Guard::new(Instant::now() + Duration::from_secs(10));
        let target = base + chrono::Duration::seconds(150_000);
        let start = find_start(&p, target, &parser, base, &guard).unwrap();
        let exact = offsets.iter().find(|(t, _)| *t >= target).unwrap().1;
        assert!(start <= exact, "start {start} must not pass {exact}");
        assert!(
            exact - start <= MIN_RANGE + PROBE as u64,
            "start {start} too far from {exact}"
        );
        assert!(start > 0);

        // Before the first line → 0.
        let s0 = find_start(&p, base - chrono::Duration::hours(1), &parser, base, &guard).unwrap();
        assert_eq!(s0, 0);
    }
}
