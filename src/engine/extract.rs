//! Direct extraction without a regex search: lines around a byte offset (`read_context`) and the
//! last N lines of a live file (`tail_live`).

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};

use grep_matcher::Matcher;
use grep_regex::RegexMatcher;

use crate::logs::catalog::{Compression, LogFile};

use super::reader::{self, Guard};
use super::sink::trim_eol;

const CHUNK: u64 = 64 * 1024;
/// A single line longer than this is dropped by tail (kept memory bounded).
const MAX_CARRY: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Line {
    pub byte_offset: u64,
    pub text: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Context {
    pub before: Vec<Line>,
    pub line: Option<Line>,
    pub after: Vec<Line>,
}

/// Reads the line containing `offset` plus `before`/`after` lines around it. For compressed files
/// the offset is a position in the decompressed stream (as reported by search results).
pub fn read_context(
    file: &LogFile,
    offset: u64,
    before: usize,
    after: usize,
    keep_bytes: usize,
    guard: &Guard,
) -> io::Result<Context> {
    // Plain files: start a bounded distance before the offset instead of at 0.
    let start = if file.compression == Compression::None {
        let back = (before as u64 + 1) * keep_bytes.max(1024) as u64 * 4;
        let s = offset.saturating_sub(back);
        if s == 0 {
            0
        } else {
            align_to_line(&file.path, s)?
        }
    } else {
        0
    };
    let opened = reader::open(file, start, guard, false)?;
    let mut r = BufReader::with_capacity(256 * 1024, opened.reader);
    let mut pos = start;
    let mut ring: VecDeque<Line> = VecDeque::with_capacity(before + 1);
    let mut buf = Vec::new();
    let mut ctx = Context::default();
    loop {
        let n = read_line_bounded(&mut r, keep_bytes, &mut buf)?;
        if n == 0 {
            break;
        }
        let line = Line {
            byte_offset: pos,
            text: trim_eol(&buf).to_vec(),
        };
        let end = pos + n as u64;
        pos = end;
        if ctx.line.is_none() {
            if offset < end {
                ctx.line = Some(line);
                ctx.before = ring.drain(..).collect();
                if after == 0 {
                    break;
                }
            } else {
                ring.push_back(line);
                if ring.len() > before {
                    ring.pop_front();
                }
            }
        } else {
            ctx.after.push(line);
            if ctx.after.len() >= after {
                break;
            }
        }
    }
    Ok(ctx)
}

/// Moves a plain-file offset forward to the next line start.
fn align_to_line(path: &std::path::Path, offset: u64) -> io::Result<u64> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(offset - 1))?;
    let mut r = BufReader::new(f);
    let mut skipped = Vec::new();
    let n = read_line_bounded(&mut r, 0, &mut skipped)?;
    Ok(offset - 1 + n as u64)
}

/// Reads one line into `out`, keeping at most `keep` bytes of it (the rest is skipped, so memory
/// stays bounded however long the line is). A line ends at `\n` or at a run of NUL bytes (holes
/// left by copytruncate), matching how the search engine splits lines, so byte offsets agree.
/// Returns the number of bytes consumed; 0 means EOF.
fn read_line_bounded<R: BufRead>(r: &mut R, keep: usize, out: &mut Vec<u8>) -> io::Result<usize> {
    out.clear();
    let mut consumed = 0usize;
    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            return Ok(consumed);
        }
        let room = keep.saturating_sub(out.len());
        match buf.iter().position(|&b| b == b'\n' || b == 0) {
            Some(i) => {
                out.extend_from_slice(&buf[..i.min(room)]);
                let nul = buf[i] == 0;
                r.consume(i + 1);
                consumed += i + 1;
                if nul {
                    // Swallow the rest of the NUL run, which may span many buffers.
                    loop {
                        let b = r.fill_buf()?;
                        let len = b.len();
                        let k = b.iter().take_while(|&&c| c == 0).count();
                        r.consume(k);
                        consumed += k;
                        if k == 0 || k < len {
                            break;
                        }
                    }
                }
                return Ok(consumed);
            }
            None => {
                let n = buf.len();
                out.extend_from_slice(&buf[..n.min(room)]);
                r.consume(n);
                consumed += n;
            }
        }
    }
}

/// Returns up to `n` last lines of a plain file (optionally only lines matching `filter`), in file
/// order. Reads backwards in chunks, at most `max_scan` bytes.
pub fn tail(
    file: &LogFile,
    n: usize,
    filter: Option<&RegexMatcher>,
    max_scan: u64,
    keep_bytes: usize,
    guard: &Guard,
) -> io::Result<(Vec<Line>, bool)> {
    let mut f = File::open(&file.path)?;
    let len = f.metadata()?.len();
    let mut pos = len;
    let mut carry: Vec<u8> = Vec::new();
    let mut out: Vec<Line> = Vec::new();
    let mut scanned = 0u64;
    let mut at_eof = true;
    let mut buf = Vec::new();

    let take = |text: &[u8], off: u64, out: &mut Vec<Line>| {
        let text = trim_eol(text);
        let keep = match filter {
            Some(m) => m.is_match(text).unwrap_or(false),
            None => true,
        };
        if keep {
            out.push(Line {
                byte_offset: off,
                text: text[..text.len().min(keep_bytes)].to_vec(),
            });
        }
    };

    while pos > 0 && out.len() < n {
        if scanned >= max_scan {
            return Ok((finish(out, n), true));
        }
        guard.check()?;
        let start = pos.saturating_sub(CHUNK);
        let sz = (pos - start) as usize;
        buf.resize(sz, 0);
        f.seek(SeekFrom::Start(start))?;
        f.read_exact(&mut buf)?;
        scanned += sz as u64;
        guard
            .bytes
            .fetch_add(sz as u64, std::sync::atomic::Ordering::Relaxed);
        buf.extend_from_slice(&carry);

        let mut end = buf.len();
        while let Some(i) = buf[..end].iter().rposition(|&c| c == b'\n') {
            let seg_start = i + 1;
            if !(at_eof && seg_start == end) {
                take(&buf[seg_start..end], start + seg_start as u64, &mut out);
                if out.len() >= n {
                    break;
                }
            }
            at_eof = false;
            end = i;
        }
        if out.len() >= n {
            break;
        }
        at_eof = at_eof && end == buf.len();
        carry = buf[..end].to_vec();
        if carry.len() > MAX_CARRY {
            carry.clear();
        }
        pos = start;
        if pos == 0 && !carry.is_empty() {
            let c = std::mem::take(&mut carry);
            take(&c, 0, &mut out);
        }
    }
    Ok((finish(out, n), false))
}

fn finish(mut out: Vec<Line>, n: usize) -> Vec<Line> {
    out.truncate(n);
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::time::Interval;
    use std::time::{Duration, Instant};

    fn lf(path: std::path::PathBuf, comp: Compression) -> LogFile {
        LogFile {
            service: "s".into(),
            name: "f".into(),
            path,
            host: "h".into(),
            live: true,
            suffix_at: None,
            bucket: None,
            coverage: Interval::all(),
            compression: comp,
            size: 0,
            mtime: chrono::Utc::now(),
        }
    }

    fn write_lines(n: usize) -> (tempfile::TempDir, std::path::PathBuf, Vec<u64>) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.log");
        let mut s = String::new();
        let mut offs = Vec::new();
        for i in 0..n {
            offs.push(s.len() as u64);
            s.push_str(&format!("line {i} {}\n", "x".repeat(i % 50)));
        }
        std::fs::write(&p, s).unwrap();
        (d, p, offs)
    }

    fn guard() -> Guard {
        Guard::new(Instant::now() + Duration::from_secs(10))
    }

    fn txt(l: &Line) -> String {
        String::from_utf8_lossy(&l.text)
            .split(' ')
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn tail_last_lines() {
        let (_d, p, offs) = write_lines(5000);
        let f = lf(p, Compression::None);
        let (lines, partial) = tail(&f, 3, None, u64::MAX, 4096, &guard()).unwrap();
        assert!(!partial);
        assert_eq!(
            lines.iter().map(txt).collect::<Vec<_>>(),
            ["line 4997", "line 4998", "line 4999"]
        );
        assert_eq!(lines[0].byte_offset, offs[4997]);

        let m = RegexMatcherBuilderShim::fixed("line 12");
        let (lines, _) = tail(&f, 2, Some(&m), u64::MAX, 4096, &guard()).unwrap();
        assert_eq!(
            lines.iter().map(txt).collect::<Vec<_>>(),
            ["line 1298", "line 1299"]
        );

        let (lines, _) = tail(&f, 10_000, None, u64::MAX, 4096, &guard()).unwrap();
        assert_eq!(lines.len(), 5000);
        assert_eq!(lines[0].byte_offset, 0);
    }

    #[test]
    fn tail_without_trailing_newline() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.log");
        std::fs::write(&p, "a\nb\nc").unwrap();
        let (lines, _) =
            tail(&lf(p, Compression::None), 2, None, u64::MAX, 4096, &guard()).unwrap();
        assert_eq!(
            lines.iter().map(|l| l.text.clone()).collect::<Vec<_>>(),
            [b"b".to_vec(), b"c".to_vec()]
        );
    }

    #[test]
    fn context_plain_and_gzip() {
        let (_d, p, offs) = write_lines(3000);
        let f = lf(p.clone(), Compression::None);
        let c = read_context(&f, offs[2000] + 3, 2, 2, 4096, &guard()).unwrap();
        assert_eq!(txt(c.line.as_ref().unwrap()), "line 2000");
        assert_eq!(
            c.before.iter().map(txt).collect::<Vec<_>>(),
            ["line 1998", "line 1999"]
        );
        assert_eq!(
            c.after.iter().map(txt).collect::<Vec<_>>(),
            ["line 2001", "line 2002"]
        );

        let gz = p.with_extension("gz");
        let mut enc =
            flate2::write::GzEncoder::new(File::create(&gz).unwrap(), flate2::Compression::fast());
        std::io::Write::write_all(&mut enc, &std::fs::read(&p).unwrap()).unwrap();
        enc.finish().unwrap();
        let fz = lf(gz, Compression::Gzip);
        let c = read_context(&fz, offs[10], 1, 0, 4096, &guard()).unwrap();
        assert_eq!(txt(c.line.as_ref().unwrap()), "line 10");
        assert_eq!(c.before.iter().map(txt).collect::<Vec<_>>(), ["line 9"]);
    }

    #[test]
    fn context_survives_huge_nul_hole_in_gzip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.log.gz");
        let mut enc =
            flate2::write::GzEncoder::new(File::create(&p).unwrap(), flate2::Compression::fast());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..64 {
            std::io::Write::write_all(&mut enc, &zeros).unwrap(); // 64 MiB without a newline
        }
        std::io::Write::write_all(&mut enc, b"first\nsecond\nthird\n").unwrap();
        enc.finish().unwrap();
        let f = lf(p, Compression::Gzip);
        let off = (64u64 << 20) + "first\n".len() as u64;
        let c = read_context(&f, off, 1, 1, 4096, &guard()).unwrap();
        assert_eq!(c.line.unwrap().text, b"second");
        assert_eq!(
            c.before.iter().map(|l| l.text.clone()).collect::<Vec<_>>(),
            [b"first".to_vec()]
        );
        assert_eq!(c.after[0].text, b"third");
    }

    #[test]
    fn long_lines_are_cut_while_reading() {
        let mut r = std::io::BufReader::with_capacity(
            16,
            std::io::Cursor::new(format!("{}\nok\n", "x".repeat(10_000))),
        );
        let mut out = Vec::new();
        assert_eq!(read_line_bounded(&mut r, 10, &mut out).unwrap(), 10_001);
        assert_eq!(out, b"xxxxxxxxxx");
        assert_eq!(read_line_bounded(&mut r, 10, &mut out).unwrap(), 3);
        assert_eq!(out, b"ok");
        assert_eq!(read_line_bounded(&mut r, 10, &mut out).unwrap(), 0);
    }

    struct RegexMatcherBuilderShim;
    impl RegexMatcherBuilderShim {
        fn fixed(p: &str) -> RegexMatcher {
            grep_regex::RegexMatcherBuilder::new()
                .fixed_strings(true)
                .line_terminator(Some(b'\n'))
                .build(p)
                .unwrap()
        }
    }
}
