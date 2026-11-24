//! File readers: plain, gzip (multi-member, for pigz output) and zstd. Every read goes through a
//! [`Guard`] that enforces the deadline and cancellation and counts scanned bytes. Live files are
//! read with plain buffered reads (never mmap): under copytruncate a mapped file that is truncated
//! raises SIGBUS. A file that shrinks while being read is reported, not treated as an error.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

use crate::logs::catalog::{Compression, LogFile};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StopReason {
    Timeout = 1,
    Cancelled = 2,
    /// Internal: the request already has all the results it can use.
    Enough = 3,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::Timeout => "timeout",
            StopReason::Cancelled => "cancelled",
            StopReason::Enough => "enough",
        }
    }
}

/// Request-wide stop flag, set by the deadline or by MCP request cancellation.
#[derive(Debug, Default)]
pub struct Stop(AtomicU8);

impl Stop {
    pub fn set(&self, r: StopReason) {
        let _ = self
            .0
            .compare_exchange(0, r as u8, Ordering::SeqCst, Ordering::SeqCst);
    }

    pub fn get(&self) -> Option<StopReason> {
        match self.0.load(Ordering::Relaxed) {
            1 => Some(StopReason::Timeout),
            2 => Some(StopReason::Cancelled),
            3 => Some(StopReason::Enough),
            _ => None,
        }
    }
}

/// Per-request guard shared by all readers of a request.
#[derive(Clone, Debug)]
pub struct Guard {
    pub stop: Arc<Stop>,
    pub deadline: Instant,
    pub bytes: Arc<AtomicU64>,
}

pub const STOPPED_MSG: &str = "grep-cp: search stopped";

impl Guard {
    pub fn new(deadline: Instant) -> Self {
        Self {
            stop: Arc::new(Stop::default()),
            deadline,
            bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn check(&self) -> io::Result<()> {
        if self.stop.get().is_none() && Instant::now() >= self.deadline {
            self.stop.set(StopReason::Timeout);
        }
        if self.stop.get().is_some() {
            // Must NOT be ErrorKind::Interrupted: std and decoder read loops retry those, which
            // would spin forever at 100% CPU instead of stopping.
            return Err(io::Error::other(STOPPED_MSG));
        }
        Ok(())
    }

    pub fn stopped(&self) -> bool {
        // check() records Timeout when the deadline has passed.
        self.check().is_err()
    }

    pub fn bytes_scanned(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// True if an error came from the guard stopping the search (decoders may wrap or re-word the
/// error, so match on the message anywhere in its text).
pub fn is_stop_error(e: &io::Error) -> bool {
    e.kind() != io::ErrorKind::Interrupted && e.to_string().contains(STOPPED_MSG)
}

/// A file handle that checks the guard on every read and detects in-place truncation.
pub struct GuardedFile {
    file: File,
    guard: Guard,
    pos: u64,
    detect_shrink: bool,
    shrunk: Arc<AtomicBool>,
}

impl Read for GuardedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.guard.check()?;
        let n = self.file.read(buf)?;
        if n == 0
            && self.detect_shrink
            && let Ok(m) = self.file.metadata()
            && m.len() < self.pos
        {
            self.shrunk.store(true, Ordering::Relaxed);
        }
        self.pos += n as u64;
        self.guard.bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

pub struct Opened {
    pub reader: Box<dyn Read + Send>,
    pub shrunk: Arc<AtomicBool>,
}

/// Opens a log file for streaming. `start` seeks into plain files only (offsets of compressed
/// files are positions in the decompressed stream and cannot be seeked).
pub fn open(file: &LogFile, start: u64, guard: &Guard, copytruncate: bool) -> io::Result<Opened> {
    let mut f = File::open(&file.path)?;
    let start = if file.compression == Compression::None && start > 0 {
        f.seek(SeekFrom::Start(start))?
    } else {
        0
    };
    let shrunk = Arc::new(AtomicBool::new(false));
    let gf = GuardedFile {
        file: f,
        guard: guard.clone(),
        pos: start,
        detect_shrink: copytruncate && file.live,
        shrunk: shrunk.clone(),
    };
    let reader: Box<dyn Read + Send> = match file.compression {
        Compression::None => Box::new(gf),
        Compression::Gzip => Box::new(flate2::read::MultiGzDecoder::new(BufReader::with_capacity(
            256 * 1024,
            gf,
        ))),
        #[cfg(feature = "zstd")]
        Compression::Zstd => Box::new(zstd::stream::read::Decoder::new(gf)?),
        #[cfg(not(feature = "zstd"))]
        Compression::Zstd => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "zstd support not compiled in (enable the 'zstd' feature)",
            ));
        }
    };
    Ok(Opened { reader, shrunk })
}

/// Ends the stream (EOF) once a line timestamp at the start of a read chunk is past `limit`, so a
/// search stops reading a file past the window even when nothing there matches. Lines inside the
/// chunk that triggered the stop are still delivered; per-line filtering handles them.
pub struct TimeStop<'a, R> {
    inner: R,
    parser: &'a crate::parse::line::LineParser,
    limit: crate::parse::time::Ts,
    now: crate::parse::time::Ts,
    done: bool,
}

impl<'a, R: Read> TimeStop<'a, R> {
    pub fn new(
        inner: R,
        parser: &'a crate::parse::line::LineParser,
        limit: crate::parse::time::Ts,
        now: crate::parse::time::Ts,
    ) -> Self {
        Self {
            inner,
            parser,
            limit,
            now,
            done: false,
        }
    }
}

impl<R: Read> Read for TimeStop<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        let n = self.inner.read(buf)?;
        let chunk = &buf[..n];
        // First complete line after the first newline (the chunk may start mid-line).
        if let Some(nl) = chunk.iter().position(|&b| b == b'\n') {
            let rest = &chunk[nl + 1..];
            if let Some(end) = rest.iter().position(|&b| b == b'\n')
                && let Some(t) = self.parser.parse_ts(&rest[..end], self.now)
                && t >= self.limit
            {
                self.done = true;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::line::LineParser;
    use crate::parse::time::parse_instant;

    #[test]
    fn time_stop_ends_stream_past_limit() {
        let base = parse_instant("2026-06-02T10:00:00Z", &chrono_tz::UTC).unwrap();
        let mut data = String::new();
        for i in 0..100_000i64 {
            let t = base + chrono::Duration::seconds(i);
            data.push_str(&format!("{} line {i}\n", t.to_rfc3339()));
        }
        let p = LineParser::new(r"^(?P<ts>\S+)", "rfc3339", None, chrono_tz::UTC).unwrap();
        let limit = base + chrono::Duration::seconds(1000);
        let mut r = TimeStop::new(data.as_bytes(), &p, limit, base);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert!(
            out.len() < data.len() / 10,
            "read {} of {}",
            out.len(),
            data.len()
        );
        assert!(String::from_utf8_lossy(&out).contains("line 999\n"));
    }

    #[test]
    fn stop_error_is_not_interrupted() {
        let g = Guard::new(Instant::now());
        let e = g.check().unwrap_err();
        assert_ne!(e.kind(), io::ErrorKind::Interrupted);
        assert!(is_stop_error(&e));
    }
}
