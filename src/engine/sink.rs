//! grep-searcher sinks: one that collects matching lines with context under line/byte caps, and
//! one that only counts. Both apply the optional per-line time filter.

use std::collections::{BTreeMap, VecDeque};
use std::io;

use chrono::Duration;
use grep_searcher::{Searcher, Sink, SinkContext, SinkContextKind, SinkMatch};

use crate::parse::line::LineParser;
use crate::parse::time::{Ts, Window};

/// Lines with timestamps this far past the window end stop the file (allows for slightly
/// out-of-order lines from concurrent writers).
pub const LATE_GRACE: Duration = Duration::minutes(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    First,
    Last,
}

#[derive(Debug, Clone)]
pub struct RawHit {
    pub byte_offset: u64,
    pub ts: Option<Ts>,
    /// Timestamp used for sorting: own ts, or the one inherited from a preceding line.
    pub sort_ts: Option<Ts>,
    pub text: Vec<u8>,
    pub before: Vec<Vec<u8>>,
    pub after: Vec<Vec<u8>>,
}

impl RawHit {
    pub fn size(&self) -> usize {
        self.text.len()
            + self.before.iter().map(|l| l.len()).sum::<usize>()
            + self.after.iter().map(|l| l.len()).sum::<usize>()
    }
}

/// Shared time filter: decides whether a matched line is in the window, and when to stop a file.
///
/// Lines without their own timestamp (stack traces, wrapped JSON) inherit the timestamp of the
/// nearest preceding timestamped line in the search buffer, then the last one seen in this file.
/// If neither exists, the file's nominal bucket decides (`fallback_in_window`).
pub struct TimeFilter<'a> {
    parser: Option<&'a LineParser>,
    window: &'a Window,
    now: Ts,
    fallback_in_window: bool,
    last_ts: Option<Ts>,
}

pub enum Verdict {
    Keep {
        /// The line's own timestamp.
        own: Option<Ts>,
        /// Own or inherited timestamp (used for sorting and minute buckets).
        effective: Option<Ts>,
    },
    Skip,
    StopFile,
}

/// How far back in the buffer to look for a timestamped line.
const INHERIT_SCAN_BYTES: usize = 64 * 1024;
const INHERIT_SCAN_LINES: usize = 200;

impl<'a> TimeFilter<'a> {
    pub fn new(
        parser: Option<&'a LineParser>,
        window: &'a Window,
        now: Ts,
        fallback_in_window: bool,
    ) -> Self {
        Self {
            parser,
            window,
            now,
            fallback_in_window,
            last_ts: None,
        }
    }

    pub fn check(&mut self, m: &SinkMatch<'_>) -> Verdict {
        let Some(p) = self.parser else {
            return Verdict::Keep {
                own: None,
                effective: None,
            };
        };
        let own = p.parse_ts(trim_eol(m.bytes()), self.now);
        let effective = own
            .or_else(|| preceding_ts(p, m.buffer(), m.bytes_range_in_buffer().start, self.now))
            .or(self.last_ts);
        if effective.is_some() {
            self.last_ts = effective;
        }
        match effective {
            None if self.fallback_in_window => Verdict::Keep { own, effective },
            None => Verdict::Skip,
            Some(t) if self.window.contains(t) => Verdict::Keep { own, effective },
            Some(t) if t >= self.window.span().to + LATE_GRACE => Verdict::StopFile,
            Some(_) => Verdict::Skip,
        }
    }
}

/// Timestamp of the nearest timestamped line before `start` in `buf` (bounded scan).
fn preceding_ts(p: &LineParser, buf: &[u8], start: usize, now: Ts) -> Option<Ts> {
    let floor = start.saturating_sub(INHERIT_SCAN_BYTES);
    let mut end = start; // start of the line after the candidate
    for _ in 0..INHERIT_SCAN_LINES {
        if end <= floor || end == 0 {
            return None;
        }
        let line_end = end - 1; // the '\n' terminating the candidate line
        let line_start = buf[floor..line_end]
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|i| floor + i + 1)
            .unwrap_or(floor);
        if let Some(t) = p.parse_ts(trim_eol(&buf[line_start..line_end]), now) {
            return Some(t);
        }
        end = line_start;
    }
    None
}

pub fn trim_eol(b: &[u8]) -> &[u8] {
    let b = b.strip_suffix(b"\n").unwrap_or(b);
    b.strip_suffix(b"\r").unwrap_or(b)
}

fn keep(b: &[u8], max: usize) -> Vec<u8> {
    let b = trim_eol(b);
    b[..b.len().min(max)].to_vec()
}

pub struct LineSink<'a> {
    pub filter: TimeFilter<'a>,
    /// Offset of the reader start within the file (seeked plain files).
    pub base: u64,
    pub order: Order,
    pub max_lines: usize,
    pub max_bytes: usize,
    pub before: usize,
    pub after: usize,
    /// Raw bytes kept per line (final truncation happens in output).
    pub keep_bytes: usize,

    pub hits: VecDeque<RawHit>,
    pub bytes: usize,
    /// True if matches were dropped or the file was stopped because of the caps.
    pub capped: bool,
    pending_before: Vec<Vec<u8>>,
    last_active: bool,
    stopping: bool,
}

impl<'a> LineSink<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        filter: TimeFilter<'a>,
        base: u64,
        order: Order,
        max_lines: usize,
        max_bytes: usize,
        before: usize,
        after: usize,
        keep_bytes: usize,
    ) -> Self {
        Self {
            filter,
            base,
            order,
            max_lines,
            max_bytes,
            before,
            after,
            keep_bytes,
            hits: VecDeque::new(),
            bytes: 0,
            capped: false,
            pending_before: Vec::new(),
            last_active: false,
            stopping: false,
        }
    }
}

impl Sink for LineSink<'_> {
    type Error = io::Error;

    fn matched(&mut self, _s: &Searcher, m: &SinkMatch<'_>) -> Result<bool, io::Error> {
        if self.stopping {
            self.capped = true;
            return Ok(false);
        }
        let line = trim_eol(m.bytes());
        let (ts, effective) = match self.filter.check(m) {
            Verdict::Keep { own, effective } => (own, effective),
            Verdict::Skip => {
                self.pending_before.clear();
                self.last_active = false;
                return Ok(true);
            }
            Verdict::StopFile => return Ok(false),
        };
        let hit = RawHit {
            byte_offset: self.base + m.absolute_byte_offset(),
            ts,
            sort_ts: effective,
            text: keep(line, self.keep_bytes),
            before: std::mem::take(&mut self.pending_before),
            after: Vec::new(),
        };
        self.bytes += hit.size();
        self.hits.push_back(hit);
        self.last_active = true;

        match self.order {
            Order::First => {
                if self.hits.len() >= self.max_lines || self.bytes >= self.max_bytes {
                    self.stopping = true;
                    if self.after == 0 {
                        self.capped = true;
                        return Ok(false);
                    }
                }
            }
            Order::Last => {
                while self.hits.len() > self.max_lines
                    || (self.bytes > self.max_bytes && self.hits.len() > 1)
                {
                    if let Some(h) = self.hits.pop_front() {
                        self.bytes -= h.size();
                    }
                    self.capped = true;
                }
            }
        }
        Ok(true)
    }

    fn context(&mut self, _s: &Searcher, c: &SinkContext<'_>) -> Result<bool, io::Error> {
        match c.kind() {
            SinkContextKind::Before => {
                self.pending_before.push(keep(c.bytes(), self.keep_bytes));
                if self.pending_before.len() > self.before {
                    self.pending_before.remove(0);
                }
            }
            SinkContextKind::After => {
                if self.last_active
                    && let Some(h) = self.hits.back_mut()
                    && h.after.len() < self.after
                {
                    let l = keep(c.bytes(), self.keep_bytes);
                    self.bytes += l.len();
                    h.after.push(l);
                    if self.stopping && h.after.len() >= self.after {
                        self.capped = true;
                        return Ok(false);
                    }
                }
            }
            SinkContextKind::Other => {}
        }
        Ok(true)
    }

    fn context_break(&mut self, _s: &Searcher) -> Result<bool, io::Error> {
        self.pending_before.clear();
        Ok(true)
    }
}

/// Counts matches; optionally per minute (needs line timestamps).
pub struct CountSink<'a> {
    pub filter: TimeFilter<'a>,
    pub count: u64,
    pub per_minute: Option<BTreeMap<i64, u64>>,
    pub no_ts: u64,
}

impl<'a> CountSink<'a> {
    pub fn new(filter: TimeFilter<'a>, per_minute: bool) -> Self {
        Self {
            filter,
            count: 0,
            per_minute: per_minute.then(BTreeMap::new),
            no_ts: 0,
        }
    }
}

impl Sink for CountSink<'_> {
    type Error = io::Error;

    fn matched(&mut self, _s: &Searcher, m: &SinkMatch<'_>) -> Result<bool, io::Error> {
        match self.filter.check(m) {
            Verdict::Keep { effective, .. } => {
                self.count += 1;
                if let Some(pm) = &mut self.per_minute {
                    match effective {
                        Some(t) => *pm.entry(t.timestamp().div_euclid(60)).or_default() += 1,
                        None => self.no_ts += 1,
                    }
                }
                Ok(true)
            }
            Verdict::Skip => Ok(true),
            Verdict::StopFile => Ok(false),
        }
    }
}
