//! Search engine: runs the ripgrep library crates in-process over a planned file list on the
//! shared worker pool, with bounded look-ahead, a deadline, cancellation and per-request caps.

pub mod extract;
pub mod output;
pub mod pool;
pub mod reader;
pub mod seek;
pub mod sink;

use std::collections::{BTreeMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use grep_searcher::{BinaryDetection, MmapChoice, Searcher, SearcherBuilder};

use crate::errors::{ToolError, ToolResult};
use crate::logs::catalog::{Compression, LogFile};
use crate::parse::line::LineParser;
use crate::parse::time::{Ts, Window};

pub use pool::WorkerPool;
pub use reader::{Guard, StopReason};
pub use sink::Order;
use sink::{CountSink, LineSink, RawHit, TimeFilter};

/// Longest single line the searcher will buffer before giving up on a file. Kept small: it is
/// per worker thread, and a few of them run per request.
const HEAP_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct PatternSpec {
    pub pattern: String,
    pub fixed_string: bool,
    pub ignore_case: bool,
}

pub fn build_matcher(spec: &PatternSpec, size_limit: usize) -> ToolResult<RegexMatcher> {
    if spec.pattern.is_empty() {
        return Err(ToolError::Pattern("pattern must not be empty".into()));
    }
    if spec.pattern.contains('\n') {
        return Err(ToolError::Pattern("pattern must be a single line".into()));
    }
    RegexMatcherBuilder::new()
        .case_insensitive(spec.ignore_case)
        .fixed_strings(spec.fixed_string)
        .line_terminator(Some(b'\n'))
        .size_limit(size_limit)
        .dfa_size_limit(size_limit)
        .build(&spec.pattern)
        .map_err(|e| ToolError::Pattern(e.to_string()))
}

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Lines {
        order: Order,
        max_lines: usize,
        max_bytes: usize,
        before: usize,
        after: usize,
    },
    Count {
        per_minute: bool,
        /// `locate`: once a (service, host) has a hit, skip its remaining files.
        first_file_per_host: bool,
    },
}

pub struct Job {
    pub files: Vec<Arc<LogFile>>,
    pub matcher: RegexMatcher,
    pub invert: bool,
    pub window: Window,
    pub mode: Mode,
    pub parser: Option<LineParser>,
    /// Max files this request keeps in flight on the shared pool (its look-ahead).
    pub workers: usize,
    pub guard: Guard,
    pub keep_bytes: usize,
    pub copytruncate: bool,
    pub now: Ts,
}

#[derive(Debug, Clone)]
pub struct Found {
    pub file: Arc<LogFile>,
    pub hit: RawHit,
}

#[derive(Debug, Clone)]
pub struct FileCount {
    pub file: Arc<LogFile>,
    pub count: u64,
    pub per_minute: Option<BTreeMap<i64, u64>>,
    pub no_ts: u64,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub hits: Vec<Found>,
    pub counts: Vec<FileCount>,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub truncated: bool,
    pub stopped: Option<StopReason>,
    pub warnings: Vec<String>,
}

struct FileResult {
    hits: Vec<RawHit>,
    capped: bool,
    count: Option<FileCount>,
    scanned: bool,
    /// The file could not be read completely (error, heap limit, truncated while reading).
    partial: bool,
    warning: Option<String>,
}

impl FileResult {
    fn empty() -> Self {
        Self {
            hits: Vec::new(),
            capped: false,
            count: None,
            scanned: false,
            partial: false,
            warning: None,
        }
    }
}

impl Job {
    fn searcher(&self) -> Searcher {
        let (before, after) = match self.mode {
            Mode::Lines { before, after, .. } => (before, after),
            Mode::Count { .. } => (0, 0),
        };
        SearcherBuilder::new()
            .line_number(false)
            .invert_match(self.invert)
            .before_context(before)
            .after_context(after)
            // NUL runs (sparse holes left by copytruncate) become empty lines instead of
            // one giant line or a binary-file abort.
            .binary_detection(BinaryDetection::convert(b'\0'))
            // Offsets must be raw file/stream positions: no BOM stripping or transcoding.
            .bom_sniffing(false)
            .memory_map(MmapChoice::never())
            .heap_limit(Some(HEAP_LIMIT))
            .build()
    }

    fn search_file(&self, file: &Arc<LogFile>) -> FileResult {
        let mut res = FileResult::empty();
        if self.guard.stopped() {
            return res;
        }
        let span = self.window.span();
        let start = match (self.parser.as_ref(), file.compression) {
            (Some(p), Compression::None) if span.from > file.coverage.from => {
                // Grace for slightly out-of-order lines just after the window start.
                let from = span.from - sink::LATE_GRACE;
                match seek::find_start(&file.path, from, p, self.now, &self.guard) {
                    Ok(o) => o,
                    Err(e) if reader::is_stop_error(&e) => return res,
                    Err(_) => 0,
                }
            }
            _ => 0,
        };
        let opened = match reader::open(file, start, &self.guard, self.copytruncate) {
            Ok(o) => o,
            Err(e) => {
                res.warning = Some(format!("{}/{}: cannot open: {e}", file.service, file.name));
                return res;
            }
        };
        res.scanned = true;
        let nominal = file.bucket.unwrap_or(file.coverage);
        let filter = TimeFilter::new(
            self.parser.as_ref(),
            &self.window,
            self.now,
            self.window.overlaps(&nominal),
        );
        // Stop reading once the stream is past the window, even if nothing matches there.
        let input: Box<dyn std::io::Read + Send + '_> = match self.parser.as_ref() {
            Some(p) => Box::new(reader::TimeStop::new(
                opened.reader,
                p,
                span.to + sink::LATE_GRACE,
                self.now,
            )),
            None => opened.reader,
        };
        let mut searcher = self.searcher();
        let result = match self.mode {
            Mode::Lines {
                order,
                max_lines,
                max_bytes,
                before,
                after,
            } => {
                let mut sink = LineSink::new(
                    filter,
                    start,
                    order,
                    max_lines,
                    max_bytes,
                    before,
                    after,
                    self.keep_bytes,
                );
                let r = searcher.search_reader(&self.matcher, input, &mut sink);
                res.capped = sink.capped;
                res.hits = sink.hits.into();
                r
            }
            Mode::Count { per_minute, .. } => {
                let mut sink = CountSink::new(filter, per_minute);
                let r = searcher.search_reader(&self.matcher, input, &mut sink);
                res.count = Some(FileCount {
                    file: file.clone(),
                    count: sink.count,
                    per_minute: sink.per_minute,
                    no_ts: sink.no_ts,
                });
                r
            }
        };
        if let Err(e) = result
            && !reader::is_stop_error(&e)
        {
            res.partial = true;
            res.warning = Some(format!(
                "{}/{}: read error (results for this file may be partial): {e}",
                file.service, file.name
            ));
        }
        if opened.shrunk.load(Ordering::Relaxed) {
            res.partial = true;
            res.warning = Some(format!(
                "{}/{}: file was truncated while being read (rotation); results for it may be partial",
                file.service, file.name
            ));
        }
        res
    }
}

/// Groups consecutive file indices with the same bucket (files must be sorted by group key).
fn groups(files: &[Arc<LogFile>]) -> Vec<Vec<usize>> {
    let mut out: Vec<Vec<usize>> = Vec::new();
    let mut last: Option<Ts> = None;
    for (i, f) in files.iter().enumerate() {
        let k = f.group_key();
        if last != Some(k) {
            out.push(Vec::new());
            last = Some(k);
        }
        out.last_mut().unwrap().push(i);
    }
    out
}

fn sort_key(f: &Found) -> (Ts, Ts, &str, &str, u64) {
    (
        f.hit.sort_ts.unwrap_or_else(|| f.file.group_key()),
        f.file.group_key(),
        &f.file.host,
        &f.file.service,
        f.hit.byte_offset,
    )
}

/// Keeps the earliest (First) or latest (Last) hits within the line and byte caps.
/// Returns true if anything was dropped.
fn trim(acc: &mut Vec<Found>, order: Order, max_lines: usize, max_bytes: usize) -> bool {
    acc.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    if order == Order::Last {
        acc.reverse();
    }
    let mut bytes = 0usize;
    let mut keep = 0usize;
    for f in acc.iter() {
        let sz = f.hit.size();
        if keep >= max_lines || (keep > 0 && bytes + sz > max_bytes) {
            break;
        }
        bytes += sz;
        keep += 1;
    }
    let dropped = keep < acc.len();
    acc.truncate(keep);
    if order == Order::Last {
        acc.reverse();
    }
    dropped
}

/// Runs a job to completion on the shared pool (blocking; call from `spawn_blocking`).
pub fn run(job: Job, pool: &WorkerPool) -> Outcome {
    let job = Arc::new(job);
    let mut out = Outcome::default();
    match job.mode {
        Mode::Lines {
            order,
            max_lines,
            max_bytes,
            ..
        } => run_lines(&job, pool, order, max_lines, max_bytes, &mut out),
        Mode::Count {
            first_file_per_host,
            ..
        } => run_count(&job, pool, first_file_per_host, &mut out),
    }
    out.bytes_scanned = job.guard.bytes_scanned();
    out.stopped = job.guard.stop.get().filter(|r| *r != StopReason::Enough);
    if out.stopped.is_some() {
        out.truncated = true;
    }
    out
}

/// Decides, just before a file is searched, whether to skip it (locate: host already found).
type SkipFn = Arc<dyn Fn(&LogFile) -> bool + Send + Sync>;

/// Searches the files at `positions` (indices into `job.files`) in that order with at most
/// `job.workers` in flight, handing each result to `on_result` together with its position.
/// `on_result` returns false to stop: unstarted files are dropped and running ones are told to
/// stop. Results arrive in completion order.
fn drive(
    job: &Arc<Job>,
    pool: &WorkerPool,
    positions: &[usize],
    skip: Option<SkipFn>,
    mut on_result: impl FnMut(usize, FileResult) -> bool,
) {
    let session = pool.session();
    let (tx, rx) = mpsc::channel::<(usize, FileResult)>();
    let lookahead = job.workers.max(1);
    let mut next = 0usize;
    let mut in_flight = 0usize;
    loop {
        while in_flight < lookahead && next < positions.len() && !job.guard.stopped() {
            let pos = next;
            let i = positions[pos];
            let (job, tx, skip) = (job.clone(), tx.clone(), skip.clone());
            session.submit(move || {
                let f = &job.files[i];
                let r = if skip.as_ref().is_some_and(|s| s(f)) {
                    FileResult::empty()
                } else {
                    catch_unwind(AssertUnwindSafe(|| job.search_file(f))).unwrap_or_else(|_| {
                        let mut r = FileResult::empty();
                        r.partial = true;
                        r.warning = Some(format!(
                            "{}/{}: internal error while searching",
                            f.service, f.name
                        ));
                        r
                    })
                };
                let _ = tx.send((pos, r));
            });
            next += 1;
            in_flight += 1;
        }
        if in_flight == 0 {
            break;
        }
        let Ok((pos, r)) = rx.recv() else { break };
        in_flight -= 1;
        if !on_result(pos, r) {
            // Tell files still running to stop; their results are discarded.
            job.guard.stop.set(StopReason::Enough);
            break;
        }
    }
}

fn merge_result(out: &mut Outcome, r: &FileResult) {
    if r.scanned {
        out.files_scanned += 1;
    }
    out.truncated |= r.capped || r.partial;
    if let Some(w) = &r.warning {
        out.warnings.push(w.clone());
    }
}

fn run_lines(
    job: &Arc<Job>,
    pool: &WorkerPool,
    order: Order,
    max_lines: usize,
    max_bytes: usize,
    out: &mut Outcome,
) {
    let mut gs = groups(&job.files);
    if order == Order::Last {
        gs.reverse();
    }
    // Files in processing order; group g covers positions starts[g]..starts[g] + gs[g].len().
    let positions: Vec<usize> = gs.iter().flatten().copied().collect();
    let mut group_of = Vec::with_capacity(positions.len());
    let mut starts = Vec::with_capacity(gs.len());
    for (g, files) in gs.iter().enumerate() {
        starts.push(group_of.len());
        group_of.extend(std::iter::repeat_n(g, files.len()));
    }
    let mut remaining: Vec<usize> = gs.iter().map(|g| g.len()).collect();
    let mut done: Vec<Option<FileResult>> = (0..positions.len()).map(|_| None).collect();
    let mut next_group = 0usize;
    let mut acc: Vec<Found> = Vec::new();

    drive(job, pool, &positions, None, |pos, r| {
        let g = group_of[pos];
        done[pos] = Some(r);
        remaining[g] -= 1;
        // Merge groups strictly in order, as soon as each is complete.
        while next_group < gs.len() && remaining[next_group] == 0 {
            let first = starts[next_group];
            for p in first..first + gs[next_group].len() {
                let r = done[p].take().expect("completed result");
                merge_result(out, &r);
                let file = &job.files[positions[p]];
                acc.extend(r.hits.into_iter().map(|hit| Found {
                    file: file.clone(),
                    hit,
                }));
            }
            let dropped = trim(&mut acc, order, max_lines, max_bytes);
            out.truncated |= dropped;
            next_group += 1;
            // If trimming dropped anything, the caps are reached: later groups (strictly later
            // for First, earlier for Last) cannot displace what we hold.
            let full = dropped
                || acc.len() >= max_lines
                || acc.iter().map(|f| f.hit.size()).sum::<usize>() >= max_bytes;
            if full && next_group < gs.len() {
                out.truncated = true;
                return false;
            }
        }
        true
    });
    out.hits = acc;
}

fn run_count(job: &Arc<Job>, pool: &WorkerPool, first_file_per_host: bool, out: &mut Outcome) {
    let found: Arc<Mutex<HashSet<(String, String)>>> = Arc::new(Mutex::new(HashSet::new()));
    let skip: Option<SkipFn> = first_file_per_host.then(|| {
        let found = found.clone();
        Arc::new(move |f: &LogFile| {
            found
                .lock()
                .unwrap()
                .contains(&(f.service.clone(), f.host.clone()))
        }) as Arc<dyn Fn(&LogFile) -> bool + Send + Sync>
    });
    let positions: Vec<usize> = (0..job.files.len()).collect();
    let mut counts = Vec::new();
    drive(job, pool, &positions, skip, |_, r| {
        merge_result(out, &r);
        if let Some(c) = r.count {
            if first_file_per_host && c.count > 0 {
                found
                    .lock()
                    .unwrap()
                    .insert((c.file.service.clone(), c.file.host.clone()));
            }
            counts.push(c);
        }
        true
    });
    counts.sort_by(|a, b| a.file.order_key().cmp(&b.file.order_key()));
    out.counts = counts;
}
