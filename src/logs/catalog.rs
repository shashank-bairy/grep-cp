//! Catalog: scans the root for service dirs and each service dir for log files, parses filenames
//! into (host, bucket, compression), computes each file's time coverage, and caches the result.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant, SystemTime};

use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

use crate::config::{Settings, SuffixMarks};
use crate::errors::{ToolError, ToolResult};
use crate::logs::sandbox::{confine, is_safe_component};
use crate::parse::time::{Interval, Ts, local_to_utc};

const CACHE_TTL: StdDuration = StdDuration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    None,
    Gzip,
    Zstd,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceEntry {
    pub name: String,
    pub readable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LogFile {
    pub service: String,
    /// Filename as listed in the service dir (the only file identifier callers ever see).
    pub name: String,
    /// Canonical path inside the root.
    pub path: PathBuf,
    pub host: String,
    pub live: bool,
    /// Instant encoded in the rotated filename suffix.
    pub suffix_at: Option<Ts>,
    /// Nominal bucket for rotated files (without safety margin).
    pub bucket: Option<Interval>,
    /// Interval this file may contain lines for (with safety margins). Used by the planner.
    pub coverage: Interval,
    pub compression: Compression,
    pub size: u64,
    pub mtime: Ts,
}

impl LogFile {
    /// Sort key for ordering files chronologically (live files last), then by host.
    pub fn order_key(&self) -> (Ts, &str) {
        (self.group_key(), &self.host)
    }

    /// Start of the nominal bucket; live files sort after every rotated file.
    pub fn group_key(&self) -> Ts {
        match self.bucket {
            Some(b) => b.from,
            None => DateTime::<Utc>::MAX_UTC,
        }
    }
}

#[derive(Debug)]
pub struct ServiceFiles {
    pub service: String,
    pub files: Vec<Arc<LogFile>>,
    /// Names that did not match `file_regex` (or failed the sandbox), for `doctor`.
    pub unmatched: Vec<String>,
}

struct Cached<T> {
    dir_mtime: Option<SystemTime>,
    at: Instant,
    value: T,
}

impl<T: Clone> Cached<T> {
    fn fresh(&self, dir_mtime: Option<SystemTime>) -> Option<T> {
        (self.dir_mtime == dir_mtime && dir_mtime.is_some() && self.at.elapsed() < CACHE_TTL)
            .then(|| self.value.clone())
    }
}

pub struct Catalog {
    settings: Arc<Settings>,
    root_canon: PathBuf,
    services: Mutex<Option<Cached<Arc<Vec<ServiceEntry>>>>>,
    files: Mutex<HashMap<String, Cached<Arc<ServiceFiles>>>>,
    /// Single-flight: concurrent cache misses wait for one scan instead of each scanning.
    services_scan: Mutex<()>,
    file_scans: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

fn dir_mtime(p: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

impl Catalog {
    pub fn new(settings: Arc<Settings>) -> std::io::Result<Self> {
        let root_canon = std::fs::canonicalize(&settings.root).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("layout.root {}: {e}", settings.root.display()),
            )
        })?;
        Ok(Self {
            settings,
            root_canon,
            services: Mutex::new(None),
            files: Mutex::new(HashMap::new()),
            services_scan: Mutex::new(()),
            file_scans: Mutex::new(HashMap::new()),
        })
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root_canon
    }

    fn service_dir(&self, service: &str) -> PathBuf {
        let mut p = self.root_canon.join(service);
        for c in &self.settings.service_subpath {
            p.push(c);
        }
        p
    }

    /// Lists service dirs under the root (cached ~30s, invalidated when the root's mtime changes).
    pub fn list_services(&self) -> ToolResult<Arc<Vec<ServiceEntry>>> {
        let mtime = dir_mtime(&self.root_canon);
        if let Some(c) = self.services.lock().unwrap().as_ref()
            && let Some(v) = c.fresh(mtime)
        {
            return Ok(v);
        }
        let _scan = self.services_scan.lock().unwrap();
        // Another caller may have finished the scan while we waited.
        if let Some(c) = self.services.lock().unwrap().as_ref()
            && let Some(v) = c.fresh(mtime)
        {
            return Ok(v);
        }
        let rd = std::fs::read_dir(&self.root_canon)
            .map_err(|e| ToolError::Internal(format!("cannot read log root: {e}")))?;
        let mut out = Vec::new();
        for entry in rd.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !is_safe_component(&name) || !self.settings.service_name_re.is_match(&name) {
                continue;
            }
            let path = self.root_canon.join(&name);
            let is_dir = match entry.file_type() {
                Ok(ft) if ft.is_dir() => true,
                Ok(ft) if ft.is_symlink() => {
                    confine(&self.root_canon, &path).is_some_and(|p| p.is_dir())
                }
                _ => false,
            };
            if !is_dir {
                continue;
            }
            let readable = std::fs::read_dir(self.service_dir(&name)).is_ok();
            out.push(ServiceEntry {
                description: self.settings.service_descriptions.get(&name).cloned(),
                name,
                readable,
            });
        }
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        let out = Arc::new(out);
        *self.services.lock().unwrap() = Some(Cached {
            dir_mtime: mtime,
            at: Instant::now(),
            value: out.clone(),
        });
        Ok(out)
    }

    /// Validates a caller-supplied service name against the regex and the listing.
    pub fn resolve_service(&self, name: &str) -> ToolResult<String> {
        let name = name.trim();
        if !is_safe_component(name) || !self.settings.service_name_re.is_match(name) {
            return Err(ToolError::InvalidArgument(format!(
                "service name '{name}' is not valid"
            )));
        }
        let list = self.list_services()?;
        if let Some(e) = list.iter().find(|e| e.name == name) {
            if !e.readable {
                return Err(ToolError::ServiceUnreadable(name.to_string()));
            }
            return Ok(e.name.clone());
        }
        Err(ToolError::UnknownService {
            name: name.to_string(),
            suggestion: suggest(name, list.iter().map(|e| e.name.as_str())),
        })
    }

    /// Parsed files of a service (cached ~30s, invalidated when the dir's mtime changes).
    pub fn files(&self, service: &str) -> ToolResult<Arc<ServiceFiles>> {
        let service = self.resolve_service(service)?;
        let dir = self.service_dir(&service);
        let mtime = dir_mtime(&dir);
        if let Some(c) = self.files.lock().unwrap().get(&service)
            && let Some(v) = c.fresh(mtime)
        {
            return Ok(v);
        }
        let lock = self
            .file_scans
            .lock()
            .unwrap()
            .entry(service.clone())
            .or_default()
            .clone();
        let _scan = lock.lock().unwrap();
        if let Some(c) = self.files.lock().unwrap().get(&service)
            && let Some(v) = c.fresh(mtime)
        {
            return Ok(v);
        }
        let sf = Arc::new(self.scan_service(&service, &dir)?);
        self.files.lock().unwrap().insert(
            service,
            Cached {
                dir_mtime: mtime,
                at: Instant::now(),
                value: sf.clone(),
            },
        );
        Ok(sf)
    }

    pub fn resolve_file(&self, service: &str, file: &str) -> ToolResult<Arc<LogFile>> {
        let sf = self.files(service)?;
        sf.files
            .iter()
            .find(|f| f.name == file)
            .cloned()
            .ok_or_else(|| ToolError::UnknownFile {
                service: sf.service.clone(),
                file: file.to_string(),
            })
    }

    fn scan_service(&self, service: &str, dir: &std::path::Path) -> ToolResult<ServiceFiles> {
        let rd =
            std::fs::read_dir(dir).map_err(|_| ToolError::ServiceUnreadable(service.into()))?;
        let s = &self.settings;
        let mut parsed: Vec<LogFile> = Vec::new();
        let mut unmatched = Vec::new();

        for entry in rd.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !is_safe_component(&name) {
                continue;
            }
            let path = dir.join(&name);
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let real = if ft.is_file() {
                path.clone()
            } else if ft.is_symlink() {
                match confine(&self.root_canon, &path) {
                    Some(p) if p.is_file() => p,
                    _ => {
                        unmatched.push(name);
                        continue;
                    }
                }
            } else {
                continue;
            };
            let Some(caps) = s.file_re.captures(&name) else {
                unmatched.push(name);
                continue;
            };
            let Some(host) = caps.name("host").map(|m| m.as_str().to_string()) else {
                unmatched.push(name);
                continue;
            };
            let Ok(meta) = std::fs::metadata(&real) else {
                continue;
            };
            let mtime: Ts = meta
                .modified()
                .map(DateTime::<Utc>::from)
                .unwrap_or_else(|_| Utc::now());

            let suffix_at = match caps.name("Y") {
                Some(_) => {
                    let n = |g: &str| caps.name(g).and_then(|m| m.as_str().parse::<u32>().ok());
                    let date = caps
                        .name("Y")
                        .and_then(|y| y.as_str().parse::<i32>().ok())
                        .and_then(|y| NaiveDate::from_ymd_opt(y, n("m")?, n("d")?));
                    let naive = date.and_then(|d| d.and_hms_opt(n("H")?, n("M").unwrap_or(0), 0));
                    match naive.and_then(|nv| local_to_utc(nv, &s.tz).ok()) {
                        Some(t) => Some(t),
                        None => {
                            unmatched.push(name);
                            continue;
                        }
                    }
                }
                None => None,
            };

            let ext = caps.name("ext").map(|m| m.as_str()).unwrap_or("");
            let compression = if ext.ends_with("gz") || (ext.is_empty() && name.ends_with(".gz")) {
                Compression::Gzip
            } else if ext.ends_with("zst") || (ext.is_empty() && name.ends_with(".zst")) {
                Compression::Zstd
            } else {
                Compression::None
            };

            parsed.push(LogFile {
                service: service.to_string(),
                name,
                path: real,
                host,
                live: suffix_at.is_none(),
                suffix_at,
                bucket: None,
                coverage: Interval::all(),
                compression,
                size: meta.len(),
                mtime,
            });
        }

        // While a rotated file is being compressed both `x.log.T` and `x.log.T.gz` exist; the
        // compressed one may be partial, so keep the plain one.
        let mut plain_rotated: std::collections::HashSet<(String, Ts)> = Default::default();
        for f in &parsed {
            if let (Some(t), Compression::None) = (f.suffix_at, f.compression) {
                plain_rotated.insert((f.host.clone(), t));
            }
        }
        parsed.retain(|f| match f.suffix_at {
            Some(t) if f.compression != Compression::None => {
                !plain_rotated.contains(&(f.host.clone(), t))
            }
            _ => true,
        });

        assign_coverage(&mut parsed, s);
        parsed.sort_by(|a, b| a.order_key().cmp(&b.order_key()).then(a.name.cmp(&b.name)));
        unmatched.sort();

        Ok(ServiceFiles {
            service: service.to_string(),
            files: parsed.into_iter().map(Arc::new).collect(),
            unmatched,
        })
    }
}

/// Computes nominal buckets and coverage intervals for rotated files, and coverage for live files
/// (from the newest rotation of the same host onwards).
pub fn assign_coverage(files: &mut [LogFile], s: &Settings) {
    let b = s.bucket;
    let adjacent = s.raw.rotation.include_adjacent_bucket;
    let marks = s.raw.rotation.suffix_marks;
    let mut newest_end: HashMap<String, Ts> = HashMap::new();

    for f in files.iter_mut() {
        let Some(t) = f.suffix_at else { continue };
        let nominal = match marks {
            SuffixMarks::End => Interval::new(t - b, t),
            SuffixMarks::Start => Interval::new(t, t + b),
        };
        let mut cov = nominal;
        if adjacent {
            cov = Interval::new(nominal.from - b, nominal.to + b);
        } else if marks == SuffixMarks::End {
            // Rotation can run late; the file then holds lines up to when it was rotated, which
            // its mtime approximates. Cap the extension at one bucket.
            let late = f.mtime.min(nominal.to + b);
            if late > cov.to {
                cov.to = late;
            }
        }
        f.bucket = Some(nominal);
        f.coverage = cov;
        let e = newest_end.entry(f.host.clone()).or_insert(nominal.to);
        if nominal.to > *e {
            *e = nominal.to;
        }
    }

    for f in files.iter_mut().filter(|f| f.live) {
        let from = match newest_end.get(&f.host) {
            Some(&end) if adjacent => end - b,
            Some(&end) => end,
            None => DateTime::<Utc>::MIN_UTC,
        };
        f.coverage = Interval::new(from, DateTime::<Utc>::MAX_UTC);
    }
}

/// Closest name by case-insensitive match, then by edit distance.
pub fn suggest<'a>(
    name: &str,
    candidates: impl Iterator<Item = &'a str> + Clone,
) -> Option<String> {
    let lower = name.to_lowercase();
    if let Some(c) = candidates.clone().find(|c| c.to_lowercase() == lower) {
        return Some(c.to_string());
    }
    let max = (name.len() / 3).max(2);
    candidates
        .map(|c| (strsim::levenshtein(&lower, &c.to_lowercase()), c))
        .filter(|(d, _)| *d <= max)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::sample_toml;

    fn settings(root: &std::path::Path, extra: &str) -> Arc<Settings> {
        let mut t = sample_toml(root.to_str().unwrap());
        t = t.replace("include_adjacent_bucket = false", extra);
        Arc::new(Settings::from_toml(&t).unwrap())
    }

    #[test]
    fn scans_and_parses() {
        let dir = tempfile::tempdir().unwrap();
        let svc = dir.path().join("orders");
        std::fs::create_dir(&svc).unwrap();
        for n in [
            "web-1.log",
            "web-1.log.2026-06-02-10-00.gz",
            "web-1.log.2026-06-02-11-00",
            "web-1.log.2026-06-02-11-00.gz", // partial compression; plain wins
            "web-2.log",
            "junk.txt",
        ] {
            std::fs::write(svc.join(n), b"x\n").unwrap();
        }
        std::fs::create_dir(dir.path().join("Billing")).unwrap();
        let cat = Catalog::new(settings(dir.path(), "include_adjacent_bucket = false")).unwrap();

        let svcs = cat.list_services().unwrap();
        assert_eq!(
            svcs.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["Billing", "orders"]
        );
        assert_eq!(svcs[1].description.as_deref(), Some("Order API"));

        let sf = cat.files("orders").unwrap();
        let names: Vec<_> = sf.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "web-1.log.2026-06-02-10-00.gz",
                "web-1.log.2026-06-02-11-00",
                "web-1.log",
                "web-2.log"
            ]
        );
        assert_eq!(sf.unmatched, ["junk.txt"]);
        let r = &sf.files[0];
        assert_eq!(r.compression, Compression::Gzip);
        assert_eq!(
            r.bucket.unwrap().from.to_rfc3339(),
            "2026-06-02T09:00:00+00:00"
        );
        let live1 = sf.files.iter().find(|f| f.name == "web-1.log").unwrap();
        assert_eq!(
            live1.coverage.from.to_rfc3339(),
            "2026-06-02T11:00:00+00:00"
        );
        let live2 = sf.files.iter().find(|f| f.name == "web-2.log").unwrap();
        assert_eq!(live2.coverage.from, DateTime::<Utc>::MIN_UTC);
    }

    #[test]
    fn adjacent_widens_coverage() {
        let dir = tempfile::tempdir().unwrap();
        let svc = dir.path().join("orders");
        std::fs::create_dir(&svc).unwrap();
        std::fs::write(svc.join("a.log.2026-06-02-10-00.gz"), b"").unwrap();
        std::fs::write(svc.join("a.log"), b"").unwrap();
        let cat = Catalog::new(settings(dir.path(), "include_adjacent_bucket = true")).unwrap();
        let sf = cat.files("orders").unwrap();
        let r = &sf.files[0];
        assert_eq!(r.coverage.from.to_rfc3339(), "2026-06-02T08:00:00+00:00");
        assert_eq!(r.coverage.to.to_rfc3339(), "2026-06-02T11:00:00+00:00");
        assert_eq!(
            sf.files[1].coverage.from.to_rfc3339(),
            "2026-06-02T09:00:00+00:00"
        );
    }

    #[test]
    fn service_resolution() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("orders")).unwrap();
        let cat = Catalog::new(settings(dir.path(), "include_adjacent_bucket = false")).unwrap();
        assert!(cat.resolve_service("orders").is_ok());
        match cat.resolve_service("ordres") {
            Err(ToolError::UnknownService { suggestion, .. }) => {
                assert_eq!(suggestion.as_deref(), Some("orders"))
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            cat.resolve_service(".."),
            Err(ToolError::InvalidArgument(_))
        ));
        assert!(matches!(
            cat.resolve_service("a/b"),
            Err(ToolError::InvalidArgument(_))
        ));
        assert!(matches!(
            cat.resolve_file("orders", "../../etc/passwd"),
            Err(ToolError::UnknownFile { .. })
        ));
    }
}
