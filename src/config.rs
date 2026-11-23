//! Config schema (TOML), defaults, validation, and the compiled runtime form ([`Settings`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Duration;
use chrono_tz::Tz;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::parse::id_decode::IdDecoder;
use crate::parse::line::LineParser;
use crate::parse::time::parse_duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Name of this box, echoed in every result (e.g. "eu1").
    pub box_name: String,
    /// IANA timezone used for naive times, filename suffixes and line timestamps without offset.
    #[serde(default = "d_timezone")]
    pub timezone: String,
    #[serde(default)]
    pub server: ServerSection,
    pub layout: LayoutSection,
    #[serde(default)]
    pub rotation: RotationSection,
    #[serde(default)]
    pub line: Option<LineSection>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub id_decoders: Vec<IdDecoderSection>,
    #[serde(default)]
    pub services: Vec<ServiceDescription>,
    #[serde(default)]
    pub locate: LocateSection,
    #[serde(default)]
    pub redaction: Vec<RedactionRule>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Https,
    Stdio,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    #[serde(default = "d_transport")]
    pub transport: Transport,
    #[serde(default = "d_bind")]
    pub bind: String,
    /// Allowed browser origins (Origin header). Empty = requests with an Origin header from any
    /// origin are accepted; requests without Origin (CLI clients) always pass.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Allowed Host header values (DNS-rebinding protection). Empty = any host.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// File with lines `<name>:<sha256-hex>`; required for https.
    #[serde(default = "d_tokens_file")]
    pub tokens_file: PathBuf,
    /// Requests per minute per token.
    #[serde(default = "d_rate_limit")]
    pub rate_limit_per_minute: u32,
    #[serde(default)]
    pub tls: Option<TlsSection>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            transport: d_transport(),
            bind: d_bind(),
            allowed_origins: vec![],
            allowed_hosts: vec![],
            tokens_file: d_tokens_file(),
            rate_limit_per_minute: d_rate_limit(),
            tls: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum TlsMinVersion {
    #[serde(rename = "1.2")]
    V12,
    #[serde(rename = "1.3")]
    V13,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsReload {
    /// Watch cert/key files and also reload on SIGHUP.
    Watch,
    /// Reload on SIGHUP only.
    Sighup,
    /// Never reload.
    Off,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub cert: PathBuf,
    pub key: PathBuf,
    #[serde(default = "d_tls_min")]
    pub min_version: TlsMinVersion,
    #[serde(default = "d_tls_reload")]
    pub reload: TlsReload,
    #[serde(default)]
    pub client_ca: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutSection {
    pub root: PathBuf,
    /// Template for a service's directory. Must be `{root}/{service}` optionally followed by fixed
    /// sub-path components (e.g. `{root}/{service}/logs`).
    #[serde(default = "d_service_dir")]
    pub service_dir: String,
    #[serde(default = "d_service_name_regex")]
    pub service_name_regex: String,
    /// Named groups: `host` (required); `Y m d H [M]` for rotated files; `ext` for compression.
    pub file_regex: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SuffixMarks {
    /// Suffix is the rotation time: the file covers the bucket *before* it.
    End,
    /// Suffix is the bucket start: the file covers the bucket *after* it.
    Start,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotationSection {
    #[serde(default = "d_bucket")]
    pub bucket: String,
    #[serde(default = "d_suffix_marks")]
    pub suffix_marks: SuffixMarks,
    /// Widen every rotated file's coverage by one bucket on the uncertain side.
    #[serde(default = "d_true")]
    pub include_adjacent_bucket: bool,
    #[serde(default = "d_retention")]
    pub retention_days: u32,
    /// Live files are truncated in place (logrotate copytruncate): disables mmap, tolerates shrink.
    #[serde(default = "d_true")]
    pub live_file_copytruncate: bool,
}

impl Default for RotationSection {
    fn default() -> Self {
        Self {
            bucket: d_bucket(),
            suffix_marks: d_suffix_marks(),
            include_adjacent_bucket: true,
            retention_days: d_retention(),
            live_file_copytruncate: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineSection {
    /// Must contain a named group `ts`.
    pub timestamp_regex: String,
    /// `rfc3339` | `rfc3164` | `epoch` | `epoch_ms` | a strftime pattern.
    #[serde(default = "d_ts_format")]
    pub timestamp_format: String,
    /// Optional named groups: level, thread, logger, trace_id, msg (any names are returned).
    #[serde(default)]
    pub fields_regex: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_range_hours: u32,
    pub max_range_hours_count: u32,
    pub max_lines_default: usize,
    pub max_lines_hard: usize,
    pub max_bytes: usize,
    pub max_line_bytes: usize,
    pub max_context: usize,
    pub max_scan_bytes: u64,
    pub timeout_secs_default: u64,
    pub timeout_secs_max: u64,
    /// Files one request keeps in flight on the shared pool (its look-ahead).
    pub workers_per_request: usize,
    /// Threads in the shared search pool; size it to the CPU quota (CPUQuota=200% → 2).
    pub search_threads: usize,
    pub max_concurrent_requests: usize,
    pub regex_size_limit: usize,
    /// How long a request may wait for a free concurrency slot before failing with "busy".
    pub queue_wait_secs: u64,
    /// Max lines for tail_live.
    pub tail_max_lines: usize,
    /// Max bytes read backwards per live file in tail_live.
    pub tail_max_scan_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_range_hours: 24,
            max_range_hours_count: 168,
            max_lines_default: 200,
            max_lines_hard: 2000,
            max_bytes: 65_536,
            max_line_bytes: 4096,
            max_context: 20,
            max_scan_bytes: 20_000_000_000,
            timeout_secs_default: 60,
            timeout_secs_max: 180,
            workers_per_request: 3,
            search_threads: 2,
            max_concurrent_requests: 4,
            regex_size_limit: 10_485_760,
            queue_wait_secs: 10,
            tail_max_lines: 500,
            tail_max_scan_bytes: 268_435_456,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdDecoderSection {
    pub name: String,
    /// Named groups: Y (4-digit) or y (2-digit), m, d, and optionally H, M, S.
    pub regex: String,
    #[serde(default = "d_id_window")]
    pub window: String,
    #[serde(default = "d_id_lookback")]
    pub lookback: String,
    #[serde(default)]
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDescription {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LocateSection {
    pub window_default: String,
    pub max_scan_bytes: u64,
}

impl Default for LocateSection {
    fn default() -> Self {
        Self {
            window_default: "1h".into(),
            max_scan_bytes: 5_000_000_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionRule {
    pub name: String,
    pub regex: String,
    pub replace: String,
}

fn d_timezone() -> String {
    "UTC".into()
}
fn d_transport() -> Transport {
    Transport::Https
}
fn d_bind() -> String {
    "0.0.0.0:8765".into()
}
fn d_tokens_file() -> PathBuf {
    PathBuf::from("/etc/grepcp/tokens")
}
fn d_rate_limit() -> u32 {
    120
}
fn d_tls_min() -> TlsMinVersion {
    TlsMinVersion::V12
}
fn d_tls_reload() -> TlsReload {
    TlsReload::Watch
}
fn d_service_dir() -> String {
    "{root}/{service}".into()
}
fn d_service_name_regex() -> String {
    "^[A-Za-z0-9._-]+$".into()
}
fn d_bucket() -> String {
    "1h".into()
}
fn d_suffix_marks() -> SuffixMarks {
    SuffixMarks::End
}
fn d_true() -> bool {
    true
}
fn d_retention() -> u32 {
    7
}
fn d_ts_format() -> String {
    "rfc3339".into()
}
fn d_id_window() -> String {
    "1h".into()
}
fn d_id_lookback() -> String {
    "1m".into()
}

/// Compiled, validated runtime settings.
#[derive(Debug, Clone)]
pub struct Settings {
    pub raw: Config,
    pub tz: Tz,
    pub root: PathBuf,
    /// Sub-path components after `{service}` in the service_dir template.
    pub service_subpath: Vec<String>,
    pub service_name_re: Regex,
    pub file_re: Regex,
    pub bucket: Duration,
    pub retention: Duration,
    pub line: Option<LineParser>,
    pub id_decoders: Vec<IdDecoder>,
    pub redactions: Vec<(String, Regex, String)>,
    pub locate_window: Duration,
    pub service_descriptions: HashMap<String, String>,
}

impl Settings {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        Self::from_toml(&text).map_err(|e| anyhow::anyhow!("config {}: {e}", path.display()))
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        let raw: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        Self::compile(raw)
    }

    pub fn compile(raw: Config) -> Result<Self, String> {
        let tz: Tz = raw
            .timezone
            .parse()
            .map_err(|_| format!("timezone '{}' is not a valid IANA name", raw.timezone))?;

        if raw.box_name.trim().is_empty() {
            return Err("box_name must not be empty".into());
        }

        let root = raw.layout.root.clone();
        if !root.is_absolute() {
            return Err("layout.root must be an absolute path".into());
        }

        let service_subpath = parse_service_dir(&raw.layout.service_dir)?;

        let service_name_re = Regex::new(&raw.layout.service_name_regex)
            .map_err(|e| format!("layout.service_name_regex: {e}"))?;
        let file_re =
            Regex::new(&raw.layout.file_regex).map_err(|e| format!("layout.file_regex: {e}"))?;
        let groups: Vec<&str> = file_re.capture_names().flatten().collect();
        if !groups.contains(&"host") {
            return Err("layout.file_regex must have a named group 'host'".into());
        }
        let date_groups = ["Y", "m", "d", "H"];
        let n_date = date_groups.iter().filter(|g| groups.contains(g)).count();
        if n_date != 0 && n_date != date_groups.len() {
            return Err(
                "layout.file_regex: rotated-file groups must include all of Y, m, d, H".into(),
            );
        }

        let bucket =
            parse_duration(&raw.rotation.bucket).map_err(|e| format!("rotation.bucket: {e}"))?;
        if raw.rotation.retention_days == 0 {
            return Err("rotation.retention_days must be > 0".into());
        }
        let retention = Duration::days(raw.rotation.retention_days as i64);

        let line = match &raw.line {
            Some(l) => Some(LineParser::new(
                &l.timestamp_regex,
                &l.timestamp_format,
                Some(&l.fields_regex),
                tz,
            )?),
            None => None,
        };

        let mut id_decoders = Vec::new();
        for d in &raw.id_decoders {
            let dec = IdDecoder {
                name: d.name.clone(),
                re: Regex::new(&d.regex).map_err(|e| format!("id_decoders '{}': {e}", d.name))?,
                window: parse_duration(&d.window)
                    .map_err(|e| format!("id_decoders '{}'.window: {e}", d.name))?,
                lookback: parse_duration(&d.lookback)
                    .map_err(|e| format!("id_decoders '{}'.lookback: {e}", d.name))?,
                services: d.services.clone(),
            };
            dec.validate()?;
            id_decoders.push(dec);
        }

        let mut redactions = Vec::new();
        for r in &raw.redaction {
            let re = Regex::new(&r.regex).map_err(|e| format!("redaction '{}': {e}", r.name))?;
            redactions.push((r.name.clone(), re, r.replace.clone()));
        }

        let locate_window = parse_duration(&raw.locate.window_default)
            .map_err(|e| format!("locate.window_default: {e}"))?;

        let l = &raw.limits;
        if l.max_lines_default == 0 || l.max_lines_default > l.max_lines_hard {
            return Err("limits: need 0 < max_lines_default <= max_lines_hard".into());
        }
        if l.workers_per_request == 0 || l.max_concurrent_requests == 0 || l.search_threads == 0 {
            return Err(
                "limits: workers_per_request, search_threads and max_concurrent_requests must be > 0"
                    .into(),
            );
        }
        if l.timeout_secs_default == 0 || l.timeout_secs_default > l.timeout_secs_max {
            return Err("limits: need 0 < timeout_secs_default <= timeout_secs_max".into());
        }
        if l.max_line_bytes < 64 || l.max_bytes < l.max_line_bytes {
            return Err("limits: need 64 <= max_line_bytes <= max_bytes".into());
        }

        if raw.server.transport == Transport::Https && raw.server.tls.is_none() {
            return Err("server.transport = \"https\" requires a [server.tls] section".into());
        }

        let service_descriptions = raw
            .services
            .iter()
            .map(|s| (s.name.clone(), s.description.clone()))
            .collect();

        Ok(Self {
            tz,
            root,
            service_subpath,
            service_name_re,
            file_re,
            bucket,
            retention,
            line,
            id_decoders,
            redactions,
            locate_window,
            service_descriptions,
            raw,
        })
    }

    pub fn limits(&self) -> &Limits {
        &self.raw.limits
    }

    pub fn box_name(&self) -> &str {
        &self.raw.box_name
    }
}

/// Validates the `service_dir` template and returns the fixed components after `{service}`.
fn parse_service_dir(tpl: &str) -> Result<Vec<String>, String> {
    let rest = tpl
        .strip_prefix("{root}/{service}")
        .ok_or("layout.service_dir must start with '{root}/{service}'")?;
    let mut out = Vec::new();
    for comp in rest.split('/').filter(|c| !c.is_empty()) {
        if comp == "." || comp == ".." || comp.contains('{') || comp.contains('}') {
            return Err(format!("layout.service_dir: invalid component '{comp}'"));
        }
        out.push(comp.to_string());
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_toml(root: &str) -> String {
        format!(
            r#"
box_name = "test"
timezone = "UTC"

[server]
transport = "stdio"

[layout]
root = "{root}"
file_regex = '^(?P<host>.+?)\.log(?:\.(?P<Y>\d{{4}})-(?P<m>\d{{2}})-(?P<d>\d{{2}})-(?P<H>\d{{2}})-(?P<M>\d{{2}})(?P<ext>\.gz|\.zst)?)?$'

[rotation]
include_adjacent_bucket = false

[line]
timestamp_regex = '^(?P<ts>\S+)'

[[id_decoders]]
name = "order"
regex = '^TXN-(?P<Y>\d{{4}})(?P<m>\d{{2}})(?P<d>\d{{2}})-(?P<H>\d{{2}})(?P<M>\d{{2}})'
services = ["orders"]

[[services]]
name = "orders"
description = "Order API"

[[redaction]]
name = "bearer"
regex = '(?i)bearer\s+[a-z0-9._-]+'
replace = "bearer <redacted>"
"#
        )
    }

    #[test]
    fn parses_sample() {
        let s = Settings::from_toml(&sample_toml("/var/log/remote")).unwrap();
        assert_eq!(s.bucket, Duration::hours(1));
        assert!(s.line.is_some());
        assert_eq!(s.id_decoders.len(), 1);
        assert_eq!(s.service_descriptions["orders"], "Order API");
    }

    #[test]
    fn example_config_parses() {
        let text = include_str!("../config.example.toml");
        Settings::from_toml(text).unwrap();
    }

    #[test]
    fn rejects_bad_layout() {
        let bad = sample_toml("relative/path");
        assert!(Settings::from_toml(&bad).unwrap_err().contains("absolute"));
        assert!(parse_service_dir("{service}/x").is_err());
        assert!(parse_service_dir("{root}/{service}/../x").is_err());
        assert_eq!(
            parse_service_dir("{root}/{service}/logs").unwrap(),
            vec!["logs"]
        );
    }

    #[test]
    fn https_requires_tls() {
        let t = sample_toml("/x").replace("transport = \"stdio\"", "transport = \"https\"");
        assert!(Settings::from_toml(&t).unwrap_err().contains("server.tls"));
    }
}
