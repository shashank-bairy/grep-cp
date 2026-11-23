//! Optional per-line parsing: timestamp extraction (for in-file time filtering, sorting and
//! minute buckets) and named fields (level, thread, logger, trace_id, msg).

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use regex::bytes::Regex as BytesRegex;

use crate::parse::time::{Ts, local_to_utc};

/// Only the first bytes of a line are inspected for the timestamp.
const TS_SCAN_BYTES: usize = 512;

#[derive(Clone, Debug)]
pub enum TsFormat {
    /// RFC3339 / ISO-8601, lenient: `T` or space separator, offset optional (missing → box tz).
    Rfc3339,
    /// Classic syslog `Mmm dd HH:MM:SS` (no year; inferred from the current date).
    Rfc3164,
    /// Unix epoch seconds (optionally fractional).
    Epoch,
    /// Unix epoch milliseconds.
    EpochMillis,
    /// chrono strftime pattern.
    Strftime {
        fmt: String,
        has_offset: bool,
        has_year: bool,
    },
}

impl TsFormat {
    pub fn parse(s: &str) -> Self {
        match s.trim() {
            "rfc3339" | "iso8601" => TsFormat::Rfc3339,
            "rfc3164" | "syslog" => TsFormat::Rfc3164,
            "epoch" => TsFormat::Epoch,
            "epoch_ms" => TsFormat::EpochMillis,
            other => TsFormat::Strftime {
                fmt: other.to_string(),
                has_offset: other.contains("%z") || other.contains("%:z") || other.contains("%#z"),
                has_year: ["%Y", "%y", "%F", "%D", "%s", "%G", "%c", "%+"]
                    .iter()
                    .any(|p| other.contains(p)),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct LineParser {
    ts_re: BytesRegex,
    fmt: TsFormat,
    fields_re: Option<BytesRegex>,
    tz: Tz,
}

impl LineParser {
    pub fn new(
        ts_regex: &str,
        fmt: &str,
        fields_regex: Option<&str>,
        tz: Tz,
    ) -> Result<Self, String> {
        let ts_re = BytesRegex::new(ts_regex).map_err(|e| format!("line.timestamp_regex: {e}"))?;
        if !ts_re.capture_names().any(|n| n == Some("ts")) {
            return Err("line.timestamp_regex must have a named group 'ts'".into());
        }
        let fields_re = match fields_regex {
            Some(r) if !r.trim().is_empty() => {
                Some(BytesRegex::new(r).map_err(|e| format!("line.fields_regex: {e}"))?)
            }
            _ => None,
        };
        let fmt = TsFormat::parse(fmt);
        if let TsFormat::Strftime { fmt: f, .. } = &fmt {
            // Reject obviously broken patterns early.
            if !f.contains('%') {
                return Err(format!(
                    "line.timestamp_format '{f}' is neither rfc3339|rfc3164|epoch|epoch_ms nor a strftime pattern"
                ));
            }
        }
        Ok(Self {
            ts_re,
            fmt,
            fields_re,
            tz,
        })
    }

    /// Extracts the line timestamp. `now` is used to infer the year for formats without one.
    pub fn parse_ts(&self, line: &[u8], now: Ts) -> Option<Ts> {
        let head = &line[..line.len().min(TS_SCAN_BYTES)];
        let caps = self.ts_re.captures(head)?;
        let raw = caps.name("ts")?.as_bytes();
        let s = std::str::from_utf8(raw).ok()?.trim();
        self.parse_ts_str(s, now)
    }

    pub fn parse_ts_str(&self, s: &str, now: Ts) -> Option<Ts> {
        match &self.fmt {
            TsFormat::Rfc3339 => {
                if let Ok(t) = DateTime::parse_from_rfc3339(s) {
                    return Some(t.with_timezone(&Utc));
                }
                let normalized = s.replacen(' ', "T", 1);
                if let Ok(t) = DateTime::parse_from_rfc3339(&normalized) {
                    return Some(t.with_timezone(&Utc));
                }
                for f in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%dT%H:%M:%S%.f%:z"] {
                    if let Ok(t) = DateTime::parse_from_str(&normalized, f) {
                        return Some(t.with_timezone(&Utc));
                    }
                }
                // Comma as fractional separator (logback default: 2026-06-02 10:26:00,123).
                let normalized = normalized.replacen(',', ".", 1);
                NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%dT%H:%M:%S%.f")
                    .ok()
                    .and_then(|n| local_to_utc(n, &self.tz).ok())
            }
            TsFormat::Rfc3164 => self.with_inferred_year(s, "%b %e %H:%M:%S", now),
            TsFormat::Epoch => {
                let v: f64 = s.parse().ok()?;
                let secs = v.trunc() as i64;
                let nanos = ((v.fract()) * 1e9) as u32;
                Utc.timestamp_opt(secs, nanos).single()
            }
            TsFormat::EpochMillis => {
                let v: i64 = s.parse().ok()?;
                Utc.timestamp_millis_opt(v).single()
            }
            TsFormat::Strftime {
                fmt,
                has_offset,
                has_year,
            } => {
                if *has_offset {
                    DateTime::parse_from_str(s, fmt)
                        .ok()
                        .map(|t| t.with_timezone(&Utc))
                } else if *has_year {
                    NaiveDateTime::parse_from_str(s, fmt)
                        .ok()
                        .and_then(|n| local_to_utc(n, &self.tz).ok())
                } else {
                    self.with_inferred_year(s, fmt, now)
                }
            }
        }
    }

    /// Parses a year-less timestamp. Uses the current year in the box tz, falling back to the
    /// previous year when the result would be more than a day in the future (Dec → Jan rollover).
    fn with_inferred_year(&self, s: &str, fmt: &str, now: Ts) -> Option<Ts> {
        let year = now.with_timezone(&self.tz).year();
        let squeezed = squeeze_spaces(s);
        let full_fmt = format!("%Y {fmt}");
        let parse = |y: i32| {
            NaiveDateTime::parse_from_str(&format!("{y} {squeezed}"), &full_fmt)
                .ok()
                .and_then(|n| local_to_utc(n, &self.tz).ok())
        };
        let t = parse(year)?;
        if t > now + chrono::Duration::days(1) {
            parse(year - 1)
        } else {
            Some(t)
        }
    }

    /// Extracts named fields, if `fields_regex` is configured and matches.
    pub fn fields(&self, line: &[u8]) -> Option<BTreeMap<String, String>> {
        let re = self.fields_re.as_ref()?;
        let caps = re.captures(line)?;
        let mut out = BTreeMap::new();
        for name in re.capture_names().flatten() {
            if let Some(m) = caps.name(name) {
                out.insert(
                    name.to_string(),
                    String::from_utf8_lossy(m.as_bytes()).trim().to_string(),
                );
            }
        }
        if out.is_empty() { None } else { Some(out) }
    }

    pub fn has_fields(&self) -> bool {
        self.fields_re.is_some()
    }
}

/// `%e` in chrono accepts a space-padded day, but double spaces in syslog (`Jun  2`) must collapse
/// to match a single-space pattern.
fn squeeze_spaces(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c == ' ' {
            if !prev_space {
                out.push(c);
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::time::parse_instant;

    fn now() -> Ts {
        parse_instant("2026-06-02T12:00:00Z", &chrono_tz::UTC).unwrap()
    }

    #[test]
    fn rfc3339_variants() {
        let p = LineParser::new(r"^(?P<ts>\S+)", "rfc3339", None, chrono_tz::UTC).unwrap();
        let t = p
            .parse_ts(b"2026-06-02T10:26:00.123+02:00 host app: hi", now())
            .unwrap();
        assert_eq!(t.to_rfc3339(), "2026-06-02T08:26:00.123+00:00");

        let p = LineParser::new(
            r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]\d+)",
            "rfc3339",
            None,
            chrono_tz::UTC,
        )
        .unwrap();
        let t = p
            .parse_ts(b"2026-06-02 10:26:00,123 INFO x", now())
            .unwrap();
        assert_eq!(t.to_rfc3339(), "2026-06-02T10:26:00.123+00:00");
    }

    #[test]
    fn rfc3164_year_rollover() {
        let p = LineParser::new(
            r"^(?P<ts>\w{3} +\d+ \d{2}:\d{2}:\d{2})",
            "rfc3164",
            None,
            chrono_tz::UTC,
        )
        .unwrap();
        let t = p.parse_ts(b"Jun  2 10:26:00 host app: hi", now()).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-06-02T10:26:00+00:00");
        let jan = parse_instant("2027-01-01T00:10:00Z", &chrono_tz::UTC).unwrap();
        let t = p.parse_ts(b"Dec 31 23:59:00 host app: hi", jan).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-12-31T23:59:00+00:00");
    }

    #[test]
    fn strftime_and_fields() {
        let p = LineParser::new(
            r"^\[(?P<ts>[^\]]+)\]",
            "%d/%b/%Y:%H:%M:%S %z",
            Some(r"\] (?P<level>[A-Z]+) (?P<msg>.*)$"),
            chrono_tz::UTC,
        )
        .unwrap();
        let line = b"[02/Jun/2026:10:26:00 +0000] WARN disk almost full";
        let t = p.parse_ts(line, now()).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-06-02T10:26:00+00:00");
        let f = p.fields(line).unwrap();
        assert_eq!(f["level"], "WARN");
        assert_eq!(f["msg"], "disk almost full");
    }

    #[test]
    fn requires_ts_group() {
        assert!(LineParser::new(r"^(\S+)", "rfc3339", None, chrono_tz::UTC).is_err());
    }
}
