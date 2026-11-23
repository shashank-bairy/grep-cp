//! Time windows: parsing user input (RFC3339, naive local times, relative durations) into UTC
//! half-open intervals, and interval arithmetic used by the planner and the line filter.

use chrono::{DateTime, Duration, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::Serialize;

pub type Ts = DateTime<Utc>;

/// Longest duration accepted anywhere (keeps all time arithmetic far from overflow).
pub const MAX_DURATION_DAYS: i64 = 400;

/// Half-open interval `[from, to)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Interval {
    pub from: Ts,
    pub to: Ts,
}

impl Interval {
    pub fn new(from: Ts, to: Ts) -> Self {
        Self { from, to }
    }

    /// Unbounded interval (used for live files with no rotation history).
    pub fn all() -> Self {
        Self {
            from: DateTime::<Utc>::MIN_UTC,
            to: DateTime::<Utc>::MAX_UTC,
        }
    }

    pub fn overlaps(&self, other: &Interval) -> bool {
        self.from < other.to && other.from < self.to
    }

    pub fn contains(&self, t: Ts) -> bool {
        self.from <= t && t < self.to
    }

    pub fn len(&self) -> Duration {
        self.to - self.from
    }

    pub fn is_empty(&self) -> bool {
        self.to <= self.from
    }
}

/// A search window: one or more sorted, non-overlapping intervals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    parts: Vec<Interval>,
}

impl Window {
    pub fn single(iv: Interval) -> Self {
        Self { parts: vec![iv] }
    }

    /// Builds a window from arbitrary intervals: drops empty ones, sorts and merges overlaps.
    pub fn from_parts(mut parts: Vec<Interval>) -> Option<Self> {
        parts.retain(|p| !p.is_empty());
        if parts.is_empty() {
            return None;
        }
        parts.sort_by_key(|p| p.from);
        let mut merged: Vec<Interval> = Vec::with_capacity(parts.len());
        for p in parts {
            match merged.last_mut() {
                Some(last) if p.from <= last.to => {
                    if p.to > last.to {
                        last.to = p.to;
                    }
                }
                _ => merged.push(p),
            }
        }
        Some(Self { parts: merged })
    }

    pub fn parts(&self) -> &[Interval] {
        &self.parts
    }

    pub fn span(&self) -> Interval {
        Interval::new(self.parts[0].from, self.parts[self.parts.len() - 1].to)
    }

    pub fn contains(&self, t: Ts) -> bool {
        self.parts.iter().any(|p| p.contains(t))
    }

    pub fn overlaps(&self, iv: &Interval) -> bool {
        self.parts.iter().any(|p| p.overlaps(iv))
    }

    pub fn total_len(&self) -> Duration {
        self.parts
            .iter()
            .map(|p| p.len())
            .fold(Duration::zero(), |a, b| a + b)
    }

    /// Restricts the window to `[from, ∞)`; returns `None` if nothing remains.
    pub fn clamp_from(&self, from: Ts) -> Option<Self> {
        let parts = self
            .parts
            .iter()
            .map(|p| Interval::new(p.from.max(from), p.to))
            .collect();
        Self::from_parts(parts)
    }
}

/// Parses durations like `90s`, `30m`, `1h`, `2d`, `1h30m`, `1w`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let mut total = Duration::zero();
    let mut num = String::new();
    let mut saw_unit = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        if num.is_empty() {
            return Err(format!(
                "invalid duration '{s}': expected a number before '{c}'"
            ));
        }
        let n: i64 = num
            .parse()
            .map_err(|_| format!("invalid duration '{s}': number too large"))?;
        num.clear();
        let part = match c {
            's' => Duration::try_seconds(n),
            'm' => Duration::try_minutes(n),
            'h' => Duration::try_hours(n),
            'd' => Duration::try_days(n),
            'w' => Duration::try_weeks(n),
            _ => {
                return Err(format!(
                    "invalid duration '{s}': unknown unit '{c}' (use s, m, h, d, w)"
                ));
            }
        }
        .ok_or_else(|| format!("invalid duration '{s}': out of range"))?;
        total = total
            .checked_add(&part)
            .filter(|t| *t <= Duration::days(MAX_DURATION_DAYS))
            .ok_or_else(|| {
                format!("invalid duration '{s}': longer than {MAX_DURATION_DAYS} days")
            })?;
        saw_unit = true;
    }
    if !num.is_empty() || !saw_unit {
        return Err(format!(
            "invalid duration '{s}': missing unit (e.g. 30m, 1h, 2d)"
        ));
    }
    if total <= Duration::zero() {
        return Err(format!("invalid duration '{s}': must be positive"));
    }
    Ok(total)
}

/// Converts a local wall-clock time in `tz` to UTC. Ambiguous times (DST fall-back) resolve to the
/// earlier instant; non-existent times (DST spring-forward gap) shift forward by an hour.
pub fn local_to_utc(naive: NaiveDateTime, tz: &Tz) -> Result<Ts, String> {
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(t) => Ok(t.with_timezone(&Utc)),
        LocalResult::Ambiguous(a, _) => Ok(a.with_timezone(&Utc)),
        LocalResult::None => match tz.from_local_datetime(&(naive + Duration::hours(1))) {
            LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => Ok(t.with_timezone(&Utc)),
            LocalResult::None => Err(format!("local time {naive} does not exist in {tz}")),
        },
    }
}

/// Parses an instant: RFC3339 (`2026-06-02T10:26:00Z`, `...+05:30`), or naive
/// `YYYY-MM-DD HH:MM[:SS]` / `YYYY-MM-DDTHH:MM[:SS]` / `YYYY-MM-DD` interpreted in `tz`.
pub fn parse_instant(s: &str, tz: &Tz) -> Result<Ts, String> {
    let s = s.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, fmt) {
            return local_to_utc(n, tz);
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return local_to_utc(d.and_time(NaiveTime::MIN), tz);
    }
    Err(format!(
        "invalid time '{s}': use RFC3339 (2026-06-02T10:00:00Z) or 'YYYY-MM-DD HH:MM' in the box timezone ({tz}). Dates are always YYYY-MM-DD"
    ))
}

/// Time selector as accepted by the tools. Exactly one style may be used:
/// `from`/`to`, `last`, or `date` (+ optional `hours`).
#[derive(Clone, Debug, Default)]
pub struct TimeSpec {
    pub from: Option<String>,
    pub to: Option<String>,
    pub last: Option<String>,
    pub date: Option<String>,
    pub hours: Option<Vec<u32>>,
}

impl TimeSpec {
    pub fn is_empty(&self) -> bool {
        self.from.is_none()
            && self.to.is_none()
            && self.last.is_none()
            && self.date.is_none()
            && self.hours.is_none()
    }
}

/// Resolves a [`TimeSpec`] into a [`Window`]. Returns `Ok(None)` if the spec is empty.
pub fn resolve(spec: &TimeSpec, tz: &Tz, now: Ts) -> Result<Option<Window>, String> {
    if spec.is_empty() {
        return Ok(None);
    }
    let styles = [
        spec.from.is_some() || spec.to.is_some(),
        spec.last.is_some(),
        spec.date.is_some() || spec.hours.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if styles > 1 {
        return Err("use only one of: from/to, last, or date (+hours)".into());
    }

    if let Some(last) = &spec.last {
        let d = parse_duration(last)?;
        // A small forward margin so lines written while the request runs are still included.
        return Ok(Some(Window::single(Interval::new(
            now - d,
            now + Duration::minutes(1),
        ))));
    }

    if spec.from.is_some() || spec.to.is_some() {
        let from = spec
            .from
            .as_deref()
            .ok_or("'to' given without 'from'")
            .map_err(String::from)?;
        let from = parse_instant(from, tz)?;
        let to = match &spec.to {
            Some(t) => parse_instant(t, tz)?,
            None => now + Duration::minutes(1),
        };
        if to <= from {
            return Err("'to' must be after 'from'".into());
        }
        return Ok(Some(Window::single(Interval::new(from, to))));
    }

    let date = spec
        .date
        .as_deref()
        .ok_or("'hours' given without 'date'")
        .map_err(String::from)?;
    let day = NaiveDate::parse_from_str(date.trim(), "%Y-%m-%d")
        .map_err(|_| format!("invalid date '{date}': dates are always YYYY-MM-DD"))?;
    let parts = match &spec.hours {
        None => {
            let from = local_to_utc(day.and_time(NaiveTime::MIN), tz)?;
            let next = day.succ_opt().ok_or("date out of range")?;
            let to = local_to_utc(next.and_time(NaiveTime::MIN), tz)?;
            vec![Interval::new(from, to)]
        }
        Some(hours) if hours.is_empty() => return Err("'hours' must not be empty".into()),
        Some(hours) => {
            let mut v = Vec::with_capacity(hours.len());
            for &h in hours {
                if h > 23 {
                    return Err(format!("invalid hour {h}: must be 0-23"));
                }
                let start = day.and_hms_opt(h, 0, 0).ok_or("invalid hour")?;
                let from = local_to_utc(start, tz)?;
                let to = local_to_utc(start + Duration::hours(1), tz)?;
                if to <= from {
                    return Err(format!(
                        "hour {h} does not exist on {date} in {tz} (DST clock change); pick another hour"
                    ));
                }
                v.push(Interval::new(from, to));
            }
            v
        }
    };
    Window::from_parts(parts)
        .map(Some)
        .ok_or_else(|| "empty time window".to_string())
}

/// Formats a UTC instant in the box timezone as RFC3339 with offset.
pub fn fmt_local(t: Ts, tz: &Tz) -> String {
    t.with_timezone(tz)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}

/// Formats a UTC instant as `YYYY-MM-DD HH:MM` in the box timezone.
pub fn fmt_minute(t: Ts, tz: &Tz) -> String {
    t.with_timezone(tz).format("%Y-%m-%d %H:%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tz() -> Tz {
        "Europe/Berlin".parse().unwrap()
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::minutes(90));
        assert_eq!(parse_duration("2d").unwrap(), Duration::days(2));
        assert!(parse_duration("30").is_err());
        assert!(parse_duration("m").is_err());
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("0m").is_err());
        assert!(parse_duration("100000000000d").is_err());
        assert!(parse_duration("9999999999999999999999h").is_err());
        assert!(parse_duration("401d").is_err());
        assert!(parse_duration("400d").is_ok());
    }

    #[test]
    fn instants() {
        let t = parse_instant("2026-06-02T10:00:00Z", &tz()).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-06-02T10:00:00+00:00");
        // Berlin is UTC+2 in June.
        let t = parse_instant("2026-06-02 10:00", &tz()).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-06-02T08:00:00+00:00");
        let t = parse_instant("2026-06-02", &tz()).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-06-01T22:00:00+00:00");
        assert!(parse_instant("02-06-2026", &tz()).is_err());
    }

    #[test]
    fn dst_gap_shifts_forward() {
        // 2026-03-29 02:30 does not exist in Berlin.
        let t = parse_instant("2026-03-29 02:30", &tz()).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-03-29T01:30:00+00:00");
    }

    #[test]
    fn resolve_styles() {
        let now = parse_instant("2026-06-02T12:00:00Z", &tz()).unwrap();
        let w = resolve(
            &TimeSpec {
                last: Some("1h".into()),
                ..Default::default()
            },
            &tz(),
            now,
        )
        .unwrap()
        .unwrap();
        assert_eq!(w.span().from, now - Duration::hours(1));

        let w = resolve(
            &TimeSpec {
                date: Some("2026-06-02".into()),
                hours: Some(vec![14, 10, 11]),
                ..Default::default()
            },
            &tz(),
            now,
        )
        .unwrap()
        .unwrap();
        assert_eq!(w.parts().len(), 2); // 10-12 merged, 14-15
        assert_eq!(w.total_len(), Duration::hours(3));

        assert!(
            resolve(
                &TimeSpec {
                    last: Some("1h".into()),
                    from: Some("2026-06-02 10:00".into()),
                    ..Default::default()
                },
                &tz(),
                now
            )
            .is_err()
        );
        assert!(resolve(&TimeSpec::default(), &tz(), now).unwrap().is_none());
    }

    #[test]
    fn dst_days() {
        let tz = tz();
        let now = parse_instant("2026-12-01T00:00:00Z", &tz).unwrap();
        // Fall back (2026-10-25 in Berlin): the day has 25 real hours.
        let w = resolve(
            &TimeSpec {
                date: Some("2026-10-25".into()),
                ..Default::default()
            },
            &tz,
            now,
        )
        .unwrap()
        .unwrap();
        assert_eq!(w.total_len(), Duration::hours(25));
        // Spring forward (2026-03-29): 02:00-03:00 does not exist.
        let e = resolve(
            &TimeSpec {
                date: Some("2026-03-29".into()),
                hours: Some(vec![2]),
                ..Default::default()
            },
            &tz,
            now,
        )
        .unwrap_err();
        assert!(e.contains("DST"), "{e}");
    }

    #[test]
    fn window_ops() {
        let t0 = parse_instant("2026-06-02T10:00:00Z", &tz()).unwrap();
        let h = Duration::hours(1);
        let w = Window::from_parts(vec![
            Interval::new(t0, t0 + h),
            Interval::new(t0 + h * 3, t0 + h * 4),
        ])
        .unwrap();
        assert!(w.contains(t0));
        assert!(!w.contains(t0 + h * 2));
        assert!(w.overlaps(&Interval::new(t0 + h / 2, t0 + h * 2)));
        assert!(!w.overlaps(&Interval::new(t0 + h, t0 + h * 3)));
        let c = w.clamp_from(t0 + h * 2).unwrap();
        assert_eq!(c.parts().len(), 1);
    }
}
