//! Decodes a creation time embedded in an identifier (e.g. `TXN-20260602-1026-0001` → 2026-06-02 10:26),
//! so ID lookups can be scoped to a short window automatically.

use chrono::{Duration, NaiveDate};
use chrono_tz::Tz;
use regex::Regex;

use crate::parse::time::{Interval, Ts, local_to_utc};

#[derive(Clone, Debug)]
pub struct IdDecoder {
    pub name: String,
    pub re: Regex,
    /// How long after the decoded instant to search.
    pub window: Duration,
    /// How long before the decoded instant to search (clock skew, minute truncation).
    pub lookback: Duration,
    /// Services where this ID usually shows up; used when the caller gives none.
    pub services: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Decoded<'a> {
    pub decoder: &'a IdDecoder,
    pub at: Ts,
}

impl Decoded<'_> {
    pub fn interval(&self) -> Interval {
        Interval::new(
            self.at - self.decoder.lookback,
            self.at + self.decoder.window,
        )
    }
}

impl IdDecoder {
    pub fn validate(&self) -> Result<(), String> {
        let names: Vec<&str> = self.re.capture_names().flatten().collect();
        let has = |n: &str| names.contains(&n);
        if !(has("Y") || has("y")) || !has("m") || !has("d") {
            return Err(format!(
                "id_decoders '{}': regex needs named groups Y (or y), m, d and optionally H, M, S",
                self.name
            ));
        }
        Ok(())
    }

    pub fn decode(&self, id: &str, tz: &Tz) -> Option<Ts> {
        let c = self.re.captures(id.trim())?;
        let num = |n: &str| c.name(n).and_then(|m| m.as_str().parse::<u32>().ok());
        let year = match (c.name("Y"), c.name("y")) {
            (Some(y), _) => y.as_str().parse::<i32>().ok()?,
            (None, Some(y)) => 2000 + y.as_str().parse::<i32>().ok()?,
            _ => return None,
        };
        let date = NaiveDate::from_ymd_opt(year, num("m")?, num("d")?)?;
        let naive = date.and_hms_opt(
            num("H").unwrap_or(0),
            num("M").unwrap_or(0),
            num("S").unwrap_or(0),
        )?;
        local_to_utc(naive, tz).ok()
    }
}

/// Tries each decoder in order and returns the first that matches.
pub fn decode<'a>(decoders: &'a [IdDecoder], id: &str, tz: &Tz) -> Option<Decoded<'a>> {
    decoders
        .iter()
        .find_map(|d| d.decode(id, tz).map(|at| Decoded { decoder: d, at }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec() -> IdDecoder {
        IdDecoder {
            name: "order".into(),
            re: Regex::new(r"^TXN-(?P<Y>\d{4})(?P<m>\d{2})(?P<d>\d{2})-(?P<H>\d{2})(?P<M>\d{2})")
                .unwrap(),
            window: Duration::hours(1),
            lookback: Duration::minutes(1),
            services: vec!["orders".into()],
        }
    }

    #[test]
    fn decodes_order_id() {
        let d = dec();
        d.validate().unwrap();
        let tz: Tz = "UTC".parse().unwrap();
        let t = d.decode("TXN-20260602-1026-123456", &tz).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-06-02T10:26:00+00:00");
        assert!(d.decode("XYZ-20260602-1026", &tz).is_none());
        assert!(d.decode("TXN-20261302-1026", &tz).is_none()); // month 13
        let ds = [d];
        let found = decode(&ds, "TXN-20260602-1026", &tz).unwrap();
        assert_eq!(found.interval().len(), Duration::minutes(61));
    }

    #[test]
    fn two_digit_year() {
        let d = IdDecoder {
            re: Regex::new(r"^X(?P<y>\d{2})(?P<m>\d{2})(?P<d>\d{2})").unwrap(),
            ..dec()
        };
        d.validate().unwrap();
        let t = d.decode("X260602abc", &chrono_tz::UTC).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-06-02T00:00:00+00:00");
    }
}
