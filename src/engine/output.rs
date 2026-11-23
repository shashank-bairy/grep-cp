//! Output cleaning: ANSI stripping, lossy UTF-8, redaction, and line truncation. Applied to every
//! line before it leaves the process.

use crate::config::Settings;

/// Cleans one raw log line for output. Redaction runs before truncation so a cut can never expose
/// half of a secret that the rule would have matched whole.
pub fn clean(raw: &[u8], s: &Settings) -> String {
    let stripped = strip_ansi(raw);
    let mut text = String::from_utf8_lossy(&stripped).into_owned();
    for (_, re, rep) in &s.redactions {
        if re.is_match(&text) {
            text = re.replace_all(&text, rep.as_str()).into_owned();
        }
    }
    truncate(text, s.limits().max_line_bytes)
}

/// Removes ANSI escape sequences (CSI `ESC [ … final`, OSC `ESC ] … BEL|ESC \\`, and two-byte
/// `ESC x`) plus other C0 control bytes, keeping tabs.
pub fn strip_ansi(raw: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if !raw.iter().any(|&b| b < 0x20 && b != b'\t') && !raw.contains(&0x7f) {
        return std::borrow::Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b == 0x1b {
            match raw.get(i + 1) {
                Some(b'[') => {
                    i += 2;
                    while i < raw.len() && !(0x40..=0x7e).contains(&raw[i]) {
                        i += 1;
                    }
                    i += 1;
                }
                Some(b']') => {
                    i += 2;
                    while i < raw.len() {
                        if raw[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        if raw[i] == 0x1b && raw.get(i + 1) == Some(&b'\\') {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                Some(_) => i += 2,
                None => i += 1,
            }
            continue;
        }
        if (b < 0x20 && b != b'\t') || b == 0x7f {
            i += 1;
            continue;
        }
        out.push(b);
        i += 1;
    }
    std::borrow::Cow::Owned(out)
}

pub fn truncate(mut text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut cut = max;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let extra = text.len() - cut;
    text.truncate(cut);
    text.push_str(&format!(" …[+{extra} bytes]"));
    text
}

/// Human-readable byte size.
pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else {
        format!("{v:.1}{}", U[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::sample_toml;

    #[test]
    fn cleans_lines() {
        let s = Settings::from_toml(&sample_toml("/x")).unwrap();
        let out = clean(
            b"\x1b[31mERROR\x1b[0m Authorization: Bearer abc.def-123 done\r",
            &s,
        );
        assert_eq!(out, "ERROR Authorization: bearer <redacted> done");
        assert_eq!(clean(b"bad \xff byte", &s), "bad \u{fffd} byte");
        assert_eq!(clean(b"\tat x\x1b]0;title\x07 y\x00", &s), "\tat x y");
    }

    #[test]
    fn truncates_on_char_boundary() {
        let t = truncate("héllo".repeat(10), 7);
        assert!(t.starts_with("héllo"));
        assert!(t.contains("…[+"));
        assert_eq!(human_bytes(512), "512B");
        assert_eq!(human_bytes(1536), "1.5KB");
    }
}
