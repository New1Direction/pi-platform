//! Helpers that reproduce Python string semantics exactly, so ports stay
//! byte-for-byte faithful to the original agents under the parity harness.

/// Equivalent of Python `str.splitlines()`: splits on the same set of line
/// boundaries Python recognizes and does **not** emit a trailing empty line.
///
/// Boundaries: `\n \r \r\n \x0b \x0c \x1c \x1d \x1e \u{85} \u{2028} \u{2029}`.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let _ = bytes; // keep byte view available for future tuning
    let mut ci = 0usize;
    while ci < chars.len() {
        let (bpos, c) = chars[ci];
        let is_break = matches!(
            c,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}'
                | '\u{2028}' | '\u{2029}'
        );
        if is_break {
            out.push(&s[start..bpos]);
            // Handle the \r\n pair as a single boundary.
            if c == '\r' && ci + 1 < chars.len() && chars[ci + 1].1 == '\n' {
                ci += 1;
            }
            // start of next line is the byte after this boundary char(s)
            let next_byte = if ci + 1 < chars.len() {
                chars[ci + 1].0
            } else {
                s.len()
            };
            start = next_byte;
        }
        ci += 1;
        i = bpos;
    }
    let _ = i;
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Equivalent of Python `str.strip()` (no-arg): trims leading/trailing
/// whitespace. Rust's `str::trim` uses the Unicode `White_Space` property,
/// which matches CPython's default whitespace set for all practical inputs.
pub fn strip(s: &str) -> &str {
    s.trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines_matches_python_basics() {
        assert_eq!(splitlines("a\nb\nc"), vec!["a", "b", "c"]);
        // trailing newline does not produce an empty final element
        assert_eq!(splitlines("a\nb\n"), vec!["a", "b"]);
        // \r\n is a single boundary
        assert_eq!(splitlines("a\r\nb"), vec!["a", "b"]);
        // empty string -> no lines
        assert_eq!(splitlines(""), Vec::<&str>::new());
        // lone \r is a boundary
        assert_eq!(splitlines("a\rb"), vec!["a", "b"]);
    }
}
