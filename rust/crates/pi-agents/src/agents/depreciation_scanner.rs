//! Port of `pi_micro_agents/pi_depreciation_scanner.py`.
//!
//! Deterministic micro-agent that scans code files for deprecated functions,
//! libraries, or modules. Behaviour is a line-for-line mirror of the Python
//! original (`PiDepreciationScanner.scan_depreciation`).

use crate::pyutil;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub code_content: String,
    pub deprecated_patterns: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub symbols_found: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var `PI_DEPRECIATION_STRICT_MODE`
/// is set to a value that is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_DEPRECIATION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Faithful reproduction of CPython 3.11 `re.escape`.
///
/// `re.escape` escapes every ASCII character that is *not* alphanumeric and not
/// underscore, with two special cases: ASCII whitespace and the small set of
/// regex metacharacters get a backslash, while all non-ASCII characters and
/// `[A-Za-z0-9_]` are passed through untouched.
///
/// Concretely (CPython 3.7+), the special set is:
/// `()[]{}?*+-|^$\\.&~# \t\n\r\v\f`. We replicate that exactly so that the
/// generated regex matches Python's, then rely on the `regex` crate accepting
/// these escapes (it treats `\x` for any of these as the literal `x`).
fn py_re_escape(s: &str) -> String {
    // The exact set CPython escapes (everything else that is ASCII and not
    // [A-Za-z0-9_] is also escaped, but in practice that set is what remains).
    // CPython's implementation: escape any char c where c is ASCII and
    // c not in "_" and not c.isalnum() (ASCII alnum), plus it always passes
    // through non-ASCII. We mirror that branch logic directly.
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if c.is_ascii() {
            let is_word = c.is_ascii_alphanumeric() || c == '_';
            if is_word {
                out.push(c);
            } else {
                // CPython escapes all non-word ASCII chars.
                out.push('\\');
                out.push(c);
            }
        } else {
            // Non-ASCII characters are left untouched by re.escape.
            out.push(c);
        }
    }
    out
}

pub fn scan_depreciation(input: &Input) -> Output {
    let code = &input.code_content;
    let deprecated_patterns = &input.deprecated_patterns;
    let mut symbols_found: Vec<String> = Vec::new();

    let lines = pyutil::splitlines(code);
    for line in lines.iter() {
        // Note: Python iterates `enumerate(lines, start=1)` but `idx` is never
        // used in the scan body, so the index is irrelevant to the output.
        for pat in deprecated_patterns.iter() {
            // regex = r"\b" + re.escape(pat) + r"\b"
            let regex_src = format!(r"\b{}\b", py_re_escape(pat));
            // Python `re.search` would raise on an invalid pattern; since the
            // pattern is always `\b...\b` around escaped text it is always
            // valid, so unwrap mirrors the "no error" Python path.
            let re = Regex::new(&regex_src).unwrap();
            if re.is_match(line) {
                symbols_found.push(pat.clone());
            }
        }
    }

    let mut is_secure = symbols_found.is_empty();
    let risk_score = if !is_secure { 60.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_DEPRECIATION".to_string();
        } else {
            status = "WARN_DEPRECIATION".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        symbols_found,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_depreciation(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str, patterns: &[&str]) -> Output {
        scan_depreciation(&Input {
            file_path: "f.py".into(),
            code_content: code.into(),
            deprecated_patterns: patterns.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[test]
    fn clean_code_passes() {
        let o = run("import os\nx = safe_call()", &["legacy_func", "old_module"]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.symbols_found.is_empty());
    }

    #[test]
    fn deprecated_symbol_flagged() {
        let o = run("result = old_api(1, 2)", &["old_api"]);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DEPRECIATION");
        assert_eq!(o.risk_score, 60.0);
        assert_eq!(o.symbols_found, vec!["old_api"]);
    }

    #[test]
    fn word_boundary_does_not_match_substring() {
        // "old_api" should NOT match inside "old_apifoo" thanks to \b...\b.
        let o = run("x = old_apifoo()", &["old_api"]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn dotted_pattern_matches_each_line() {
        // os.system appears on two lines -> appended twice (one per line).
        let o = run("a = os.system(c)\nb = os.system(d)", &["os.system"]);
        assert_eq!(o.symbols_found, vec!["os.system", "os.system"]);
        assert!(!o.is_secure);
    }

    #[test]
    fn space_and_dash_patterns_use_word_boundaries() {
        // re.escape turns " " -> "\ " and "-" -> "\-"; the regex must still
        // compile and match the literal text within word boundaries.
        let o = run("call hello world here", &["hello world"]);
        assert_eq!(o.symbols_found, vec!["hello world"]);
        assert!(!o.is_secure);
    }
}
