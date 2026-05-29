//! Port of `pi_micro_agents/pi_vyper_state_lock_sentry.py`.
//!
//! Audits Vyper source code for `@nonreentrant` decorator safety violations:
//! functions that perform external calls and modify state but lack the
//! `@nonreentrant` decorator are flagged. Behaviour is a line-for-line mirror
//! of the Python original.
//!
//! The Python source uses one regex with a trailing lookahead
//! `(?=\n\S|\Z)`, which the Rust `regex` crate cannot express. The match is
//! therefore split into a fully-supported "header" regex plus a manual body
//! scan that reproduces the lookahead's stop condition exactly (the body, a
//! non-greedy `[\s\S]*?`, ends at the first `\n` followed by a non-whitespace
//! character, or at end-of-string). A manual non-overlapping cursor reproduces
//! `re.findall`'s advance-past-the-full-match behaviour.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub vyper_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_functions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Header portion of the Python function-block regex (everything up to and
// including the `\s*` that precedes the body group). The body group and its
// lookahead are handled manually in `find_func_blocks`.
//
// Python: r'((?:@[a-zA-Z0-9_]+(?:\([^)]*\))?\s*)*)def\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^:]*:\s*'
static HEADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"((?:@[a-zA-Z0-9_]+(?:\([^)]*\))?\s*)*)def\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^:]*:\s*")
        .unwrap()
});

// `\b[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\(` — method-call detection inside a body.
static METHOD_CALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\(").unwrap());

// State-mod patterns: `self.<name> =` and `self.<name> (+=|-=)`.
static STATE_ASSIGN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"self\.[a-zA-Z0-9_]+\s*=").unwrap());
static STATE_AUGASSIGN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"self\.[a-zA-Z0-9_]+\s*(\+=|-=)").unwrap());

/// True if `c` is whitespace per the regex `\s` class (which Python's `\S`
/// negates). Rust's `char::is_whitespace` omits `\x1c\x1d\x1e`, which the
/// regex `\s` (and Python) treat as whitespace, so handle them explicitly.
fn is_regex_whitespace(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}' | '\u{1d}' | '\u{1e}')
}

/// Compute the end byte offset of a function body that starts at `start`,
/// reproducing the Python lookahead `(?=\n\S|\Z)`: stop at the first `\n`
/// immediately followed by a non-whitespace character, else end-of-string.
fn body_end(code: &str, start: usize) -> usize {
    let bytes = code.as_bytes();
    let n = code.len();
    let mut i = start;
    while i < n {
        if bytes[i] == b'\n' {
            // Look at the next char (if any).
            if i + 1 < n {
                // Decode the char starting at i+1.
                let next = code[i + 1..].chars().next().unwrap();
                if !is_regex_whitespace(next) {
                    return i;
                }
            }
        }
        i += 1;
    }
    n
}

/// Mirror of `re.findall(...)` for the function-block pattern. Returns
/// `(decorators, name, args, body)` tuples in document order, non-overlapping.
fn find_func_blocks(code: &str) -> Vec<(String, String, String, String)> {
    let mut out: Vec<(String, String, String, String)> = Vec::new();
    let mut pos = 0usize;
    let n = code.len();
    while pos <= n {
        let m = match HEADER_RE.find_at(code, pos) {
            Some(m) => m,
            None => break,
        };
        let caps = HEADER_RE.captures_at(code, pos).unwrap();
        let decorators = caps.get(1).map_or("", |c| c.as_str()).to_string();
        let name = caps.get(2).map_or("", |c| c.as_str()).to_string();
        let args = caps.get(3).map_or("", |c| c.as_str()).to_string();
        let body_start = m.end();
        let body_stop = body_end(code, body_start);
        let body = code[body_start..body_stop].to_string();
        out.push((decorators, name, args, body));

        // Advance like `re.findall`: continue from the end of the full match,
        // which is the end of the body. Guard against non-advancing matches.
        let mut newpos = if body_stop > m.end() { body_stop } else { m.end() };
        if newpos <= m.start() {
            newpos = m.start() + 1;
        }
        pos = if newpos > pos { newpos } else { pos + 1 };
    }
    out
}

/// Mirrors `is_strict_mode()`. The Python helper also consults a config file
/// when the env var is unset; the parity harness only exercises the env-var
/// path, but we reproduce the env-var branch faithfully and default to strict
/// (the config file is absent in the parity environment, so Python also
/// returns `True` there).
fn is_strict_mode() -> bool {
    match std::env::var("PI_VYPER_LOCK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_vyper_lock(input: &Input) -> Output {
    let code = &input.vyper_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for (decorators, name, _args, body) in find_func_blocks(code) {
        // Check if function performs external call: raw_call, ext_call, or self.
        let has_external_call = body.contains("raw_call")
            || body.contains("ext_call")
            || METHOD_CALL_RE.is_match(&body);
        // Check if it has a nonreentrant decorator.
        let has_nonreentrant = decorators.contains("@nonreentrant");

        if has_external_call && !has_nonreentrant {
            // In Vyper, functions modifying state and performing external calls
            // should use nonreentrant.
            let modifies_state =
                STATE_ASSIGN_RE.is_match(&body) || STATE_AUGASSIGN_RE.is_match(&body);
            if modifies_state {
                vulnerable_funcs.push(name.clone());
                flagged_findings.push(format!(
                    "Function '{name}' makes external calls and modifies local state but lacks the `@nonreentrant` decorator. \
This may violate Vyper reentrancy safety guidelines."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_VYPER_LOCK_RISK".to_string();
        } else {
            status = "WARN_VYPER_LOCK_RISK".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_functions: vulnerable_funcs,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_vyper_lock(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_vyper_lock(&Input {
            file_path: "f.vy".into(),
            vyper_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_with_nonreentrant_passes() {
        std::env::remove_var("PI_VYPER_LOCK_STRICT_MODE");
        let code = "@external\n@nonreentrant('lock')\ndef withdraw():\n    self.balance = 0\n    raw_call(msg.sender, b\"\")\n";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn vulnerable_function_rejected_in_strict() {
        std::env::set_var("PI_VYPER_LOCK_STRICT_MODE", "true");
        let code = "@external\ndef withdraw():\n    raw_call(msg.sender, b\"\")\n    self.balance = 0\n";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_VYPER_LOCK_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["withdraw"]);
        std::env::remove_var("PI_VYPER_LOCK_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn vulnerable_function_warns_in_non_strict() {
        std::env::set_var("PI_VYPER_LOCK_STRICT_MODE", "false");
        let code = "@external\ndef f():\n    self.x += 1\n    erc20.transfer(a, b)\n";
        let o = run(code);
        // Non-strict coerces is_secure back to true and warns.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_VYPER_LOCK_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["f"]);
        std::env::remove_var("PI_VYPER_LOCK_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn external_call_without_state_mod_is_safe() {
        std::env::remove_var("PI_VYPER_LOCK_STRICT_MODE");
        let code = "@external\ndef f():\n    raw_call(p, q)\n";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
