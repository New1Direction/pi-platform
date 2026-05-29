//! Port of `pi_micro_agents/pi_vyper_sec_scanner.py`.
//!
//! Specialized Web3 micro-agent that audits Vyper source code for compiler
//! reentrancy bugs and decorator best practices. Behaviour is a line-for-line
//! mirror of the Python original.

use crate::pyutil;
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

/// Mirrors `re.search(r'#\s*@version\s*([^\n\r]+)', code)`.
/// One capture group, no lookaround / backrefs, so it maps directly.
static VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"#\s*@version\s*([^\n\r]+)").unwrap());

/// Mirrors `re.search(r'\b0\.2\.[0-9]+\b', version_str)`.
static VULN_02_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b0\.2\.[0-9]+\b").unwrap());

/// Mirrors `re.search(r'\b0\.3\.[0-9]\b', version_str)`.
static VULN_03_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b0\.3\.[0-9]\b").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: the Python original ALSO falls back to a `~/.antigravitycli/config.json`
/// (or a repo-relative copy) file lookup when `PI_VYPER_STRICT_MODE` is unset,
/// defaulting to `True` if the file is absent / unreadable / does not set the
/// key. This port mirrors only the env-var branch (the established convention in
/// this codebase, e.g. `jwt_none_sentry.rs` / `floating_pragma_sentry.rs`) and
/// defaults to strict (`true`) when the env var is absent. See `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_VYPER_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_vyper(input: &Input) -> Output {
    let code = &input.vyper_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Clean comments (Vyper comments start with #).
    // NOTE: the Python original computes `re.sub(r'#.*', '', code)` but discards
    // the result, so it is a functional no-op. We omit it intentionally.

    // Mode 1: Compiler Bug Audit
    // Check version string in Vyper (usually declared as `# @version ^0.3.7` or
    // similar in comments).
    if let Some(version_match) = VERSION_RE.captures(code) {
        let version_str = pyutil::strip(&version_match[1]).to_string();
        // Flag vulnerable compiler versions < 0.3.10 containing known
        // reentrancy lock slot clashes (e.g. ^0.2.0, 0.3.7, etc.).
        if VULN_02_RE.is_match(&version_str) || VULN_03_RE.is_match(&version_str) {
            // If it uses nonreentrant lock, flag it.
            if code.contains("@nonreentrant") {
                vulnerable_funcs.push("global_compiler".to_string());
                flagged_findings.push(format!(
                    "Vulnerable Vyper compiler version '{version_str}' detected with active @nonreentrant decorators. \
Versions < 0.3.10 have reentrancy lock slot allocation vulnerabilities."
                ));
            }
        }
    }

    // Mode 2: Vyper Decorator and Syntax Best Practices
    // In Vyper, all functions must have an accessibility decorator
    // (@external or @internal). Find functions: `def [name](...):`.
    let lines = pyutil::splitlines(code);
    for (i, raw_line) in lines.iter().enumerate() {
        let stripped = pyutil::strip(raw_line);
        if stripped.starts_with("def ") && stripped.ends_with(':') {
            // func_name = stripped[4:stripped.find("(")].strip()
            // Python slices by CHARACTER index. `str.find` returns -1 when the
            // substring is absent, and Python then interprets the slice
            // `stripped[4:-1]` (i.e. up to the last character). We mirror both
            // the found and not-found cases char-by-char.
            let chars: Vec<char> = stripped.chars().collect();
            let paren_char_idx: i64 = chars
                .iter()
                .position(|&c| c == '(')
                .map(|p| p as i64)
                .unwrap_or(-1);
            // Resolve Python negative index relative to the char length.
            let end_char_idx: usize = if paren_char_idx < 0 {
                let len = chars.len() as i64;
                let resolved = len + paren_char_idx; // len + (-1)
                if resolved < 0 {
                    0
                } else {
                    resolved as usize
                }
            } else {
                paren_char_idx as usize
            };
            let start_char_idx = 4usize.min(chars.len());
            let end_char_idx = end_char_idx.max(start_char_idx).min(chars.len());
            let slice: String = chars[start_char_idx..end_char_idx].iter().collect();
            let func_name = pyutil::strip(&slice).to_string();

            // Look at prior lines for decorators.
            let mut has_decorator = false;
            let mut decorator_line = String::new();
            // Search up to 3 lines prior.
            for lookback in 1..4i64 {
                let prev_idx = i as i64 - lookback;
                if prev_idx >= 0 {
                    let prev_line = pyutil::strip(lines[prev_idx as usize]);
                    if prev_line.starts_with('@') {
                        has_decorator = true;
                        decorator_line = prev_line.to_string();
                        break;
                    }
                }
            }

            if !has_decorator {
                vulnerable_funcs.push(func_name.clone());
                let line_no = i + 1;
                flagged_findings.push(format!(
                    "Function '{func_name}' on Line {line_no} lacks access control or state decorator (@external/@internal)."
                ));
            } else {
                // Check for invalid decorators.
                let valid_decorators = [
                    "@external",
                    "@internal",
                    "@view",
                    "@pure",
                    "@payable",
                    "@nonreentrant",
                ];
                // dec_name = decorator_line.split("(")[0].strip()
                let dec_name = pyutil::strip(decorator_line.split('(').next().unwrap_or(""));
                if !valid_decorators.contains(&dec_name) {
                    vulnerable_funcs.push(func_name.clone());
                    let line_no = i + 1;
                    flagged_findings.push(format!(
                        "Function '{func_name}' on Line {line_no} uses invalid/unrecognized decorator '{dec_name}'."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_VYPER_VULNERABILITY".to_string();
        } else {
            status = "WARN_VYPER_VULNERABILITY".to_string();
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
    let out = audit_vyper(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_vyper(&Input {
            file_path: "C.vy".into(),
            vyper_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_decorated_contract_passes() {
        std::env::remove_var("PI_VYPER_STRICT_MODE");
        let code = "# @version 0.3.10\n\n@external\ndef foo():\n    pass";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    #[serial]
    fn missing_decorator_rejected_in_strict_mode() {
        std::env::set_var("PI_VYPER_STRICT_MODE", "true");
        let code = "def foo():\n    pass";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_VYPER_VULNERABILITY");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["foo"]);
        std::env::remove_var("PI_VYPER_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn vulnerable_compiler_with_nonreentrant_flagged() {
        std::env::remove_var("PI_VYPER_STRICT_MODE");
        let code = "# @version 0.3.7\n\n@external\n@nonreentrant('lock')\ndef withdraw():\n    pass";
        let o = run(code);
        // global_compiler flagged; the @nonreentrant decorator line is the one
        // immediately above def -> dec_name "@nonreentrant" is valid, so the
        // only finding is the compiler version one.
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["global_compiler"]);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("Vulnerable Vyper compiler version '0.3.7'"));
    }

    #[test]
    #[serial]
    fn invalid_decorator_warns_in_non_strict_mode() {
        std::env::set_var("PI_VYPER_STRICT_MODE", "false");
        let code = "@bogus\ndef foo():\n    pass";
        let o = run(code);
        // non-strict coerces is_secure back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_VYPER_VULNERABILITY");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["foo"]);
        assert!(o.flagged_findings[0].contains("invalid/unrecognized decorator '@bogus'"));
        std::env::remove_var("PI_VYPER_STRICT_MODE");
    }
}
