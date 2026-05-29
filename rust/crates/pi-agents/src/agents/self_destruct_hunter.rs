//! Port of `pi_micro_agents/pi_self_destruct_hunter.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for
//! `selfdestruct`/`suicide` usage and secure decommissioning paths.
//! Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub solidity_code: String,
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

/// Mirrors `is_strict_mode()`.
///
/// The Python version, after checking the env var, falls back to reading a
/// `~/.antigravitycli/config.json` (or repo-root) config file and finally
/// defaults to `True`. That config-file fallback is environment-dependent and
/// is intentionally NOT reproduced here (mirroring `jwt_none_sentry.rs`): we
/// honour the env var and otherwise default to strict (`True`).
fn is_strict_mode() -> bool {
    match std::env::var("PI_SELFDESTRUCT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// `\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(`
// 2 capture groups; `\b` word boundaries are supported by the `regex` crate.
static FUNC_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// `re.sub(r'//.*', '', body)` — `.` does NOT match newline (no DOTALL).
static LINE_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// `re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)` — `(?s)` enables DOTALL,
// non-greedy `.*?`.
static BLOCK_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

/// Mirror of `extract_solidity_functions`.
///
/// Returns tuples of `(func_name, func_body, start_line)`. All indices are byte
/// offsets, which coincide with Python's character offsets for ASCII Solidity
/// source. `start_line` counts only `\n` characters in the prefix, matching
/// Python's `prefix.count('\n') + 1`.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, i64)> {
    let mut functions: Vec<(String, String, i64)> = Vec::new();
    let bytes = solidity_code.as_bytes();
    let code_len = bytes.len();

    for caps in FUNC_PATTERN.captures_iter(solidity_code) {
        let keyword = caps.get(1).unwrap().as_str();
        let name = caps.get(2).unwrap().as_str();
        let func_name: String = if keyword == "function" {
            name.to_string()
        } else if keyword == "constructor" {
            "constructor".to_string()
        } else if keyword == "fallback" {
            "fallback".to_string()
        } else {
            "receive".to_string()
        };

        let start_idx = caps.get(0).unwrap().start();
        // start_line = solidity_code[:start_idx].count('\n') + 1
        let start_line =
            solidity_code[..start_idx].matches('\n').count() as i64 + 1;

        // semicolon_idx = solidity_code.find(';', start_idx)  (-1 if absent)
        let semicolon_idx = find_byte(bytes, b';', start_idx);
        // brace_idx = solidity_code.find('{', start_idx)
        let brace_idx = find_byte(bytes, b'{', start_idx);

        if brace_idx == -1 || (semicolon_idx != -1 && semicolon_idx < brace_idx) {
            continue;
        }

        let brace_idx = brace_idx as usize;
        let mut brace_count: i64 = 1;
        let mut curr_idx = brace_idx + 1;
        while curr_idx < code_len && brace_count > 0 {
            let ch = bytes[curr_idx];
            if ch == b'{' {
                brace_count += 1;
            } else if ch == b'}' {
                brace_count -= 1;
            }
            curr_idx += 1;
        }

        if brace_count == 0 {
            let func_body = &solidity_code[start_idx..curr_idx];
            functions.push((func_name, func_body.to_string(), start_line));
        }
    }

    functions
}

/// Python `str.find(ch, start)` over ASCII bytes: byte index of first
/// occurrence at/after `start`, or `-1` if not found.
fn find_byte(bytes: &[u8], needle: u8, start: usize) -> i64 {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == needle {
            return i as i64;
        }
        i += 1;
    }
    -1
}

pub fn audit_selfdestruct(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    // has_pause_mech = any(kw in code.lower() for kw in [...])
    let code_lower = code.to_lowercase();
    let has_pause_mech = ["pause", "pausable", "ispaused", "expire", "expiration"]
        .iter()
        .any(|kw| code_lower.contains(kw));

    for (func_name, func_body, start_line) in functions {
        // Clean comments
        let cleaned_body = LINE_COMMENT.replace_all(&func_body, "");
        let cleaned_body = BLOCK_COMMENT.replace_all(&cleaned_body, "").into_owned();

        if cleaned_body.contains("selfdestruct(") || cleaned_body.contains("suicide(") {
            let cleaned_lower = cleaned_body.to_lowercase();
            // Mode 1: SelfDestruct Exploit Scan
            let has_auth = ["onlyOwner", "onlyAdmin", "hasRole"]
                .iter()
                .any(|m| cleaned_body.contains(m))
                || ["msg.sender == owner", "msg.sender == admin"]
                    .iter()
                    .any(|r| cleaned_lower.contains(r));

            if !has_auth {
                vulnerable_funcs.push(func_name.clone());
                flagged_findings.push(format!(
                    "Function '{func_name}' on Line {start_line} contains a selfdestruct call without active \
access control modifiers (like onlyOwner) or owner equality requirements, exposing the contract to theft."
                ));
            } else {
                // Mode 2: Contract Decommissioning Check
                if !has_pause_mech {
                    flagged_findings.push(format!(
                        "Decommissioning warning: Function '{func_name}' on Line {start_line} performs selfdestruct, \
but contract does not implement standard Pausable state transitions to safeguard funds prior to termination."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 95.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SELFDESTRUCT_VULNERABILITY".to_string();
        } else {
            status = "WARN_SELFDESTRUCT_VULNERABILITY".to_string();
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
    let out = audit_selfdestruct(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_selfdestruct(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[serial]
    #[test]
    fn unauthorized_selfdestruct_rejected() {
        std::env::remove_var("PI_SELFDESTRUCT_STRICT_MODE");
        let o = run(
            "contract C {\n  function kill() public {\n    selfdestruct(payable(msg.sender));\n  }\n}",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SELFDESTRUCT_VULNERABILITY");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_functions, vec!["kill"]);
    }

    #[serial]
    #[test]
    fn authorized_selfdestruct_without_pause_warns_in_findings_but_secure() {
        std::env::remove_var("PI_SELFDESTRUCT_STRICT_MODE");
        let o = run(
            "contract C {\n  function kill() public onlyOwner {\n    selfdestruct(payable(owner));\n  }\n}",
        );
        // No vulnerable functions -> secure & PASSED, but a decommissioning warning is recorded.
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("Decommissioning warning"));
    }

    #[serial]
    #[test]
    fn non_strict_env_coerces_warn_and_secure() {
        std::env::set_var("PI_SELFDESTRUCT_STRICT_MODE", "false");
        let o = run(
            "contract C {\n  function kill() public {\n    selfdestruct(payable(msg.sender));\n  }\n}",
        );
        assert!(o.is_secure); // coerced back to true in WARN path
        assert_eq!(o.status, "WARN_SELFDESTRUCT_VULNERABILITY");
        assert_eq!(o.vulnerable_functions, vec!["kill"]);
        std::env::remove_var("PI_SELFDESTRUCT_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn clean_contract_passes() {
        std::env::remove_var("PI_SELFDESTRUCT_STRICT_MODE");
        let o = run("contract C {\n  function foo() public returns (uint) { return 1; }\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.flagged_findings.is_empty());
    }
}
