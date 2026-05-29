//! Port of `pi_micro_agents/pi_read_only_reentrancy_sentry.py`.
//!
//! Audits Solidity contracts for read-only reentrancy vulnerabilities and
//! view-function safety. Behaviour is a line-for-line mirror of the Python
//! original.

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

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: the Python original ALSO consults
/// `~/.antigravitycli/config.json` (and a repo-relative fallback) when the env
/// var is unset, defaulting to `True`. This port only honours the env var and
/// otherwise defaults to `true`, exactly like the reference `jwt_none_sentry`
/// port. See parity `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_READONLY_REENTRANCY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Mirrors `re.compile(r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(')`.
static FUNC_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// Mirrors `re.sub(r'//.*', '', body)` — single-line comment removal.
// `.` does not match newline by default (no DOTALL), matching Python.
static LINE_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// Mirrors `re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)` — block comments.
static BLOCK_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

/// Mirrors `extract_solidity_functions`. Returns `(func_name, func_body, start_line)`.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let mut functions: Vec<(String, String, usize)> = Vec::new();
    // Byte length, mirroring Python `len(str)` over a code string. We operate
    // on bytes throughout to match Python `str.find` byte/offset semantics for
    // ASCII while remaining UTF-8 safe (regex match offsets are byte offsets).
    let bytes = solidity_code.as_bytes();
    let code_len = bytes.len();

    for caps in FUNC_PATTERN.captures_iter(solidity_code) {
        let keyword = caps.get(1).unwrap().as_str();
        let name = caps.get(2).unwrap().as_str();
        let func_name: String = match keyword {
            "function" => name.to_string(),
            "constructor" => "constructor".to_string(),
            "fallback" => "fallback".to_string(),
            _ => "receive".to_string(),
        };

        let m = caps.get(0).unwrap();
        let start_idx = m.start();
        // start_line = solidity_code[:start_idx].count('\n') + 1
        let start_line = solidity_code[..start_idx].matches('\n').count() + 1;

        // semicolon_idx = solidity_code.find(';', start_idx)
        let semicolon_idx = find_byte(bytes, b';', start_idx);
        // brace_idx = solidity_code.find('{', start_idx)
        let brace_idx = find_byte(bytes, b'{', start_idx);

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue
        let brace_idx = match brace_idx {
            None => continue,
            Some(b) => b,
        };
        if let Some(s) = semicolon_idx {
            if s < brace_idx {
                continue;
            }
        }

        // Brace matching.
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
            // func_body = solidity_code[start_idx:curr_idx]
            let func_body = solidity_code[start_idx..curr_idx].to_string();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

/// Mirrors Python `str.find(ch, start)`: byte index of the first `needle` at or
/// after `start`, or `None` (Python `-1`).
fn find_byte(bytes: &[u8], needle: u8, start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn audit_readonly_reentrancy(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    for (func_name, func_body, start_line) in &functions {
        // Clean comments.
        let cleaned_body = LINE_COMMENT.replace_all(func_body, "");
        let cleaned_body = BLOCK_COMMENT.replace_all(&cleaned_body, "");
        let cleaned_body: &str = &cleaned_body;

        // Mode 1: Read-Only Reentrancy Check.
        if ["get_virtual_price", "get_dy", "balanceOf"]
            .iter()
            .any(|kw| cleaned_body.contains(kw))
        {
            if !["nonReentrant", "checkLock", "require(", "assert("]
                .iter()
                .any(|check| cleaned_body.contains(check))
            {
                vulnerable_funcs.push(func_name.clone());
                flagged_findings.push(format!(
                    "Function '{func_name}' on Line {start_line} queries external pool balances or pricing virtual functions \
without verifying if the external pool contract is currently locked/reentered. \
This exposes it to Read-Only Reentrancy exploits."
                ));
            }
        }

        // Mode 2: View-Function Safety Check.
        if func_body.contains("view") || func_body.contains("pure") {
            if cleaned_body.contains("block.timestamp") && !cleaned_body.contains("require") {
                flagged_findings.push(format!(
                    "Safety warning: View function '{func_name}' on Line {start_line} relies on block.timestamp \
for dynamic pricing query without validation checks."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_READONLY_REENTRANCY".to_string();
        } else {
            status = "WARN_READONLY_REENTRANCY".to_string();
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
    let out = audit_readonly_reentrancy(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_readonly_reentrancy(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_function_passes() {
        std::env::remove_var("PI_READONLY_REENTRANCY_STRICT_MODE");
        let o = run("function foo() public { uint x = 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn readonly_reentrancy_flagged_strict() {
        std::env::remove_var("PI_READONLY_REENTRANCY_STRICT_MODE");
        let o = run("function getPrice() public view returns (uint) { return pool.get_virtual_price(); }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_READONLY_REENTRANCY");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["getPrice"]);
    }

    #[test]
    #[serial]
    fn readonly_reentrancy_warn_when_not_strict() {
        std::env::set_var("PI_READONLY_REENTRANCY_STRICT_MODE", "false");
        let o = run("function getBal() public view returns (uint) { return token.balanceOf(addr); }");
        std::env::remove_var("PI_READONLY_REENTRANCY_STRICT_MODE");
        assert!(o.is_secure); // coerced back to true in WARN path
        assert_eq!(o.status, "WARN_READONLY_REENTRANCY");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["getBal"]);
    }

    #[test]
    #[serial]
    fn require_check_suppresses_flag() {
        std::env::remove_var("PI_READONLY_REENTRANCY_STRICT_MODE");
        let o = run("function getDy() public view { require(!locked); pool.get_dy(0,1,2); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }
}
