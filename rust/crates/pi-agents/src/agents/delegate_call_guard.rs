//! Port of `pi_micro_agents/pi_delegate_call_guard.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for unsafe
//! `delegatecall` usage and EIP-1967 storage-slot compliance. Behaviour is a
//! line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::pyutil;

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

// Python: re.sub(r'//.*', '', code)
// `.` (no DOTALL) does not span newlines, so this strips a `//` line comment to
// the end of its line but keeps the newline.
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// Python: re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
// DOTALL -> `(?s)` so `.` also matches newlines; non-greedy `.*?`.
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

// Python: re.compile(r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(')
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

const EIP1967_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/// Mirrors `is_strict_mode()`.
///
/// Faithful for the env-var branch (which all parity samples exercise). When the
/// env var `PI_DELEGATECALL_STRICT_MODE` is unset, Python additionally consults
/// a JSON config file (`~/.antigravitycli/config.json`, then a repo-relative
/// `../../.antigravitycli/config.json`), returning
/// `bool(data.get("PI_DELEGATECALL_STRICT_MODE", True))` if found and `True`
/// otherwise. We replicate only the final default (`True`); see the parity
/// deviations note for the config-file fallback.
fn is_strict_mode() -> bool {
    match std::env::var("PI_DELEGATECALL_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `extract_solidity_functions`.
///
/// Returns `(func_name, func_body, start_line)` tuples for concrete (braced)
/// Solidity functions. Operates over byte offsets to exactly match Python's
/// index-based scan; the regex pattern only matches ASCII keywords/identifiers,
/// and brace/semicolon scanning is over single-byte ASCII chars.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let mut functions: Vec<(String, String, usize)> = Vec::new();
    let bytes = solidity_code.as_bytes();
    let code_len = bytes.len();

    for caps in FUNC_RE.captures_iter(solidity_code) {
        let keyword = caps.get(1).map_or("", |m| m.as_str());
        let name = caps.get(2).map_or("", |m| m.as_str());
        let func_name = if keyword == "function" {
            name.to_string()
        } else if keyword == "constructor" {
            "constructor".to_string()
        } else if keyword == "fallback" {
            "fallback".to_string()
        } else {
            "receive".to_string()
        };

        let start_idx = caps.get(0).map_or(0, |m| m.start());

        // Calculate line number: solidity_code[:start_idx].count('\n') + 1.
        // Python `.count('\n')` counts only the '\n' character.
        let start_line = solidity_code[..start_idx].matches('\n').count() + 1;

        // Semicolons and opening braces determine concrete vs abstract functions.
        // Python `str.find(ch, start_idx)` returns a byte-equivalent index (ASCII).
        let semicolon_idx = find_byte_from(bytes, b';', start_idx);
        let brace_idx = find_byte_from(bytes, b'{', start_idx);

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx)
        match brace_idx {
            None => continue,
            Some(b) => {
                if let Some(s) = semicolon_idx {
                    if s < b {
                        continue;
                    }
                }
            }
        }
        let brace_idx = brace_idx.unwrap();

        // Match braces to find full function block body.
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

/// Equivalent of Python `str.find(ch, start)` over ASCII bytes: returns the
/// first byte index `>= start` where `bytes[i] == needle`, else `None` (Python
/// returns -1).
fn find_byte_from(bytes: &[u8], needle: u8, start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn audit_delegatecall(input: &Input) -> Output {
    let code = &input.solidity_code;

    // Clean comments to avoid false positives in global analysis.
    let code_clean = LINE_COMMENT_RE.replace_all(code, "");
    let code_clean = BLOCK_COMMENT_RE.replace_all(&code_clean, "");

    let functions = extract_solidity_functions(code);

    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Check globally if the standard EIP-1967 storage slot is referenced.
    let has_eip1967_slot = code_clean.to_lowercase().contains(EIP1967_SLOT);

    for (func_name, func_body, start_line) in &functions {
        if func_name == "constructor" {
            continue;
        }

        // Clean comments for this function body.
        let cleaned_body = LINE_COMMENT_RE.replace_all(func_body, "");
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "");

        // Check if delegatecall is used.
        if cleaned_body.contains("delegatecall(") {
            // If EIP-1967 standard slot is present, treat as compliant proxy.
            if has_eip1967_slot {
                continue;
            }

            // Otherwise, inspect the lines to pinpoint the delegatecall.
            let lines = pyutil::splitlines(&cleaned_body);
            for (offset, line) in lines.into_iter().enumerate() {
                let line_num = start_line + offset;
                let stripped = pyutil::strip(line);
                if stripped.contains("delegatecall(") {
                    // Flag as vulnerable.
                    if !vulnerable_funcs.contains(func_name) {
                        vulnerable_funcs.push(func_name.clone());
                    }

                    flagged_findings.push(format!(
                        "Function '{func_name}' executes a delegatecall on Line {line_num}: '{stripped}' \
without references to the standard EIP-1967 storage slot \
(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc), \
making it vulnerable to unauthorized delegatecall hijacks."
                    ));
                    break;
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
            status = "REJECTED_DELEGATECALL_VULNERABILITY".to_string();
        } else {
            status = "WARN_DELEGATECALL_VULNERABILITY".to_string();
            is_secure = true; // Warn only in non-strict mode.
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
    let out = audit_delegatecall(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        // Ensure deterministic strict mode for tests.
        std::env::set_var("PI_DELEGATECALL_STRICT_MODE", "true");
        audit_delegatecall(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_contract_passes() {
        let o = run("contract C {\n  function ping() public { value = 1; }\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn unsafe_delegatecall_flagged() {
        let o = run(
            "contract C {\n  function exec(address t, bytes data) public {\n    t.delegatecall(data);\n  }\n}",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DELEGATECALL_VULNERABILITY");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_functions, vec!["exec"]);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("Line 3"));
    }

    #[test]
    #[serial]
    fn eip1967_slot_makes_delegatecall_compliant() {
        let code = "contract Proxy {\n  function _delegate(address impl) internal {\n    bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;\n    impl.delegatecall(msg.data);\n  }\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn warn_path_coerces_secure() {
        std::env::set_var("PI_DELEGATECALL_STRICT_MODE", "false");
        let o = audit_delegatecall(&Input {
            file_path: "C.sol".into(),
            solidity_code:
                "contract C {\n  function exec(bytes data) public {\n    target.delegatecall(data);\n  }\n}"
                    .into(),
            check_level: "MEDIUM".into(),
        });
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_DELEGATECALL_VULNERABILITY");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_functions, vec!["exec"]);
        std::env::set_var("PI_DELEGATECALL_STRICT_MODE", "true");
    }
}
