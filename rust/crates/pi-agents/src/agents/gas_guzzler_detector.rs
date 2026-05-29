//! Port of `pi_micro_agents/pi_gas_guzzler_detector.py`.
//!
//! Audits Solidity contracts for unbounded-loop gas exhaustion and general gas
//! inefficiencies. Behaviour is a line-for-line mirror of the Python original.

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

// Compiled regexes mirroring the Python source.
//
// `re.compile(r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(')`
static FUNC_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap());
// `re.sub(r'//.*', '', func_body)` — `.` does not match newline (Python default).
static LINE_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());
// `re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)` — non-greedy, DOTALL.
static BLOCK_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());
// `re.search(r'\.\s*length\b', cleaned_body)`
static LENGTH_LOOKUP: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.\s*length\b").unwrap());
// `re.search(r'\b(s\.|storageVar|stateVar|mappingVar)\b', cleaned_body)`
static STORAGE_VAR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(s\.|storageVar|stateVar|mappingVar)\b").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the env var `PI_GAS_STRICT_MODE`: if set, returns
/// `value.lower() == "true"`. If unset, it falls back to a
/// `~/.antigravitycli/config.json` config file (or a module-relative
/// `../../.antigravitycli/config.json`), returning
/// `bool(data.get("PI_GAS_STRICT_MODE", True))` — i.e. defaulting to `True`
/// when the file is absent / unreadable / missing the key. We mirror the
/// env-var branch exactly and default to `true` when the env var is unset,
/// matching the Python default for a config file that lacks the key. See the
/// module `deviations` notes for the config-file edge case.
fn is_strict_mode() -> bool {
    match std::env::var("PI_GAS_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `extract_solidity_functions(solidity_code)`.
///
/// Returns `(func_name, func_body, start_line)` tuples for every brace-balanced
/// function/constructor/fallback/receive definition.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let mut functions: Vec<(String, String, usize)> = Vec::new();
    let bytes = solidity_code.as_bytes();
    let code_len = bytes.len();

    for caps in FUNC_PATTERN.captures_iter(solidity_code) {
        let keyword = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let name = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let func_name: String = if keyword == "function" {
            name.to_string()
        } else if keyword == "constructor" {
            "constructor".to_string()
        } else if keyword == "fallback" {
            "fallback".to_string()
        } else {
            "receive".to_string()
        };

        // `match.start()` — byte offset (== char index for ASCII Solidity).
        let start_idx = caps.get(0).unwrap().start();
        // `solidity_code[:start_idx].count('\n') + 1`
        let start_line = solidity_code[..start_idx].matches('\n').count() + 1;

        // `solidity_code.find(';', start_idx)` / `.find('{', start_idx)`
        let semicolon_idx = solidity_code[start_idx..].find(';').map(|p| start_idx + p);
        let brace_idx = solidity_code[start_idx..].find('{').map(|p| start_idx + p);

        // `if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue`
        let brace_idx = match brace_idx {
            None => continue,
            Some(b) => {
                if let Some(s) = semicolon_idx {
                    if s < b {
                        continue;
                    }
                }
                b
            }
        };

        // Brace-balance scan over bytes (ASCII `{`/`}` are single bytes).
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
            let func_body = solidity_code[start_idx..curr_idx].to_string();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

pub fn audit_gas(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    for (func_name, func_body, start_line) in &functions {
        // cleaned_body = re.sub(r'//.*', '', func_body)
        let cleaned_body = LINE_COMMENT.replace_all(func_body, "");
        // cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)
        let cleaned_body = BLOCK_COMMENT.replace_all(&cleaned_body, "").to_string();

        // Mode 1: Unbounded Loop Check.
        if cleaned_body.contains("for") || cleaned_body.contains("while") {
            let length_match = LENGTH_LOOKUP.is_match(&cleaned_body);
            if length_match
                && !cleaned_body.contains("length =")
                && !cleaned_body.contains("len =")
            {
                vulnerable_funcs.push(func_name.clone());
                flagged_findings.push(format!(
                    "Function '{func_name}' on Line {start_line} contains a loop over a dynamic array's .length \
without caching it in memory. This wastes gas on each iteration and risks Out-Of-Gas block limits."
                ));
            }
        }

        // Mode 2: Gas Optimizations (Storage reads in loops).
        if cleaned_body.contains("for") || cleaned_body.contains("while") {
            if cleaned_body.matches("memory").count() == 0
                && cleaned_body.matches("calldata").count() == 0
                && STORAGE_VAR.is_match(&cleaned_body)
            {
                flagged_findings.push(format!(
                    "Gas Optimization: Function '{func_name}' on Line {start_line} contains a loop with potential direct \
storage variables access. Consider caching storage variables in memory before the loop."
                ));
            }
        }

        // memory instead of calldata for read-only arrays.
        if cleaned_body.contains("[] memory") {
            flagged_findings.push(format!(
                "Gas Optimization: Function '{func_name}' on Line {start_line} uses 'memory' instead of 'calldata' \
for an input array parameter. Declaring input parameters as 'calldata' is more gas-efficient."
            ));
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_GAS_RISK".to_string();
        } else {
            status = "WARN_GAS_RISK".to_string();
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
    let out = audit_gas(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        // Avoid env-var leakage from sibling tests.
        std::env::remove_var("PI_GAS_STRICT_MODE");
        audit_gas(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_contract_passes() {
        let code = "contract C {\n  function f() public {\n    uint256 len = a.length;\n    for (uint i = 0; i < len; i++) { x += 1; }\n  }\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn unbounded_loop_rejected_strict() {
        std::env::remove_var("PI_GAS_STRICT_MODE");
        let code = "contract C {\n  function f() public {\n    for (uint i = 0; i < users.length; i++) { total += users[i]; }\n  }\n}";
        let o = audit_gas(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        });
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_GAS_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["f"]);
    }

    #[test]
    #[serial]
    fn unbounded_loop_warn_when_not_strict() {
        std::env::set_var("PI_GAS_STRICT_MODE", "false");
        let o = audit_gas(&Input {
            file_path: "C.sol".into(),
            solidity_code: "contract C {\n  function f() public {\n    for (uint i; i < users.length; i++) {}\n  }\n}".into(),
            check_level: "STRICT".into(),
        });
        std::env::remove_var("PI_GAS_STRICT_MODE");
        // Non-strict: is_secure coerced back to True, status WARN.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_GAS_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["f"]);
    }

    #[test]
    #[serial]
    fn memory_array_param_flagged() {
        let o = run("contract C {\n  function f(uint[] memory data) public {}\n}");
        // memory param only -> finding present, but no vulnerable funcs -> secure.
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("'memory' instead of 'calldata'"));
    }
}
