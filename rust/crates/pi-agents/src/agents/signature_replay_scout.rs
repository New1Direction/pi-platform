//! Port of `pi_micro_agents/pi_signature_replay_scout.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for signature
//! replay vulnerabilities and EIP-712 compliance. Behaviour is a line-for-line
//! mirror of the Python original (`PiSignatureReplayScout.audit_signature`).

use crate::pyutil;
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

/// Mirrors `is_strict_mode()`: the env var, if present, wins
/// (`"true"` case-insensitively => strict). When the env var is absent the
/// Python fallback consults `~/.antigravitycli/config.json` and otherwise
/// returns `True`; both fallback branches default to strict, so this mirrors
/// the absent-env-var case as strict. NOTE: the config.json fallback is not
/// reproduced (see deviations).
fn is_strict_mode() -> bool {
    match std::env::var("PI_SIGNATURE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// `//.*`  -> line comment up to (but not including) a newline. In both Python
// (no DOTALL) and Rust (no `(?s)`), `.` does not match `\n`.
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());
// `/\*.*?\*/` with re.DOTALL -> `(?s)` so `.` matches newlines too.
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());
// `\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(`
static FUNC_DECL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

/// Mirror of `extract_solidity_functions`. Returns `(func_name, func_body, start_line)`.
///
/// Python indexes/slices on Unicode code points, while the `regex` crate yields
/// byte offsets. We therefore work over a `Vec<char>` and translate the regex
/// byte offsets to char offsets so all slicing/`find` semantics match Python.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, i64)> {
    let mut functions: Vec<(String, String, i64)> = Vec::new();

    let chars: Vec<char> = solidity_code.chars().collect();
    let code_len = chars.len();

    // Map byte offset -> char index for converting regex match positions.
    let byte_to_char: std::collections::HashMap<usize, usize> = solidity_code
        .char_indices()
        .enumerate()
        .map(|(ci, (bpos, _))| (bpos, ci))
        .collect();

    for caps in FUNC_DECL_RE.captures_iter(solidity_code) {
        let m0 = caps.get(0).unwrap();
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

        // start_idx = match.start() (char index in Python)
        let start_idx = *byte_to_char
            .get(&m0.start())
            .expect("regex match start aligns with a char boundary");

        // start_line = solidity_code[:start_idx].count('\n') + 1
        let start_line: i64 =
            chars[..start_idx].iter().filter(|&&c| c == '\n').count() as i64 + 1;

        // semicolon_idx = solidity_code.find(';', start_idx)  (-1 if not found)
        let semicolon_idx: i64 = chars[start_idx..]
            .iter()
            .position(|&c| c == ';')
            .map(|p| (start_idx + p) as i64)
            .unwrap_or(-1);
        // brace_idx = solidity_code.find('{', start_idx)  (-1 if not found)
        let brace_idx: i64 = chars[start_idx..]
            .iter()
            .position(|&c| c == '{')
            .map(|p| (start_idx + p) as i64)
            .unwrap_or(-1);

        if brace_idx == -1 || (semicolon_idx != -1 && semicolon_idx < brace_idx) {
            continue;
        }

        // Brace matching to find full function block body.
        let mut brace_count: i64 = 1;
        let mut curr_idx: usize = (brace_idx as usize) + 1;
        while curr_idx < code_len && brace_count > 0 {
            let ch = chars[curr_idx];
            if ch == '{' {
                brace_count += 1;
            } else if ch == '}' {
                brace_count -= 1;
            }
            curr_idx += 1;
        }

        if brace_count == 0 {
            let func_body: String = chars[start_idx..curr_idx].iter().collect();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

pub fn audit_signature(input: &Input) -> Output {
    let code = &input.solidity_code;

    // Clean comments to avoid false positives in global analysis.
    let code_clean = LINE_COMMENT_RE.replace_all(code, "");
    let code_clean = BLOCK_COMMENT_RE.replace_all(&code_clean, "");

    let functions = extract_solidity_functions(code);

    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Check globally if DOMAIN_SEPARATOR is defined.
    let has_domain_separator = code_clean.to_lowercase().contains("domain_separator");

    for (func_name, func_body, start_line) in &functions {
        if func_name == "constructor" {
            continue;
        }

        // Clean comments for this function body.
        let cleaned_body = LINE_COMMENT_RE.replace_all(func_body, "");
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "");

        let body_lower = cleaned_body.to_lowercase();

        // Check if signature recovery is performed.
        let has_recovery =
            body_lower.contains("ecrecover(") || body_lower.contains("ecdsa.recover(");

        if has_recovery {
            // EIP-712 referenced via DOMAIN_SEPARATOR -> safe/compliant (Mode 1).
            if has_domain_separator {
                continue;
            }

            // Check for nonce tracking or chainId tracking in the function body.
            let has_nonce = body_lower.contains("nonce");
            let has_chainid = body_lower.contains("chainid");

            if has_nonce || has_chainid {
                continue;
            }

            // Otherwise, possibly vulnerable to replay attacks (Mode 2).
            let lines = pyutil::splitlines(&cleaned_body);
            for (offset, line) in lines.into_iter().enumerate() {
                let line_num = start_line + offset as i64;
                let stripped = pyutil::strip(line);
                let stripped_lower = stripped.to_lowercase();
                if stripped_lower.contains("ecrecover(") || stripped_lower.contains("ecdsa.recover(")
                {
                    if !vulnerable_funcs.contains(func_name) {
                        vulnerable_funcs.push(func_name.clone());
                    }

                    flagged_findings.push(format!(
                        "Function '{func_name}' recovers signature on Line {line_num}: '{stripped}' \
without references to EIP-712 structured data hashing (DOMAIN_SEPARATOR) \
or nonces/chainId replay tracking mechanisms."
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
            status = "REJECTED_SIGNATURE_REPLAY_VULNERABILITY".to_string();
        } else {
            status = "WARN_SIGNATURE_REPLAY_VULNERABILITY".to_string();
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
    let out = audit_signature(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_signature(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn vulnerable_ecrecover_without_protection_rejected() {
        std::env::remove_var("PI_SIGNATURE_STRICT_MODE");
        let code = "contract C {\n  function claim(bytes sig) public {\n    address s = ecrecover(h, v, r, ss);\n  }\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SIGNATURE_REPLAY_VULNERABILITY");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_functions, vec!["claim"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    #[serial]
    fn nonce_protected_passes() {
        std::env::remove_var("PI_SIGNATURE_STRICT_MODE");
        let code = "contract C {\n  function claim(bytes sig) public {\n    require(nonce == used);\n    address s = ecrecover(h, v, r, ss);\n  }\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn non_strict_env_warns_and_coerces_secure() {
        std::env::set_var("PI_SIGNATURE_STRICT_MODE", "false");
        let code = "contract C {\n  function claim(bytes sig) public {\n    address s = ecrecover(h, v, r, ss);\n  }\n}";
        let o = run(code);
        assert!(o.is_secure); // coerced back to true in warn mode
        assert_eq!(o.status, "WARN_SIGNATURE_REPLAY_VULNERABILITY");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_functions, vec!["claim"]);
        std::env::remove_var("PI_SIGNATURE_STRICT_MODE");
    }
}
