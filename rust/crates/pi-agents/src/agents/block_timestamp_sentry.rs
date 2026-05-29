//! Port of `pi_micro_agents/pi_block_timestamp_sentry.py`.
//!
//! Audits Solidity contracts for `block.timestamp`/`now` reliance (pseudo-random
//! entropy) and EIP-4337 expiration / timelock comparison safety. Behaviour is a
//! line-for-line mirror of the Python original.

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

// Python: re.compile(r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(')
// No lookaround / backrefs -> directly supported by the `regex` crate.
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// Python: re.sub(r'//.*', '', func_body)  ('.' does not match '\n' -> per-line removal)
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// Python: re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE (deviation): the Python original additionally falls back to reading
/// `~/.antigravitycli/config.json` (then a repo-relative copy) when the env var
/// is unset, returning `bool(data.get("PI_TIMESTAMP_STRICT_MODE", True))`, else
/// `True`. This port only honours the env var and otherwise defaults to `True`,
/// matching the Python default when no config file overrides the key.
fn is_strict_mode() -> bool {
    match std::env::var("PI_TIMESTAMP_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `extract_solidity_functions`: returns `(func_name, func_body, start_line)`.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, i64)> {
    let mut functions: Vec<(String, String, i64)> = Vec::new();
    let bytes = solidity_code.as_bytes();
    let code_len = bytes.len();

    for m in FUNC_RE.captures_iter(solidity_code) {
        let keyword = m.get(1).map(|g| g.as_str()).unwrap_or("");
        let name = m.get(2).map(|g| g.as_str()).unwrap_or("");
        let func_name: String = if keyword == "function" {
            name.to_string()
        } else if keyword == "constructor" {
            "constructor".to_string()
        } else if keyword == "fallback" {
            "fallback".to_string()
        } else {
            "receive".to_string()
        };

        let start_idx = m.get(0).unwrap().start();
        // Python: solidity_code[:start_idx].count('\n') + 1
        let start_line = (solidity_code[..start_idx].matches('\n').count() as i64) + 1;

        // Python: solidity_code.find(';', start_idx) / .find('{', start_idx)
        // -> first occurrence at byte index >= start_idx, or -1.
        let semicolon_idx: i64 = find_byte_from(bytes, b';', start_idx);
        let brace_idx: i64 = find_byte_from(bytes, b'{', start_idx);

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue
        if brace_idx == -1 || (semicolon_idx != -1 && semicolon_idx < brace_idx) {
            continue;
        }

        let brace_idx_u = brace_idx as usize;
        let mut brace_count: i64 = 1;
        let mut curr_idx = brace_idx_u + 1;
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
            // Python: solidity_code[start_idx:curr_idx]
            let func_body = solidity_code[start_idx..curr_idx].to_string();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

/// Index of the first occurrence of `needle` at byte position >= `from`, else -1.
/// Mirrors Python `str.find(ch, start)` semantics for the ASCII delimiters used here.
fn find_byte_from(bytes: &[u8], needle: u8, from: usize) -> i64 {
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == needle {
            return i as i64;
        }
        i += 1;
    }
    -1
}

pub fn audit_timestamp(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    for (func_name, func_body, start_line) in functions.iter() {
        // Clean comments
        let cleaned_body = LINE_COMMENT_RE.replace_all(func_body, "");
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "");
        let cleaned_body: &str = &cleaned_body;

        // Mode 1: Timestamp Reliance Check (Randomness generation, etc.)
        if cleaned_body.contains("block.timestamp") || cleaned_body.contains("now") {
            // Flag if used in keccak256 or random-like expressions or modulo
            if cleaned_body.contains('%')
                || cleaned_body.contains("keccak256(")
                || cleaned_body.to_lowercase().contains("random")
            {
                vulnerable_funcs.push(func_name.clone());
                flagged_findings.push(format!(
                    "Function '{func_name}' on Line {start_line} relies on 'block.timestamp' for pseudo-randomness \
or entropy. Miners can manipulate timestamps within certain bounds, leading to exploitable randomness."
                ));
            }
            // Mode 2: EIP-4337 Expiration Validation / Timelocks
            // Check if there are inequality checks but recommend standard time variance guards
            else if cleaned_body.contains('<') || cleaned_body.contains('>') {
                // Verify if a standard margin or grace period exists
                let has_margin = ["day", "hour", "week", "86400", "3600"]
                    .iter()
                    .any(|margin| cleaned_body.contains(margin));
                if !has_margin {
                    flagged_findings.push(format!(
                        "Expiration warning: Function '{func_name}' on Line {start_line} compares 'block.timestamp' \
without using standard explicit time constants (like days, hours, or seconds margins), \
which can lead to precise deadline mismatch issues under varying network block congestion."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_TIMESTAMP_VULNERABILITY".to_string();
        } else {
            status = "WARN_TIMESTAMP_VULNERABILITY".to_string();
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
    let out = audit_timestamp(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_timestamp(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_contract_passes() {
        std::env::remove_var("PI_TIMESTAMP_STRICT_MODE");
        let o = run("contract C { function f() public { uint x = 1; } }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    #[serial]
    fn timestamp_randomness_rejected_in_strict() {
        std::env::set_var("PI_TIMESTAMP_STRICT_MODE", "true");
        let o = run(
            "contract C { function rng() public { uint r = uint(keccak256(abi.encodePacked(block.timestamp))) % 100; } }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TIMESTAMP_VULNERABILITY");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["rng"]);
        std::env::remove_var("PI_TIMESTAMP_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn timestamp_randomness_warns_in_lenient() {
        std::env::set_var("PI_TIMESTAMP_STRICT_MODE", "false");
        let o = run(
            "contract C { function rng() public { uint r = uint(keccak256(abi.encodePacked(block.timestamp))) % 100; } }",
        );
        // lenient mode coerces is_secure back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_TIMESTAMP_VULNERABILITY");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["rng"]);
        std::env::remove_var("PI_TIMESTAMP_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn expiration_warning_without_margin() {
        std::env::remove_var("PI_TIMESTAMP_STRICT_MODE");
        let o = run("contract C { function check() public { require(block.timestamp < deadline); } }");
        // expiration warnings do not mark a function vulnerable
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.vulnerable_functions.len(), 0);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].starts_with("Expiration warning:"));
    }
}
