//! Port of `pi_micro_agents/pi_solidity_yul_memory_offset_audit.py`.
//!
//! Audits Yul inline assembly for risky memory writes that overwrite the free
//! memory pointer at offset `0x40`. Behaviour is a line-for-line mirror of the
//! Python original.

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

/// Mirrors `is_strict_mode()`: when the env var is set, strict iff it equals
/// (case-insensitively) "true"; when unset, default to strict (True).
fn is_strict_mode() -> bool {
    match std::env::var("PI_YUL_MEMORY_OFFSET_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`
// 3 capture groups -> captures_iter. `.` does NOT match newlines (no DOTALL),
// matching Python's default; `[\s\S]` matches everything including newlines.
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// `re.findall(r'mstore\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*.*?\)', body)`
// 1 capture group -> captures_iter yields the group. `.` does not match newline.
static MSTORE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"mstore\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*.*?\)").unwrap());

pub fn audit_yul_memory(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions.
    for caps in FUNC_RE.captures_iter(code) {
        let name = &caps[1];
        let _args = &caps[2];
        let body = &caps[3];

        // Check if there is an assembly block.
        if body.contains("assembly") {
            // Find all mstore operations in assembly.
            for mcaps in MSTORE_RE.captures_iter(body) {
                let offset_str = &mcaps[1];
                // Convert hex or decimal offset. The regex guarantees valid
                // digits, so parsing never fails (mirrors the try/except which
                // would only swallow a ValueError that cannot occur here).
                let offset: Option<i64> = if offset_str.contains("0x") {
                    i64::from_str_radix(offset_str.trim_start_matches("0x"), 16).ok()
                } else {
                    offset_str.parse::<i64>().ok()
                };
                if let Some(offset) = offset {
                    // Writing directly to 0x40 (overwriting the free memory pointer itself!)
                    if offset == 0x40 {
                        vulnerable_funcs.push(name.to_string());
                        flagged_findings.push(format!(
                            "Function '{name}' overwrites the free memory pointer at offset '0x40' directly inside Yul assembly. \
Modifying the free memory pointer offset without reallocation protocol can corrupt the EVM memory heap, leading to critical logic errors or access control bypasses."
                        ));
                        break;
                    }
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
            status = "REJECTED_YUL_MEMORY_OFFSET".to_string();
        } else {
            status = "WARN_YUL_MEMORY_OFFSET".to_string();
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
    let out = audit_yul_memory(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_yul_memory(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_code_passes() {
        let o = run("function foo() public { uint x = 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn assembly_scratch_pad_is_ok() {
        // mstore to 0x00 scratch space is not flagged.
        let o = run("function h() internal { assembly { mstore(0x00, 1) } }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn overwrites_free_memory_pointer_is_rejected() {
        let o = run("function bad() public { assembly { mstore(0x40, 0x80) } }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_YUL_MEMORY_OFFSET");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
    }
}
