//! Port of `pi_micro_agents/pi_solidity_dirty_memory_sentry.py`.
//!
//! Specialized Yul / inline assembly micro-agent that audits Solidity
//! contracts for memory safety and dirty memory overwrites. Behaviour is a
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

// `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`
//
// Python default (no DOTALL): `.` does not match `\n`, so `(.*?)` (group 2) is
// single-line; `[\s\S]` matches any char including newlines for the body. The
// Rust `regex` crate has the same default for `.`, so this pattern is a direct
// translation. 3 capture groups -> captures_iter.
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// `re.search(r'mstore\s*\(\s*(0x[89a-fA-F0-9]{2,}|1[2-9]\d|\d{3,})\s*,', body)`
// No lookaround/backrefs -> direct translation. Only the boolean presence is
// used by the Python logic, so a `find`/`is_match` suffices.
static WRITES_ABSOLUTE_DYNAMIC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"mstore\s*\(\s*(0x[89a-fA-F0-9]{2,}|1[2-9]\d|\d{3,})\s*,").unwrap()
});

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: the Python original additionally falls back to a
/// `~/.antigravitycli/config.json` file (defaulting to strict) when the env var
/// is unset. That filesystem fallback is intentionally NOT replicated here (it
/// is non-deterministic across machines); like the other ported sentries we
/// default to strict when the env var is absent. See parity deviations.
fn is_strict_mode() -> bool {
    match std::env::var("PI_DIRTY_MEMORY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_dirty_memory(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // group 2 (args) is captured by the regex but unused by the logic.
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        if body.contains("assembly") && body.contains("mstore") {
            // Check if it writes to dynamic memory offsets (above 0x80) without
            // reading the free memory pointer (0x40).
            let has_free_mem_load = body.replace(' ', "").contains("mload(0x40)");

            // Check for direct writes above the scratch space / zero slot
            // absolute boundary without free memory load.
            let writes_absolute_dynamic = WRITES_ABSOLUTE_DYNAMIC_RE.is_match(body);

            if writes_absolute_dynamic && !has_free_mem_load {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' writes directly to absolute memory offset in assembly \
without loading the Solidity free memory pointer via 'mload(0x40)'. \
This violates Solidity's memory safety rules and can lead to dynamic memory corruption or overwriting active data struct layouts."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_DIRTY_MEMORY".to_string();
        } else {
            status = "WARN_DIRTY_MEMORY".to_string();
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
    let out = audit_dirty_memory(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_dirty_memory(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_code_passes() {
        std::env::remove_var("PI_DIRTY_MEMORY_STRICT_MODE");
        // assembly + mstore but loads the free memory pointer -> safe.
        let o = run("function safe() public { assembly { let p := mload(0x40) mstore(0x80, 1) } }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn dirty_write_rejected_in_strict() {
        std::env::set_var("PI_DIRTY_MEMORY_STRICT_MODE", "true");
        // mstore to absolute 0x80 with no mload(0x40) -> vulnerable.
        let o = run("function bad() public { assembly { mstore(0x80, 1) } }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DIRTY_MEMORY");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
    }

    #[test]
    #[serial]
    fn dirty_write_warns_when_not_strict() {
        std::env::set_var("PI_DIRTY_MEMORY_STRICT_MODE", "false");
        let o = run("function bad() public { assembly { mstore(128, 1) } }");
        // is_secure coerced back to true in WARN path.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_DIRTY_MEMORY");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
        std::env::remove_var("PI_DIRTY_MEMORY_STRICT_MODE");
    }
}
