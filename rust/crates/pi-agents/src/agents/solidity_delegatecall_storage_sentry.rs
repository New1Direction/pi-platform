//! Port of `pi_micro_agents/pi_solidity_delegatecall_storage_sentry.py`.
//!
//! Audits proxy contracts for Yul `delegatecall` implementations that load the
//! target address from a non-standard (non EIP-1967) storage slot, or that lack
//! any clear slot-loading pattern. Behaviour is a line-for-line mirror of the
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

// `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`
// 3 capture groups -> captures_iter. Note `.*?` does not span newlines in Python's
// default mode (nor does Rust's `.`), while `[\s\S]*?` spans everything in both.
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// `re.search(r'sload\s*\(\s*(0x[a-fA-F0-9]+|[a-zA-Z0-9_]+)\s*\)', body)`
// 1 capture group -> captures.
static SLOAD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sload\s*\(\s*(0x[a-fA-F0-9]+|[a-zA-Z0-9_]+)\s*\)").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Faithful for the env-var branch (which all parity samples exercise). When the
/// env var is unset, Python additionally consults a JSON config file
/// (`~/.antigravitycli/config.json`, then `src/.antigravitycli/config.json`),
/// returning `bool(data.get("PI_DELEGATECALL_STORAGE_STRICT_MODE", True))` if
/// found and `True` otherwise. We replicate only the final default (`True`); see
/// the parity deviations note for the config-file fallback.
fn is_strict_mode() -> bool {
    match std::env::var("PI_DELEGATECALL_STORAGE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_delegatecall_storage(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions. captures: group(1)=name, group(2)=args, group(3)=body.
    for caps in FUNC_RE.captures_iter(code) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        let _args = caps.get(2).map_or("", |m| m.as_str());
        let body = caps.get(3).map_or("", |m| m.as_str());

        // Check if delegatecall is used inside assembly.
        if body.contains("assembly") && body.contains("delegatecall") {
            // Look for target loaded using sload.
            if let Some(sload_caps) = SLOAD_RE.captures(body) {
                let slot = sload_caps.get(1).map_or("", |m| m.as_str());
                // EIP-1967 standard slots.
                let eip1967_slots = [
                    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                    "0xa3f0ad74a5890d8e115a428731304671291891c9d44342144a0b228226348149",
                    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
                ];
                if !eip1967_slots.contains(&slot) {
                    vulnerable_funcs.push(name.to_string());
                    flagged_findings.push(format!(
                        "Function '{name}' performs a delegatecall where the target implementation \
address is loaded from non-standard storage slot '{slot}'. \
Proxy implementation targets should be saved in standard EIP-1967 constant slots \
to mitigate the risk of storage layout collision and unintended state overwrites."
                    ));
                }
            } else {
                // delegatecall used without apparent slot verification.
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' contains a delegatecall instruction in inline assembly but \
does not show clear EIP-1967 storage slot loading patterns for the implementation target."
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
            status = "REJECTED_DELEGATECALL_STORAGE".to_string();
        } else {
            status = "WARN_DELEGATECALL_STORAGE".to_string();
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
    let out = audit_delegatecall_storage(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_delegatecall_storage(&Input {
            file_path: "Proxy.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn standard_eip1967_slot_passes() {
        std::env::remove_var("PI_DELEGATECALL_STORAGE_STRICT_MODE");
        let code = "function _fallback() internal { assembly { let impl := \
sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc) \
let r := delegatecall(gas(), impl, 0, 0, 0, 0) } }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn non_standard_slot_flagged() {
        std::env::remove_var("PI_DELEGATECALL_STORAGE_STRICT_MODE");
        let code = "function _delegate() internal { assembly { let impl := sload(0x1234) \
let r := delegatecall(gas(), impl, 0, 0, 0, 0) } }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DELEGATECALL_STORAGE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["_delegate"]);
    }

    #[test]
    #[serial]
    fn no_slot_pattern_warns_when_not_strict() {
        std::env::set_var("PI_DELEGATECALL_STORAGE_STRICT_MODE", "false");
        let code = "function run() public { assembly { let r := delegatecall(gas(), \
addr, 0, 0, 0, 0) } }";
        let o = run(code);
        // not strict -> WARN, is_secure coerced back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_DELEGATECALL_STORAGE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["run"]);
        std::env::remove_var("PI_DELEGATECALL_STORAGE_STRICT_MODE");
    }
}
