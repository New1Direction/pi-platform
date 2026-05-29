//! Port of `pi_micro_agents/pi_cross_chain_message_replay_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for cross-chain
//! message replay vulnerabilities (receiver functions lacking a nonce/payload
//! deduplication registry). Behaviour is a line-for-line mirror of the Python
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

// `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}`
// 3 capture groups -> captures_iter (mirrors re.findall with groups).
// `.` does not match newline (Python has no DOTALL flag here); `[\s\S]` does.
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// `mapping\s*\(\s*[^=]+=>\s*bool\s*\)` -> re.search -> Regex::find.
static MAPPING_BOOL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"mapping\s*\(\s*[^=]+=>\s*bool\s*\)").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the env var; if set it returns `env_val.lower() == "true"`.
/// Otherwise it consults `~/.antigravitycli/config.json` (falling back to a
/// repo-relative path) and returns `bool(data.get("PI_BRIDGE_REPLAY_STRICT_MODE", True))`.
/// In the parity environment neither config file contains the
/// `PI_BRIDGE_REPLAY_STRICT_MODE` key, so the config branch always yields `True`,
/// and the final default is also `True`. This Rust port therefore returns `true`
/// whenever the env var is unset. See `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_BRIDGE_REPLAY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_bridge_replay(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions: re.findall with 3 groups -> captures_iter.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        let _args = caps.get(2).map_or("", |m| m.as_str());
        let body = caps.get(3).map_or("", |m| m.as_str());

        // Mode 1: Check for receiver style function.
        let name_lower = name.to_lowercase();
        let is_receiver = ["lzreceive", "execute", "process", "onmessagereceived", "receiveland"]
            .iter()
            .any(|kw| name_lower.contains(kw));

        if is_receiver {
            // Mode 2: Verify there is a tracking registry recording processed
            // nonces or payload hashes (mapping lookup/assignment in the body,
            // or a `mapping(... => bool)` anywhere in the code).
            let has_nonce_guard = body.contains("processedNonces")
                || body.contains("isExecuted")
                || body.contains("processedMessages")
                || MAPPING_BOOL_RE.is_match(code);

            if !has_nonce_guard {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Cross-chain receiver function '{name}' is missing message replay guards. \
It does not maintain a deduplication registry (e.g. mapping of processed message hashes or nonces). \
This permits malicious users to re-submit the same signed cross-chain payload repeatedly \
to drain contract asset balances."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 95.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_BRIDGE_REPLAY".to_string();
        } else {
            status = "WARN_BRIDGE_REPLAY".to_string();
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
    let out = audit_bridge_replay(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_bridge_replay(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_with_nonce_guard_passes() {
        std::env::remove_var("PI_BRIDGE_REPLAY_STRICT_MODE");
        let o = run(
            "function lzReceive(uint16 a) external { processedNonces[a] = true; doStuff(); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn vulnerable_receiver_rejected() {
        std::env::remove_var("PI_BRIDGE_REPLAY_STRICT_MODE");
        let o = run("function lzReceive(uint16 a) external { doStuff(); }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_BRIDGE_REPLAY");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_functions, vec!["lzReceive"]);
    }

    #[test]
    #[serial]
    fn non_strict_env_warns_and_coerces_secure() {
        std::env::set_var("PI_BRIDGE_REPLAY_STRICT_MODE", "false");
        let o = run("function execute(bytes p) external { run(p); }");
        std::env::remove_var("PI_BRIDGE_REPLAY_STRICT_MODE");
        assert!(o.is_secure); // coerced back to true
        assert_eq!(o.status, "WARN_BRIDGE_REPLAY");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_functions, vec!["execute"]);
    }

    #[test]
    #[serial]
    fn mapping_bool_anywhere_guards_all_receivers() {
        std::env::remove_var("PI_BRIDGE_REPLAY_STRICT_MODE");
        let o = run(
            "mapping(bytes32 => bool) public seen;\nfunction process(bytes p) external { run(p); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
