//! Port of `pi_micro_agents/pi_solidity_signature_omitted_replay_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits EIP-712 hash calculation functions
//! for omitting nonces or `block.chainid` parameters, creating signature replay
//! vulnerabilities. Behaviour is a line-for-line mirror of the Python original.

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
fn is_strict_mode() -> bool {
    match std::env::var("PI_SIGNATURE_OMITTED_REPLAY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Python: re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// Three capture groups: name, args, body. No lookaround/backreferences, so the
// pattern ports directly. `[\s\S]` explicitly spans newlines; `.*?` does not
// (matching Python's default `.` semantics here, since there is no DOTALL flag).
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

pub fn audit_signature_replay(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Look for keccak256 hashing associated with signatures
        let name_lower = name.to_lowercase();
        if body.contains("keccak256")
            && (body.contains("abi.encode") || body.contains("abi.encodePacked"))
            && (name_lower.contains("signature")
                || name_lower.contains("hash")
                || name_lower.contains("permit")
                || name_lower.contains("verify"))
        {
            // Check if it includes block.chainid or chainid
            let has_chainid = body.contains("chainid") || body.contains("block.chainid");
            // Check if it includes nonce or nonces
            let has_nonce = body.contains("nonce") || body.contains("nonces");

            if !has_chainid || !has_nonce {
                let mut missing_elements: Vec<&str> = Vec::new();
                if !has_chainid {
                    missing_elements.push("block.chainid");
                }
                if !has_nonce {
                    missing_elements.push("nonce");
                }

                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{}' hashes parameters for signature verification but lacks {}. \
Omitting chainid allows signature replay across different forks or EVM chains. \
Omitting nonces allows double-spending/execution replay within the same contract.",
                    name,
                    missing_elements.join(", ")
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SIGNATURE_OMITTED_REPLAY".to_string();
        } else {
            status = "WARN_SIGNATURE_OMITTED_REPLAY".to_string();
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
    let out = audit_signature_replay(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_signature_replay(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_function_passes() {
        // Includes both chainid and nonce -> secure.
        let o = run(
            "function hashOrder(uint256 amount) public { \
bytes32 h = keccak256(abi.encode(amount, nonce, block.chainid)); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn missing_both_flagged() {
        let o = run(
            "function permitHash(uint256 amount) public { \
bytes32 h = keccak256(abi.encode(amount)); }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SIGNATURE_OMITTED_REPLAY");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["permitHash"]);
        assert!(o.flagged_findings[0].contains("lacks block.chainid, nonce"));
    }

    #[test]
    fn missing_only_chainid_flagged() {
        let o = run(
            "function verifySig(bytes sig) public { \
bytes32 h = keccak256(abi.encodePacked(sig, nonce)); }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["verifySig"]);
        assert!(o.flagged_findings[0].contains("lacks block.chainid."));
    }
}
