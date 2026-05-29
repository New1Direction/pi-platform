//! Port of `pi_micro_agents/pi_eip712_signature_linter.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for EIP-712
//! signature verification flaws (missing `block.chainid` / dynamic
//! `DOMAIN_SEPARATOR`, exposing signature checks to cross-chain replays).
//! Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Pydantic `EIP712LinterInput`.
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

/// Pydantic `EIP712LinterOutput`.
#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_functions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors the Python function-block scanner:
/// `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}`.
///
/// No lookaround / backreferences are used, so this translates 1:1 to the
/// Rust `regex` crate. `(.*?)` (args) is non-greedy and `.` does not match
/// newlines in either engine by default; `[\s\S]*?` (body) matches everything
/// including newlines, non-greedily — identical semantics.
static FUNC_BLOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the env var `PI_EIP712_LINTER_STRICT_MODE`: if set,
/// returns `value.lower() == "true"`. If unset, it falls back to a
/// `~/.antigravitycli/config.json` config file (or a module-relative
/// `../../.antigravitycli/config.json`), returning
/// `bool(data.get("PI_EIP712_LINTER_STRICT_MODE", True))` — i.e. defaulting to
/// `True` when the file is absent / unreadable / missing the key. The repo
/// config file present at port time does NOT contain
/// `PI_EIP712_LINTER_STRICT_MODE`, so the Python fallback resolves to `True`.
/// We mirror the env-var branch exactly and default to `true` when the env var
/// is unset, matching the Python default. See module `deviations` notes.
fn is_strict_mode() -> bool {
    match std::env::var("PI_EIP712_LINTER_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_signature_linter(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions. `re.findall` with 3 groups -> captures_iter, taking
    // groups (name, args, body). `args` is captured but unused, mirroring the
    // Python loop variable binding.
    for caps in FUNC_BLOCK.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Check if function performs signature verification / ecrecover /
        // ECDSA.recover. ("ecrecover" in body or "recover" in body)
        if body.contains("ecrecover") || body.contains("recover") {
            // Check for dynamic domain separator inclusion (should contain
            // block.chainid or similar dynamic elements).
            let has_chainid = body.contains("chainid")
                || body.contains("DOMAIN_SEPARATOR")
                || code.contains("chainid");
            if !has_chainid {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' processes signature verification but does not appear to incorporate \
block.chainid or a dynamic DOMAIN_SEPARATOR. This exposes signature validation to cross-chain replays."
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
            status = "REJECTED_EIP712_RISK".to_string();
        } else {
            status = "WARN_EIP712_RISK".to_string();
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
    let out = audit_signature_linter(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        std::env::remove_var("PI_EIP712_LINTER_STRICT_MODE");
        audit_signature_linter(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_with_chainid_passes() {
        // ecrecover present, but body has chainid -> not vulnerable.
        let o = run(
            "function verify(bytes32 h) public { bytes32 ds = block.chainid; address a = ecrecover(h, 27, ds, ds); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn missing_chainid_flagged_rejected() {
        let o = run(
            "function verify(bytes32 h, uint8 v) public { address a = ecrecover(h, v, h, h); require(a == owner); }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_EIP712_RISK");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["verify"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    fn chainid_anywhere_in_code_suppresses_flag() {
        // The vulnerable function lacks chainid in its body, but a second
        // function mentions chainid; `"chainid" in code` suppresses the flag.
        let o = run(
            "function a(bytes32 h) public { address x = ecrecover(h, 1, h, h); } \
function b() public { uint c = block.chainid; }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn no_signature_logic_passes() {
        let o = run("function add(uint a, uint b) public returns (uint) { return a + b; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn recover_substring_flagged() {
        // Bare "recover" substring (e.g. ECDSA.recover) triggers the check.
        let o = run("function claim(bytes32 h, bytes memory s) public { address a = ECDSA.recover(h, s); }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_EIP712_RISK");
        assert_eq!(o.vulnerable_functions, vec!["claim"]);
    }
}
