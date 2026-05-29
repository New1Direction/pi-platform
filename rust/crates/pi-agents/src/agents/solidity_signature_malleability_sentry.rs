//! Port of `pi_micro_agents/pi_solidity_signature_malleability_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for `ecrecover`
//! ECDSA signature malleability vulnerabilities (raw `ecrecover` used without
//! validating that the `s` value sits in the lower half range, allowing
//! malleable signature variants to bypass replay checks). Behaviour is a
//! line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Pydantic `SignatureMalleabilityInput`.
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

/// Pydantic `SignatureMalleabilityOutput`.
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
static FUNC_BLOCK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the env var `PI_SIGNATURE_MALLEABILITY_STRICT_MODE`: if
/// set, returns `value.lower() == "true"`. If unset, it falls back to a
/// `~/.antigravitycli/config.json` config file (or a module-relative
/// `../../.antigravitycli/config.json`), returning
/// `bool(data.get("PI_SIGNATURE_MALLEABILITY_STRICT_MODE", True))` — i.e.
/// defaulting to `True` when the file is absent / unreadable / missing the key.
/// We mirror the env-var branch exactly and default to `true` when the env var
/// is unset, matching the Python default for the common (no relevant config)
/// case. See module `deviations` notes.
fn is_strict_mode() -> bool {
    match std::env::var("PI_SIGNATURE_MALLEABILITY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_signature_malleability(input: &Input) -> Output {
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

        // Check if ecrecover is used directly.
        if body.contains("ecrecover") {
            // Check if it uses OpenZeppelin ECDSA library or checks for high s.
            let uses_safe_library =
                body.contains("ECDSA.recover") || code.contains("using ECDSA for");
            let checks_s_value = body
                .contains("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
                || body.contains(
                    "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                );

            if !(uses_safe_library || checks_s_value) {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' utilizes raw 'ecrecover' directly without validation for signature malleability. \
Without checking that the 's' value is in the lower half range (<= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0), \
an attacker can craft a malleable signature variant that bypasses replay checks."
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
            status = "REJECTED_MALLEABLE_SIG".to_string();
        } else {
            status = "WARN_MALLEABLE_SIG".to_string();
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
    let out = audit_signature_malleability(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        std::env::remove_var("PI_SIGNATURE_MALLEABILITY_STRICT_MODE");
        audit_signature_malleability(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn raw_ecrecover_flagged_rejected() {
        let o = run(
            "function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(h, v, r, s); require(a == owner); }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_MALLEABLE_SIG");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["verify"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    #[serial]
    fn ecdsa_recover_in_body_is_safe() {
        // body contains ecrecover substring AND ECDSA.recover -> safe library.
        let o = run(
            "function claim(bytes32 h, bytes memory sig) public { address a = ECDSA.recover(h, sig); }",
        );
        // Body has no "ecrecover" substring, so loop is never flagged either way.
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn ecrecover_with_s_value_check_is_safe() {
        let o = run(
            "function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0); address a = ecrecover(h, v, r, s); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn using_ecdsa_for_anywhere_suppresses_flag() {
        // "using ECDSA for" matched against the whole `code`, not just body.
        let o = run(
            "using ECDSA for bytes32; function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(h, v, r, s); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn no_ecrecover_passes() {
        let o = run("function add(uint a, uint b) public returns (uint) { return a + b; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }

    #[test]
    #[serial]
    fn non_strict_env_warns() {
        std::env::set_var("PI_SIGNATURE_MALLEABILITY_STRICT_MODE", "false");
        let o = audit_signature_malleability(&Input {
            file_path: "C.sol".into(),
            solidity_code:
                "function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(h, v, r, s); }"
                    .into(),
            check_level: "STRICT".into(),
        });
        std::env::remove_var("PI_SIGNATURE_MALLEABILITY_STRICT_MODE");
        assert_eq!(o.status, "WARN_MALLEABLE_SIG");
        // is_secure coerced back to true in WARN path.
        assert!(o.is_secure);
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["verify"]);
    }
}
