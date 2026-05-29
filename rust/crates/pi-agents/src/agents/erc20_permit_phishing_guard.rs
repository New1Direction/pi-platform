//! Port of `pi_micro_agents/pi_erc20_permit_phishing_guard.py`.
//!
//! Audits Solidity contracts for EIP-2612 / EIP-3009 gasless `permit()`
//! implementations whose `owner` parameter is user-controlled (rather than
//! locked to `msg.sender`), which enables approval-phishing / signature-replay
//! attacks. Behaviour is a line-for-line mirror of the Python original.

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
// Group 2 (`(.*?)`) uses `.` which, like Python's default, does NOT span
// newlines. Group 3 (`([\s\S]*?)`) explicitly spans everything. Both Python
// `re` and the Rust `regex` crate use leftmost-first (lazy) quantifier
// semantics here, so the per-function match boundaries are identical.
static FUNC_BLOCK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

// `re.search(r'\.permit\s*\(', body)`
static PERMIT_CALL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.permit\s*\(").unwrap());

// `re.search(r'\.permit\s*\(\s*msg\.sender\s*,', body)`
static SENDER_OWNER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.permit\s*\(\s*msg\.sender\s*,").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// The Python original first honours the `PI_PERMIT_GUARD_STRICT_MODE` env var
/// (`true` case-insensitively => strict). When the env var is unset it falls
/// back to a config-file lookup that ultimately defaults to `True`. On the
/// parity host both branches yield `True` for the unset case, so mirroring the
/// env var plus a `True` default reproduces the observed behaviour. See
/// `deviations` for the (non-exercised) config-file edge.
fn is_strict_mode() -> bool {
    match std::env::var("PI_PERMIT_GUARD_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_permit(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        // args = caps.get(2) — captured but unused, matching Python's loop var.
        let body = caps.get(3).map_or("", |m| m.as_str());

        // Mode 1: Check for permit call integration.
        let permit_call_match = PERMIT_CALL_RE.is_match(body);

        if permit_call_match {
            // Mode 2: Check if permit parameters use msg.sender instead of a
            // user-controlled signer variable.
            let sender_owner_match = SENDER_OWNER_RE.is_match(body);

            if !sender_owner_match {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' processes gasless signatures using '.permit()' with a \
user-controlled owner parameter instead of locking it to 'msg.sender'. \
This allows attackers to execute arbitrary signatures on behalf of other users, \
posing severe approval phishing risks."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_PERMIT_RISK".to_string();
        } else {
            status = "WARN_PERMIT_RISK".to_string();
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
    let out = audit_permit(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        std::env::set_var("PI_PERMIT_GUARD_STRICT_MODE", "true");
        audit_permit(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn user_controlled_owner_flagged() {
        let o = run(
            "function gaslessApprove(address owner, uint256 v) public \
{ token.permit(owner, spender, value, deadline, v, r, s); }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_PERMIT_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["gaslessApprove"]);
    }

    #[test]
    #[serial]
    fn msg_sender_owner_is_safe() {
        let o = run(
            "function safeApprove(uint256 v) public \
{ token.permit(msg.sender, spender, value, deadline, v, r, s); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn no_permit_call_passes() {
        let o = run("function transfer(address to, uint256 amt) public { balances[to] += amt; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    #[serial]
    fn non_strict_env_warns_and_coerces_secure() {
        std::env::set_var("PI_PERMIT_GUARD_STRICT_MODE", "false");
        let o = audit_permit(&Input {
            file_path: "C.sol".into(),
            solidity_code: "function f(address owner) public { token.permit(owner, a, b, c); }"
                .into(),
            check_level: "STRICT".into(),
        });
        assert!(o.is_secure); // coerced back to true on WARN
        assert_eq!(o.status, "WARN_PERMIT_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["f"]);
        std::env::remove_var("PI_PERMIT_GUARD_STRICT_MODE");
    }
}
