//! Port of `pi_micro_agents/pi_solidity_transient_storage_reentrancy_sentry.py`.
//!
//! Audits Solidity source to ensure transient storage (`tstore`) is explicitly
//! cleared (reset to 0), preventing transient storage reentrancy. Behaviour is a
//! line-for-line mirror of the Python original.

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

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: the Python original additionally falls back to reading
/// `~/.antigravitycli/config.json` (or one relative to the module) when the env
/// var is unset, returning `bool(data.get("PI_TRANSIENT_REENTRANCY_STRICT_MODE",
/// True))`, defaulting to `True`. This port mirrors the reference agent
/// (`jwt_none_sentry.rs`) and only consults the env var, defaulting to `true`
/// when unset. See `deviations` in the parity spec.
fn is_strict_mode() -> bool {
    match std::env::var("PI_TRANSIENT_REENTRANCY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Header portion of the Python function regex, minus the trailing lookahead
/// `(?=\n\s*function|\Z)`. Captures the function name and the argument list, and
/// consumes everything through the opening `{` of the body.
///
/// Python: `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{`
static FUNC_HEADER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

/// The lookahead boundary `\n\s*function`, used to compute where each function
/// body ends (start of the next function, or end of string).
static FUNC_BOUNDARY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n\s*function").unwrap());

/// Python: `tstore\s*\(\s*([^,)]+)\s*,\s*([^)]+)\)`
static TSTORE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"tstore\s*\(\s*([^,)]+)\s*,\s*([^)]+)\)").unwrap());

/// Reproduces `re.findall(r'function\s+(...)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)', code)`.
///
/// The Rust `regex` crate has no lookahead, so the body capture
/// `([\s\S]*?)(?=\n\s*function|\Z)` is computed manually: after matching the
/// header (up to and including the opening `{`), the body runs to the next
/// occurrence of `\n\s*function` at or after that point, or to end-of-string.
/// `re.findall` advances from the end of each header match, which `find_iter`
/// over the header regex reproduces.
fn find_func_blocks(code: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for caps in FUNC_HEADER_RE.captures_iter(code) {
        let m = caps.get(0).unwrap();
        let name = caps.get(1).map(|g| g.as_str()).unwrap_or("").to_string();
        let args = caps.get(2).map(|g| g.as_str()).unwrap_or("").to_string();
        let body_start = m.end();
        let body_end = match FUNC_BOUNDARY_RE.find_at(code, body_start) {
            Some(b) => b.start(),
            None => code.len(),
        };
        let body = code[body_start..body_end].to_string();
        out.push((name, args, body));
    }
    out
}

pub fn audit_transient_reentrancy(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all function definitions in Solidity
    let func_blocks = find_func_blocks(code);

    for (name, _args, body) in &func_blocks {
        // Check for transient store calls (tstore in assembly)
        let tstore_calls: Vec<(String, String)> = TSTORE_RE
            .captures_iter(body)
            .map(|c| {
                (
                    c.get(1).map(|g| g.as_str()).unwrap_or("").to_string(),
                    c.get(2).map(|g| g.as_str()).unwrap_or("").to_string(),
                )
            })
            .collect();

        if !tstore_calls.is_empty() {
            // Check if there is an explicit clearing call (e.g. tstore(slot, 0))
            let mut cleared = false;
            for (_slot, val) in &tstore_calls {
                let val_clean = pyutil::strip(val);
                if val_clean == "0" || val_clean == "0x0" {
                    cleared = true;
                    break;
                }
            }

            if !cleared {
                vulnerable_funcs.push(name.clone());
                flagged_findings.push(format!(
                    "Function '{name}' utilizes transient storage ('tstore') but lacks a corresponding clear command \
reseting the slot to 0 before the execution completes. This leaves the contract vulnerable \
to transient storage reentrancy exploits."
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
            status = "REJECTED_TRANSIENT_REENTRANCY".to_string();
        } else {
            status = "WARN_TRANSIENT_REENTRANCY".to_string();
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
    let out = audit_transient_reentrancy(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_transient_reentrancy(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn cleared_tstore_passes() {
        std::env::remove_var("PI_TRANSIENT_REENTRANCY_STRICT_MODE");
        let o = run("function safe() public {\n    assembly { tstore(1, 9) tstore(1, 0) }\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn uncleared_tstore_rejected_strict() {
        std::env::remove_var("PI_TRANSIENT_REENTRANCY_STRICT_MODE");
        let o = run("function bad() public {\n    assembly { tstore(2, 7) }\n}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TRANSIENT_REENTRANCY");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
    }

    #[test]
    #[serial]
    fn uncleared_tstore_warn_when_not_strict() {
        std::env::set_var("PI_TRANSIENT_REENTRANCY_STRICT_MODE", "false");
        let o = run("function bad() public {\n    assembly { tstore(2, 7) }\n}");
        // non-strict: status is WARN and is_secure is coerced back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_TRANSIENT_REENTRANCY");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
        std::env::remove_var("PI_TRANSIENT_REENTRANCY_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn no_tstore_passes() {
        std::env::remove_var("PI_TRANSIENT_REENTRANCY_STRICT_MODE");
        let o = run("function plain() public {\n    uint y = 5;\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
