//! Port of `pi_micro_agents/pi_solidity_erc7702_code_sentry.py`.
//!
//! Audits EIP-7702 delegation targets in Solidity contracts to prevent
//! self-destruct and mutability exploits from unvalidated delegation targets.
//! Behaviour is a line-for-line mirror of the Python original.

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

// Python: re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// No DOTALL on the whole pattern -> `.` does not match newline (matches Rust default).
// `[\s\S]` explicitly matches any char incl. newline. 3 groups -> captures_iter.
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Python: re.findall(
//   r'address\s+([a-zA-Z0-9_]*delegate[a-zA-Z0-9_]*|[a-zA-Z0-9_]*target[a-zA-Z0-9_]*)',
//   args, re.IGNORECASE)
// 1 group -> captures_iter, group(1).
static PARAM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)address\s+([a-zA-Z0-9_]*delegate[a-zA-Z0-9_]*|[a-zA-Z0-9_]*target[a-zA-Z0-9_]*)",
    )
    .unwrap()
});

// Python: re.search(r'whitelist|isWhitelisted|allowed|trusted', body, re.IGNORECASE)
static WHITELIST_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)whitelist|isWhitelisted|allowed|trusted").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// The Python original also falls back to a config file when the env var is
/// unset; that config file is absent in the parity environment and the default
/// is `True`, so the env-var branch plus a `true` default reproduces observed
/// behaviour. See the parity spec / deviations for details.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ERC7702_CODE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_erc7702_code(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions: captures_iter mirrors re.findall with 3 groups.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Check if function appears to handle EIP-7702 delegation target setup.
        if args.contains("delegate")
            || body.contains("delegation")
            || body.contains("authorized")
        {
            // Look for a parameter named delegate or target or delegateCode.
            // re.findall with 1 group -> collect group(1) for each match.
            let param_matches: Vec<&str> = PARAM_RE
                .captures_iter(args)
                .map(|c| c.get(1).map(|m| m.as_str()).unwrap_or(""))
                .collect();

            if !param_matches.is_empty() {
                for param in &param_matches {
                    // Check if it verifies target contract bytecode or whitelist.
                    let has_whitelist_check = WHITELIST_RE.is_match(body);
                    let has_destruct_validation = body.contains("extcodesize")
                        || body.contains("code.length")
                        || body.contains("extcodehash");

                    if !(has_whitelist_check || has_destruct_validation) {
                        vulnerable_funcs.push(name.to_string());
                        flagged_findings.push(format!(
                            "Function '{name}' accepts a delegation target parameter '{param}' \
but fails to perform security validation. Unvalidated EIP-7702 delegation targets \
could point to contracts containing self-destruct opcodes or mutable states, \
which can lead to permanent compromise of the delegating EOA account."
                        ));
                        break;
                    }
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ERC7702_CODE".to_string();
        } else {
            status = "WARN_ERC7702_CODE".to_string();
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
    let out = audit_erc7702_code(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_erc7702_code(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_code_passes() {
        std::env::remove_var("PI_ERC7702_CODE_STRICT_MODE");
        // No delegation parameter -> not flagged.
        let o = run("function safe(uint x) public { uint y = x + 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn unvalidated_delegate_flagged() {
        std::env::remove_var("PI_ERC7702_CODE_STRICT_MODE");
        let o = run("function setAuth(address delegateTarget) public { authorized = true; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ERC7702_CODE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["setAuth"]);
    }

    #[test]
    #[serial]
    fn validated_delegate_passes() {
        std::env::remove_var("PI_ERC7702_CODE_STRICT_MODE");
        // Whitelist check present in body -> not flagged.
        let o = run(
            "function setAuth(address delegateTarget) public { require(whitelist[delegateTarget]); authorized = true; }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn non_strict_mode_warns() {
        std::env::set_var("PI_ERC7702_CODE_STRICT_MODE", "false");
        let o = run("function setAuth(address delegateTarget) public { authorized = true; }");
        // is_secure coerced back to true in WARN path.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ERC7702_CODE");
        assert_eq!(o.risk_score, 80.0);
        std::env::remove_var("PI_ERC7702_CODE_STRICT_MODE");
    }
}
