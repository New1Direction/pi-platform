//! Port of `pi_micro_agents/pi_solidity_arbitrary_transfer_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for unsafe
//! arbitrary ERC-20 token transfers (`transfer`/`transferFrom`/`safeTransfer`)
//! performed on user-supplied `address` parameters without a whitelist gate.
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

/// `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`
static FUNC_BLOCKS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

/// `re.findall(r'address\s+([a-zA-Z0-9_]+)', args)`
static ADDRESS_PARAM: Lazy<Regex> = Lazy::new(|| Regex::new(r"address\s+([a-zA-Z0-9_]+)").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python resolution order:
///   1. env var `PI_ARBITRARY_TRANSFER_STRICT_MODE` -> `lower() == "true"`.
///   2. else `~/.antigravitycli/config.json` (if present).
///   3. else module-relative `../../.antigravitycli/config.json` (if present),
///      reading key `PI_ARBITRARY_TRANSFER_STRICT_MODE` defaulting to True.
///   4. else True.
///
/// This Rust port replicates step (1) and the final default of `True`. The
/// config-file fallback (steps 2-3) is NOT replicated; see the crate's parity
/// notes. In the PI Platform repo neither config defines the key, so the
/// effective default is `True`, matching this implementation.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ARBITRARY_TRANSFER_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_arbitrary_transfer(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions.
    for caps in FUNC_BLOCKS.captures_iter(code) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        let args = caps.get(2).map_or("", |m| m.as_str());
        let body = caps.get(3).map_or("", |m| m.as_str());

        // Check if function takes an address parameter that might represent a token.
        let param_matches: Vec<&str> = ADDRESS_PARAM
            .captures_iter(args)
            .map(|c| c.get(1).map_or("", |m| m.as_str()))
            .collect();
        if param_matches.is_empty() {
            continue;
        }

        for param in &param_matches {
            // Look for transfer / transferFrom called on this parameter.
            let p = regex::escape(param);
            let is_transferred = Regex::new(&format!(
                r"{p}\s*\.\s*(?:transfer|transferFrom|safeTransfer)"
            ))
            .unwrap()
            .is_match(body)
                || Regex::new(&format!(
                    r"IERC20\s*\(\s*{p}\s*\)\s*\.\s*(?:transfer|transferFrom|safeTransfer)"
                ))
                .unwrap()
                .is_match(body)
                || Regex::new(&format!(r"safeTransfer\s*\(\s*(?:IERC20\s*\()?\s*{p}\s*\)?"))
                    .unwrap()
                    .is_match(body);

            if is_transferred {
                // Check if there is a whitelist check or dynamic parameter
                // validation matching this parameter.
                let has_whitelist_check = Regex::new(&format!(r"whitelist\s*\[\s*{p}\s*\]"))
                    .unwrap()
                    .is_match(body)
                    || Regex::new(&format!(r"isWhitelisted\s*\[\s*{p}\s*\]"))
                        .unwrap()
                        .is_match(body)
                    || Regex::new(&format!(r"require\s*\(\s*{p}\s*==\s*[a-zA-Z0-9_]+\s*\)"))
                        .unwrap()
                        .is_match(body)
                    || Regex::new(&format!(r"require\s*\(\s*[a-zA-Z0-9_]+\s*==\s*{p}\s*\)"))
                        .unwrap()
                        .is_match(body)
                    || body.contains("onlyOwner")
                    || body.contains("onlyAdmin");

                if !has_whitelist_check {
                    vulnerable_funcs.push(name.to_string());
                    flagged_findings.push(format!(
                        "Function '{name}' accepts a user-controlled token address '{param}' \
and triggers a transfer or transferFrom operation without performing whitelist verification. \
This could allow attackers to call malicious tokens or siphon approved assets."
                    ));
                    break;
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ARBITRARY_TRANSFER".to_string();
        } else {
            status = "WARN_ARBITRARY_TRANSFER".to_string();
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
    let out = audit_arbitrary_transfer(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_arbitrary_transfer(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_contract_passes() {
        std::env::remove_var("PI_ARBITRARY_TRANSFER_STRICT_MODE");
        // No address param -> not flagged.
        let o = run("function ping(uint256 amount) public { total += amount; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn arbitrary_transfer_flagged_strict() {
        std::env::remove_var("PI_ARBITRARY_TRANSFER_STRICT_MODE");
        let o = run("function rug(address token, uint256 amt) public { token.transfer(msg.sender, amt); }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ARBITRARY_TRANSFER");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["rug"]);
    }

    #[test]
    #[serial]
    fn whitelisted_transfer_is_safe() {
        std::env::remove_var("PI_ARBITRARY_TRANSFER_STRICT_MODE");
        let o = run(
            "function pull(address token, uint256 amt) public { require(whitelist[token]); IERC20(token).transferFrom(msg.sender, address(this), amt); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn non_strict_env_warns() {
        std::env::set_var("PI_ARBITRARY_TRANSFER_STRICT_MODE", "false");
        let o = run("function rug(address token, uint256 amt) public { token.transfer(msg.sender, amt); }");
        // is_secure coerced back to true in WARN path.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ARBITRARY_TRANSFER");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["rug"]);
        std::env::remove_var("PI_ARBITRARY_TRANSFER_STRICT_MODE");
    }
}
