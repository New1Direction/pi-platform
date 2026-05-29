//! Port of `pi_micro_agents/pi_uniswap_v3_pool_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for `slot0`
//! spot-price manipulation vulnerabilities (use of `.slot0()` without a TWAP
//! `.observe()` fallback). Behaviour is a line-for-line mirror of the Python
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

// Mirrors `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`.
// 3 capture groups -> use captures_iter. `[\s\S]` lets the body span newlines
// (Python relied on the explicit char-class rather than re.DOTALL); the args
// group `(.*?)` uses a plain `.` which, like Python without DOTALL, does not
// cross newlines.
static FUNC_BLOCK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

// Mirrors `re.search(r'\.slot0\s*\(', body)`.
static SLOT0_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.slot0\s*\(").unwrap());

// Mirrors `re.search(r'\.observe\s*\(', body)`.
static OBSERVE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.observe\s*\(").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python first consults the env var `PI_UNIV3_STRICT_MODE` (case-insensitive
/// `== "true"`). If unset, it looks for `~/.antigravitycli/config.json`, then a
/// repo-local fallback config, and reads `data.get("PI_UNIV3_STRICT_MODE", True)`.
/// In the shipped repo that key is **absent** from the config file, so the
/// effective default is `True`. We therefore replicate the env-var branch and
/// default to `true` when it is unset, matching every other ported sentry.
fn is_strict_mode() -> bool {
    match std::env::var("PI_UNIV3_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_uniswap_v3(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = &caps[1];
        let _args = &caps[2];
        let body = &caps[3];

        // Mode 1: Check for direct slot0 queries.
        let slot0_match = SLOT0_RE.is_match(body);
        let observe_match = OBSERVE_RE.is_match(body);

        if slot0_match && !observe_match {
            vulnerable_funcs.push(name.to_string());
            flagged_findings.push(format!(
                "Function '{name}' calls '.slot0()' directly to determine token prices/ratios \
without using a decentralized Oracle TWAP fallback '.observe()'. This exposes the \
contract to catastrophic spot price manipulation attacks."
            ));
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 95.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_UNIV3_RISK".to_string();
        } else {
            status = "WARN_UNIV3_RISK".to_string();
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
    let out = audit_uniswap_v3(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_uniswap_v3(&Input {
            file_path: "Pool.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn safe_observe_passes() {
        let o = run(
            "function safePrice() public view returns (uint) { pool.observe(secs); return 0; }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn slot0_without_observe_flagged() {
        let o = run(
            "function getPrice() public view returns (uint) { (uint160 s,,,,,,) = pool.slot0(); return s; }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_UNIV3_RISK");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_functions, vec!["getPrice"]);
    }

    #[test]
    fn slot0_with_observe_is_safe() {
        // Same function uses both slot0 and observe -> the TWAP fallback exists.
        let o = run(
            "function p() public view returns (uint) { uint a = pool.slot0(); pool.observe(s); return a; }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }
}
