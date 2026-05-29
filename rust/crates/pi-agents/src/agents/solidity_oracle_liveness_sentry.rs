//! Port of `pi_micro_agents/pi_solidity_oracle_liveness_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits price-oracle integrations for stale
//! price and liveness validation checks. Functions that read an oracle via
//! `latestRoundData` must unpack `updatedAt`, perform a freshness check, and
//! validate the price answer is positive; otherwise they are flagged. Behaviour
//! is a line-for-line mirror of the Python original.

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
// captures: group(1)=name, group(2)=args, group(3)=body.
// `[\s\S]` matches any char incl. newlines, so no DOTALL flag is needed. The
// `(.*?)` for args does NOT span newlines (Python `.` w/o DOTALL), so we leave
// the default (non-DOTALL) behaviour for `.` and rely on `[\s\S]` for the body.
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Per-body checks. None of these use lookaround/backreferences, so they port 1:1.
// Python: re.search(r'\bupdatedAt\b', body)
static UPDATED_AT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bupdatedAt\b").unwrap());

// Freshness checks (any one of four patterns satisfies the requirement).
// Python: re.search(r'block\.timestamp\s*-\s*updatedAt', body)
static FRESH_BT_MINUS_UA_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"block\.timestamp\s*-\s*updatedAt").unwrap());
// Python: re.search(r'updatedAt\s*-\s*block\.timestamp', body)
static FRESH_UA_MINUS_BT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"updatedAt\s*-\s*block\.timestamp").unwrap());
// Python: re.search(r'require\s*\(\s*updatedAt\s*>\s*0\s*\)', body)
static FRESH_REQUIRE_GT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"require\s*\(\s*updatedAt\s*>\s*0\s*\)").unwrap());
// Python: re.search(r'require\s*\(\s*updatedAt\s*!=\s*0\s*\)', body)
static FRESH_REQUIRE_NE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"require\s*\(\s*updatedAt\s*!=\s*0\s*\)").unwrap());

// Answer validation (either form satisfies the requirement).
// Python: re.search(r'answer\s*>\s*0', body)
static ANSWER_GT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"answer\s*>\s*0").unwrap());
// Python: re.search(r'price\s*>\s*0', body)
static PRICE_GT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"price\s*>\s*0").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Faithful for the env-var branch (which all parity samples exercise). When the
/// env var is unset, Python additionally consults a JSON config file
/// (`~/.antigravitycli/config.json`, then `src/pi_micro_agents/../../.antigravitycli/config.json`),
/// returning `bool(data.get("PI_ORACLE_LIVENESS_STRICT_MODE", True))` if found and
/// `True` otherwise. We replicate only the final default (`True`); see the parity
/// deviations note for the config-file fallback.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ORACLE_LIVENESS_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_oracle_liveness(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions. captures: group(1)=name, group(2)=args, group(3)=body.
    for caps in FUNC_RE.captures_iter(code) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        let _args = caps.get(2).map_or("", |m| m.as_str());
        let body = caps.get(3).map_or("", |m| m.as_str());

        if body.contains("latestRoundData") {
            // Check if updatedAt is unpacked and checked for freshness.
            let has_updated_at_unpack = UPDATED_AT_RE.is_match(body);
            let has_freshness_check = FRESH_BT_MINUS_UA_RE.is_match(body)
                || FRESH_UA_MINUS_BT_RE.is_match(body)
                || FRESH_REQUIRE_GT_RE.is_match(body)
                || FRESH_REQUIRE_NE_RE.is_match(body);

            let has_answer_validation = ANSWER_GT_RE.is_match(body) || PRICE_GT_RE.is_match(body);

            if !(has_updated_at_unpack && has_freshness_check && has_answer_validation) {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' queries an oracle via 'latestRoundData' but does not perform \
adequate freshness validation. Ensure that 'updatedAt' is checked against a maximum \
heartbeat threshold and the price answer is validated to be greater than zero to prevent stale oracle pricing exploits."
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
            status = "REJECTED_ORACLE_LIVENESS".to_string();
        } else {
            status = "WARN_ORACLE_LIVENESS".to_string();
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
    let out = audit_oracle_liveness(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_oracle_liveness(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_oracle_passes() {
        std::env::remove_var("PI_ORACLE_LIVENESS_STRICT_MODE");
        let code = r#"function getPrice() public view returns (uint256) {
            (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
            require(block.timestamp - updatedAt < 3600);
            require(answer > 0);
            return uint256(answer);
        }"#;
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn missing_freshness_flagged_strict() {
        std::env::remove_var("PI_ORACLE_LIVENESS_STRICT_MODE");
        let code = r#"function getPrice() public view returns (uint256) {
            (, int256 answer, , , ) = feed.latestRoundData();
            return uint256(answer);
        }"#;
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ORACLE_LIVENESS");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["getPrice"]);
    }

    #[test]
    #[serial]
    fn vulnerable_warns_when_not_strict() {
        std::env::set_var("PI_ORACLE_LIVENESS_STRICT_MODE", "false");
        let code = r#"function getPrice() public view returns (uint256) {
            (, int256 answer, , , ) = feed.latestRoundData();
            return uint256(answer);
        }"#;
        let o = run(code);
        // Non-strict: WARN status and is_secure coerced back to true.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ORACLE_LIVENESS");
        assert_eq!(o.risk_score, 80.0);
        std::env::remove_var("PI_ORACLE_LIVENESS_STRICT_MODE");
    }
}
