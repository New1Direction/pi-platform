//! Port of `pi_micro_agents/pi_solidity_initializable_gap_sentry.py`.
//!
//! Audits upgradeable Solidity contracts (proxies) for missing storage gaps
//! (e.g. `uint256[50] __gap`). Behaviour is a line-for-line mirror of the
//! Python original.

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
    pub vulnerable_contracts: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Python: re.findall(r'contract\s+([a-zA-Z0-9_]+)(?:\s+is\s+([a-zA-Z0-9_,\s]+))?\s*\{([\s\S]*?)\}', code)
// `[\s\S]` matches any char incl. newlines; mirror with the `(?s)` dotall flag and `.`.
// Three capture groups: (name, inheritance, body). The non-greedy body matches Python's `*?`.
static CONTRACT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)contract\s+([a-zA-Z0-9_]+)(?:\s+is\s+([a-zA-Z0-9_,\s]+))?\s*\{(.*?)\}")
        .unwrap()
});

// Python: re.search(r'uint256\s*\[\s*\d+\s*\]\s*(?:private|internal)?\s*__gap\s*;', body)
// No capture groups; presence check only.
static GAP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"uint256\s*\[\s*\d+\s*\]\s*(?:private|internal)?\s*__gap\s*;").unwrap()
});

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_INITIALIZABLE_GAP_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_initializable_gap(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_contracts: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all contracts. Python's re.findall with 3 groups yields tuples; an
    // unmatched optional group is the empty string "" (NOT None), so we map a
    // missing inheritance capture to "".
    for caps in CONTRACT_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let inheritance = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Check if this is an upgradeable or base parent contract.
        // Upgradeable contracts typically inherit from Initializable, or end in
        // 'Upgradeable', or are abstract.
        let is_upgradeable = name.contains("Upgradeable")
            || inheritance.contains("Initializable")
            || code.contains("abstract");

        if is_upgradeable {
            // Check for standard storage gap variable: e.g. uint256[50] __gap or similar.
            let has_gap = GAP_RE.is_match(body);
            if !has_gap {
                vulnerable_contracts.push(name.to_string());
                flagged_findings.push(format!(
                    "Upgradeable parent contract '{name}' is missing a storage gap (__gap variable). \
Without a storage gap, adding new state variables to this base contract in future upgrades will shift storage layout slots in derived contracts, causing silent state corruption."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_contracts.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_INITIALIZABLE_GAP".to_string();
        } else {
            status = "WARN_INITIALIZABLE_GAP".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_contracts,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_initializable_gap(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_initializable_gap(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn upgradeable_with_gap_passes() {
        let o = run(
            "contract MyTokenUpgradeable is Initializable { uint256 x; uint256[50] private __gap; }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_contracts.is_empty());
    }

    #[test]
    fn upgradeable_missing_gap_flagged() {
        let o = run("contract VaultUpgradeable { uint256 balance; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_INITIALIZABLE_GAP");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_contracts, vec!["VaultUpgradeable"]);
    }

    #[test]
    fn non_upgradeable_contract_ignored() {
        let o = run("contract PlainToken { uint256 balance; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_contracts.is_empty());
    }

    #[test]
    fn inherits_initializable_missing_gap_flagged() {
        let o = run("contract Base is Initializable, Ownable { uint256 v; }");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_contracts, vec!["Base"]);
    }
}
