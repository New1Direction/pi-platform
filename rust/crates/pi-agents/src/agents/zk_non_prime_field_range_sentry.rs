//! Port of `pi_micro_agents/pi_zk_non_prime_field_range_sentry.py`.
//!
//! Audits Circom source for large integer literals that meet or exceed the
//! standard BN254 ZK scalar field prime order. Behaviour is a line-for-line
//! mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub circom_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_signals: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZK_NON_PRIME_FIELD_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Mirrors Python: re.findall(r'\b([0-9]{10,})\b', code)
// The Rust `regex` crate supports `\b` word boundaries with identical
// semantics to Python here (`[0-9]` and `_`/letters are word chars), so the
// pattern is reused verbatim. Greedy `{10,}` matches maximal digit runs.
static LITERAL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([0-9]{10,})\b").unwrap());

/// The standard BN254 ZK scalar field prime order (r), as its 77-digit decimal
/// string. Stored as a string because the value far exceeds any native integer
/// width; comparison is done via big-decimal string comparison below.
const BN254_PRIME: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Returns true iff the decimal literal `lit` (ASCII digits only, possibly with
/// leading zeros) is >= the decimal value `prime` (assumed to have no leading
/// zeros). Reproduces Python's `int(lit) >= prime` for arbitrary precision.
fn decimal_ge(lit: &str, prime: &str) -> bool {
    // Strip leading zeros to get the significant-digit representation.
    let stripped = lit.trim_start_matches('0');
    let a = if stripped.is_empty() { "0" } else { stripped };
    let b = prime; // prime has no leading zeros

    if a.len() != b.len() {
        return a.len() > b.len();
    }
    // Equal length: lexicographic comparison over ASCII digits == numeric.
    a >= b
}

pub fn audit_non_prime_range(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_signals: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Look for literal numbers in code.
    for caps in LITERAL_RE.captures_iter(code) {
        let lit = caps.get(1).unwrap().as_str();
        if decimal_ge(lit, BN254_PRIME) {
            vulnerable_signals.push(lit.to_string());
            flagged_findings.push(format!(
                "Constant literal '{lit}' exceeds or equals the standard BN254 ZK scalar field prime order. \
Performing checks or constraints using elements outside the prime field boundary causes modular wrap-around, defeating range constraints."
            ));
        }
    }

    let mut is_secure = vulnerable_signals.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZK_NON_PRIME_FIELD".to_string();
        } else {
            status = "WARN_ZK_NON_PRIME_FIELD".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_signals,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_non_prime_range(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_non_prime_range(&Input {
            file_path: "c.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_code_passes() {
        // Small literals (< 10 digits) are ignored; large but below prime ok.
        let o = run("signal x; x <== 123456789; y <== 1000000000;");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    fn over_prime_literal_flagged() {
        // The BN254 prime itself meets the >= threshold.
        let o = run("c <== 21888242871839275222246405745257275088548364400416034343698204186575808495617;");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZK_NON_PRIME_FIELD");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_signals.len(), 1);
    }

    #[test]
    fn prime_minus_one_is_safe() {
        // One below the prime must NOT be flagged.
        let o = run("c <== 21888242871839275222246405745257275088548364400416034343698204186575808495616;");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn word_boundary_excludes_embedded_digits() {
        // No word boundary between letters/underscore and digits -> not matched.
        let o = run("abc21888242871839275222246405745257275088548364400416034343698204186575808495617");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
