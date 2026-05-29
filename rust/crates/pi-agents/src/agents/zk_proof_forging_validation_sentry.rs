//! Port of `pi_micro_agents/pi_zk_proof_forging_validation_sentry.py`.
//!
//! Audits Circom proof-verifier templates to ensure proofs are associated with
//! unique commitment hashes (guarding against double-proof forging / replay).
//! Behaviour is a line-for-line mirror of the Python original.

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
/// is not (case-insensitively) "true". If the var is unset -> strict (True).
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZK_PROOF_FORGING_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Python: re.findall(r'template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// Python `re` has no DOTALL here, so `.` (and `.*?`) does NOT match newlines.
// The Rust `regex` crate also keeps `.` non-newline-matching by default, so the
// pattern translates directly. `[\s\S]*?` matches everything including newlines.
static TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

pub fn audit_proof_forging(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_signals: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for caps in TEMPLATE_RE.captures_iter(code) {
        let tname = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // params (group 2) is unused in the Python body beyond unpacking.
        let _params = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        let tname_lower = tname.to_lowercase();
        if tname_lower.contains("verify") || tname_lower.contains("proof") {
            // Check if public inputs / signature params are verified against commitments.
            let body_lower = body.to_lowercase();
            if !body_lower.contains("commitment")
                && !body_lower.contains("hash")
                && !body_lower.contains("sha")
            {
                vulnerable_signals.push(tname.to_string());
                flagged_findings.push(format!(
                    "Verifier template '{tname}' does not associate proofs with unique commitment hashes. \
Without checking a hash commitment of public parameters, attackers can forge or replay proofs across different contexts."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_signals.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZK_PROOF_FORGING".to_string();
        } else {
            status = "WARN_ZK_PROOF_FORGING".to_string();
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
    let out = audit_proof_forging(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_proof_forging(&Input {
            file_path: "circuit.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_verifier_with_hash_passes() {
        let o = run("template ProofVerify(n) { signal input hash; component h = Sha256(); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    fn verifier_without_commitment_flagged() {
        let o = run("template ProofVerify(n) { signal input a; signal output b; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZK_PROOF_FORGING");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_signals, vec!["ProofVerify"]);
    }

    #[test]
    fn non_verifier_template_ignored() {
        // Template name contains neither "verify" nor "proof".
        let o = run("template Adder(n) { signal input a; signal output b; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_signals.is_empty());
    }
}
