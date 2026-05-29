//! Port of `pi_micro_agents/pi_threat_model_generator.py`.
//!
//! Generates a STRIDE-style threat model from a high-level system description.
//! Behaviour mirrors the Python original line-for-line.
//!
//! PARITY CAVEAT (see parity spec / deviations): the Python original computes
//! `STRIDE_categories = list(set(categories))`. CPython set iteration order for
//! strings is governed by per-process hash randomization (`PYTHONHASHSEED`), so
//! the Python output ordering of `STRIDE_categories` is NON-DETERMINISTIC across
//! runs. This Rust port deduplicates while preserving first-seen insertion
//! order, which is deterministic but will NOT necessarily byte-match Python's
//! scrambled ordering when more than one category is present.

// Note: this agent uses only `.to_lowercase()` and `.contains()`; the Python
// original never calls `.splitlines()`/`.strip()`, so `crate::pyutil` is not needed.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub system_desc: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub threats: Vec<String>,
    #[serde(rename = "STRIDE_categories")]
    pub stride_categories: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true". Unset => strict (True).
fn is_strict_mode() -> bool {
    match std::env::var("PI_SYSTEM_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn generate_threat_model(input: &Input) -> Output {
    // `desc = input_envelope.system_desc.lower()`
    let desc = input.system_desc.to_lowercase();
    let mut threats: Vec<String> = Vec::new();
    let mut categories: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Database related threats
    if desc.contains("database") || desc.contains("db") || desc.contains("storage") {
        threats.push(
            "Information Disclosure: Potential compromise of sensitive user databases due to weak access policies."
                .to_string(),
        );
        categories.push("Information Disclosure".to_string());
        threats.push(
            "Tampering: Malicious injection or truncation queries executed directly on storage clusters."
                .to_string(),
        );
        categories.push("Tampering".to_string());
        risk_score = risk_score.max(60.0);
    }

    // API related threats
    if desc.contains("api") || desc.contains("endpoint") || desc.contains("gateway") {
        threats.push(
            "Elevation of Privilege: Unauthenticated attackers abusing broken authorization boundaries."
                .to_string(),
        );
        categories.push("Elevation of Privilege".to_string());
        threats.push(
            "Denial of Service: Volumetric request bursts exhausting thread pools or backend CPU limits."
                .to_string(),
        );
        categories.push("Denial of Service".to_string());
        risk_score = risk_score.max(80.0);
    }

    // Public web interface
    if desc.contains("public web") || desc.contains("frontend") || desc.contains("client") {
        threats.push(
            "Spoofing: Phishing portals imitating production client domain names.".to_string(),
        );
        categories.push("Spoofing".to_string());
        risk_score = risk_score.max(50.0);
    }

    // Ensure categories are unique.
    //
    // Python: `categories = list(set(categories))` — set() dedup with
    // hash-randomized iteration order. We dedup preserving first-seen order.
    // (See module-level PARITY CAVEAT.)
    let categories = dedup_preserve_order(categories);

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "THREATS_IDENTIFIED".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_THREATS".to_string();
    }

    Output {
        is_secure: is_sec,
        threats,
        stride_categories: categories,
        risk_score,
        status,
    }
}

/// Deduplicate a vector of strings keeping the first occurrence's position.
fn dedup_preserve_order(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = generate_threat_model(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(desc: &str) -> Output {
        generate_threat_model(&Input {
            system_desc: desc.into(),
        })
    }

    #[test]
    fn clean_input_passes() {
        // Note: "clean app" — but beware substring matches. "clean" does not
        // contain any trigger token; verify a truly benign string.
        let o = run("a benign internal tool");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.threats.is_empty());
        assert!(o.stride_categories.is_empty());
    }

    #[test]
    fn database_flagged_strict() {
        let o = run("backed by a postgres database and storage layer");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 60.0);
        assert_eq!(o.status, "THREATS_IDENTIFIED");
        assert_eq!(o.threats.len(), 2);
        assert_eq!(
            o.stride_categories,
            vec!["Information Disclosure".to_string(), "Tampering".to_string()]
        );
    }

    #[test]
    fn api_takes_highest_risk() {
        let o = run("an api gateway with a database");
        // database -> 60, api -> 80; max == 80
        assert_eq!(o.risk_score, 80.0);
        assert!(!o.is_secure);
    }

    #[test]
    fn empty_input_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }
}
