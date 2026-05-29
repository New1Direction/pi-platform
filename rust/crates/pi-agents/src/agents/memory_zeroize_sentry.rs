//! Port of `pi_micro_agents/pi_memory_zeroize_sentry.py`.
//!
//! Specialized memory-lifetime micro-agent verifying zeroization API safety for
//! C/C++/Rust source. Behaviour is a line-for-line mirror of the Python
//! original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub source_code: String,
    pub sensitive_symbols: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZEROIZE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_memory_zeroize(input: &Input) -> Output {
    let code = &input.source_code;
    let symbols = &input.sensitive_symbols;
    let mut findings: Vec<String> = Vec::new();

    // Approved secure wipe tokens.
    let secure_wipes = [
        "explicit_bzero",
        "SecureZeroMemory",
        "sodium_memzero",
        "memset_s",
        "Zeroize",
    ];

    for symbol in symbols {
        // Check if symbol appears in code.
        if code.contains(symbol.as_str()) {
            // Find occurrences of standard memset that can be optimized away.
            // Python: re.findall(r'memset\s*\(\s*' + re.escape(symbol) + r'\s*,', code)
            // 0 capture groups -> findall returns the full matches -> count them.
            let pattern = format!(r"memset\s*\(\s*{}\s*,", regex::escape(symbol));
            let re = regex::Regex::new(&pattern).unwrap();
            let memset_count = re.find_iter(code).count();
            for _ in 0..memset_count {
                findings.push(format!(
                    "Symbol '{symbol}' is cleared with standard 'memset'. This call can be optimized away \
by compiler Dead-Store Elimination (DSE). Use 'explicit_bzero' or similar."
                ));
            }

            // Check if it lacks any secure wipes completely.
            let has_secure_wipe = secure_wipes.iter().any(|wipe| code.contains(wipe));
            if !has_secure_wipe && memset_count == 0 {
                findings.push(format!(
                    "Sensitive variable '{symbol}' is never securely zeroized before leaving scope."
                ));
            }
        }
    }

    let mut is_secure = findings.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_ZEROIZE_RISK".to_string();
        } else {
            status = "WARN_ZEROIZE_RISK".to_string();
        }
        if !is_strict_mode() {
            is_secure = true;
        }
    }

    Output {
        is_secure,
        flagged_findings: findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_memory_zeroize(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str, symbols: &[&str]) -> Output {
        audit_memory_zeroize(&Input {
            file_path: "f.c".into(),
            source_code: code.into(),
            sensitive_symbols: symbols.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("explicit_bzero(key, sizeof(key));", &["key"]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    fn memset_flagged() {
        let o = run("memset(secret, 0, sizeof(secret));", &["secret"]);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZEROIZE_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    fn never_zeroized_flagged() {
        let o = run("char password[32]; use(password);", &["password"]);
        assert!(!o.is_secure);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("never securely zeroized"));
    }

    #[test]
    fn symbol_absent_no_finding() {
        let o = run("int x = 1;", &["missing_symbol"]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
