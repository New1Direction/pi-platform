//! Port of `pi_micro_agents/pi_rust_solana_cpi_instruction_sentry.py`.
//!
//! Specialized Rust/Solana micro-agent that audits Solana smart contracts for
//! secure CPI (Cross-Program Invocation) program validation. Behaviour is a
//! line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub rust_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_elements: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_SOLANA_CPI_INSTRUCTION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Mirrors Python `re.findall(r'fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`.
// 3 capture groups. The Python pattern has no DOTALL flag, so `.` (in the args
// group) does not match newlines, while `[\s\S]` (in the body group) matches
// every character including newlines. The Rust `regex` crate matches both of
// those behaviours by default.
static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

pub fn audit_cpi_instruction(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for caps in METHOD_RE.captures_iter(code) {
        // group 1 = name, group 2 = args, group 3 = body
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        if body.contains("invoke") || body.contains("invoke_signed") {
            // CPI occurs. Check if the target program id is checked or validated.
            if !body.contains("key") && !body.contains("id") && !body.contains("check") {
                vulnerable_elements.push(name.to_string());
                flagged_findings.push(format!(
                    "Instruction handler '{name}' invokes CPI but does not explicitly validate the target program account ID. \
Malicious actors could pass a spoofed program ID to intercept CPI parameters or return spoofed results."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SOLANA_CPI_INSTRUCTION".to_string();
        } else {
            status = "WARN_SOLANA_CPI_INSTRUCTION".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_elements,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_cpi_instruction(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_cpi_instruction(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        // No CPI invocation at all -> secure.
        let o = run("fn process(ctx: Context) { msg!(\"hi\"); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn invoke_without_validation_flagged() {
        let o = run("fn transfer(ctx: Context) { invoke(&ix, accounts); }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_CPI_INSTRUCTION");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_elements, vec!["transfer"]);
    }

    #[test]
    fn invoke_with_key_check_is_secure() {
        // body contains "key" so the validation guard is satisfied.
        let o = run("fn transfer(ctx: Context) { assert_eq!(prog.key, expected); invoke(&ix, accounts); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_elements.is_empty());
    }
}
