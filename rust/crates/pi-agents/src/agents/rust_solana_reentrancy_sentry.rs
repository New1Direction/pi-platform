//! Port of `pi_micro_agents/pi_rust_solana_reentrancy_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Rust Solana Anchor programs to
//! ensure no account uniqueness / duplicate mutability bugs exist. Behaviour is
//! a line-for-line mirror of the Python original.

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
    pub vulnerable_instructions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// `#[derive(...Accounts...)] ... pub struct Name<...> { body }`
// 2 capture groups: struct name, struct body. `[\s\S]` works directly in the
// Rust regex crate (no DOTALL flag required).
static ACCOUNT_STRUCTS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"#\[derive\([^)]*Accounts[^)]*\)\][\s\S]*?pub struct\s+([a-zA-Z0-9_]+)\s*<[\s\S]*?\{([\s\S]*?)\}",
    )
    .unwrap()
});

// `#[account(...mut...)] pub field :` — 1 capture group (field name).
static MUT_FIELDS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"#\[account\([^)]*mut[^)]*\)\]\s*pub\s+([a-zA-Z0-9_]+)\s*:").unwrap()
});

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: the Python original also consults a `~/.antigravitycli/config.json`
/// (or a project-relative copy) when the env var is absent, defaulting to
/// `True`. That config file currently has no
/// `PI_RUST_SOLANA_REENTRANCY_STRICT_MODE` key, so Python falls back to its
/// `True` default — identical to this `Err(_) => true` branch. See parity
/// deviations.
fn is_strict_mode() -> bool {
    match std::env::var("PI_RUST_SOLANA_REENTRANCY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_solana_accounts(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_instructions: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all structures annotated with #[derive(Accounts)]
    for caps in ACCOUNT_STRUCTS_RE.captures_iter(code) {
        let struct_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let struct_body = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        // Look for mutable account fields
        let mut_fields: Vec<String> = MUT_FIELDS_RE
            .captures_iter(struct_body)
            .map(|c| c.get(1).map(|m| m.as_str()).unwrap_or("").to_string())
            .collect();

        // If there are multiple mutable accounts declared, look for comparison
        // constraints or assertions.
        if mut_fields.len() > 1 {
            // Check if there are constraints matching key uniqueness
            // E.g. constraint = account_a.key() != account_b.key()
            let mut has_uniqueness_check = false;
            for field in &mut_fields {
                // Is there a constraint containing "!=" and referencing other
                // field keys in the struct body?
                // `field` is captured from `[a-zA-Z0-9_]+`, so it carries no
                // regex metacharacters and is safe to interpolate verbatim,
                // mirroring the Python f-string regex exactly.
                let pat = format!(r"constraint\s*=.*{}.*!=", field);
                let re = Regex::new(&pat).unwrap();
                if re.is_match(struct_body) || code.contains("assert_ne!") {
                    has_uniqueness_check = true;
                    break;
                }
            }

            if !has_uniqueness_check {
                vulnerable_instructions.push(struct_name.to_string());
                flagged_findings.push(format!(
                    "Solana Accounts struct '{}' defines multiple mutable fields ({}) \
but does not enforce account key uniqueness constraints. An attacker could pass duplicate \
mutable accounts to execute double-borrow or cross-account state corruptions.",
                    struct_name,
                    mut_fields.join(", ")
                ));
            }
        }
    }

    let mut is_secure = vulnerable_instructions.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SOLANA_REENTRANCY".to_string();
        } else {
            status = "WARN_SOLANA_REENTRANCY".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_instructions,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_solana_accounts(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_solana_accounts(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_single_mut_passes() {
        std::env::remove_var("PI_RUST_SOLANA_REENTRANCY_STRICT_MODE");
        let code = r#"
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, Token>,
    pub authority: Signer<'info>,
}
"#;
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_instructions.is_empty());
    }

    #[test]
    #[serial]
    fn dual_mut_without_constraint_flagged() {
        std::env::remove_var("PI_RUST_SOLANA_REENTRANCY_STRICT_MODE");
        let code = r#"
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub account_a: Account<'info, Token>,
    #[account(mut)]
    pub account_b: Account<'info, Token>,
}
"#;
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_REENTRANCY");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_instructions, vec!["Swap"]);
    }

    #[test]
    #[serial]
    fn dual_mut_with_constraint_passes() {
        std::env::remove_var("PI_RUST_SOLANA_REENTRANCY_STRICT_MODE");
        let code = r#"
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut, constraint = account_a.key() != account_b.key())]
    pub account_a: Account<'info, Token>,
    #[account(mut)]
    pub account_b: Account<'info, Token>,
}
"#;
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    #[serial]
    fn warn_mode_coerces_secure() {
        std::env::set_var("PI_RUST_SOLANA_REENTRANCY_STRICT_MODE", "false");
        let code = r#"
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub account_a: Account<'info, Token>,
    #[account(mut)]
    pub account_b: Account<'info, Token>,
}
"#;
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_SOLANA_REENTRANCY");
        assert_eq!(o.risk_score, 80.0);
        std::env::remove_var("PI_RUST_SOLANA_REENTRANCY_STRICT_MODE");
    }
}
