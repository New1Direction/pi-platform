//! Port of `pi_micro_agents/pi_rust_anchor_security_sentry.py`.
//!
//! Specialized Solana micro-agent that audits Anchor Rust programs for signer
//! and account validation defects. Behaviour is a line-for-line mirror of the
//! Python original (`PiRustAnchorSecuritySentry.audit_anchor_security`).

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
    pub vulnerable_functions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// `re.findall(r'pub\s+fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)', code)`.
// Default flags: `.` does NOT match newline (DOTALL not set), and `.*?` is
// non-greedy. The Rust `regex` crate matches Python here for both.
static FUNC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"pub\s+fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)").unwrap());

// `re.search(r'Context\s*<\s*([a-zA-Z0-9_]+)\s*>', args)`.
static CTX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Context\s*<\s*([a-zA-Z0-9_]+)\s*>").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python: if env var `PI_ANCHOR_SECURITY_STRICT_MODE` is set, returns
/// `env_val.lower() == "true"`; otherwise it consults
/// `~/.antigravitycli/config.json` (then a repo-relative fallback) and finally
/// defaults to `True`. This port reproduces the env-var branch and the final
/// default of `true`. The JSON config-file fallback is intentionally NOT
/// reproduced (machine-dependent / non-deterministic). See `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ANCHOR_SECURITY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_anchor_security(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // funcs = re.findall(...): list of (name, args) tuples (2 groups).
    for caps in FUNC_RE.captures_iter(code) {
        let name = &caps[1];
        let args = &caps[2];

        // Anchor instruction handlers receive Context<T>.
        if args.contains("Context") {
            // Get the context generic name, e.g. Context<Initialize>.
            if let Some(ctx_caps) = CTX_RE.captures(args) {
                let struct_name = &ctx_caps[1];
                // Find the corresponding account struct block in code, e.g.
                // #[derive(Accounts)] pub struct Initialize<'info> { ... }.
                let struct_pattern = format!(
                    r"#\[derive\s*\(\s*Accounts\s*\)\s*\]\s*pub\s+struct\s+{}[^}}]+}}",
                    regex::escape(struct_name)
                );
                let struct_re = Regex::new(&struct_pattern).unwrap();
                if let Some(struct_match) = struct_re.find(code) {
                    let struct_body = struct_match.as_str();
                    // Check for signer check: should contain Signer<'info>.
                    if !struct_body.contains("Signer")
                        && !struct_body.to_lowercase().contains("signer")
                    {
                        vulnerable_funcs.push(name.to_string());
                        flagged_findings.push(format!(
                            "Anchor context struct '{struct_name}' for instruction '{name}' does not validate \
the caller signature (missing 'Signer' type). This allows arbitrary clients to execute administrative calls."
                        ));
                    }
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ANCHOR_RISK".to_string();
        } else {
            status = "WARN_ANCHOR_RISK".to_string();
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
    let out = audit_anchor_security(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_anchor_security(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    const SECURE: &str = "#[derive(Accounts)]\n\
pub struct Initialize<'info> {\n\
    pub authority: Signer<'info>,\n\
    pub data: Account<'info, Data>,\n\
}\n\
pub fn initialize(ctx: Context<Initialize>) -> Result<()> { Ok(()) }";

    const VULN: &str = "#[derive(Accounts)]\n\
pub struct Initialize<'info> {\n\
    pub authority: AccountInfo<'info>,\n\
    pub data: Account<'info, Data>,\n\
}\n\
pub fn initialize(ctx: Context<Initialize>) -> Result<()> { Ok(()) }";

    #[test]
    #[serial]
    fn secure_anchor_passes() {
        std::env::remove_var("PI_ANCHOR_SECURITY_STRICT_MODE");
        let o = run(SECURE);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn missing_signer_rejected_strict() {
        std::env::set_var("PI_ANCHOR_SECURITY_STRICT_MODE", "true");
        let o = run(VULN);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ANCHOR_RISK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["initialize"]);
        std::env::remove_var("PI_ANCHOR_SECURITY_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn missing_signer_warn_when_not_strict() {
        std::env::set_var("PI_ANCHOR_SECURITY_STRICT_MODE", "false");
        let o = run(VULN);
        // is_secure coerced back to true in the WARN branch
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ANCHOR_RISK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["initialize"]);
        std::env::remove_var("PI_ANCHOR_SECURITY_STRICT_MODE");
    }
}
