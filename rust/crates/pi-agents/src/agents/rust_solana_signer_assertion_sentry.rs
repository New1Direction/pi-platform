//! Port of `pi_micro_agents/pi_rust_solana_signer_assertion_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solana Rust programs to ensure
//! account signer checks are correctly performed. Behaviour is a line-for-line
//! mirror of the Python original.

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

// `ctx\s*:\s*Context\s*<\s*([a-zA-Z0-9_]+)\s*>`
static CTX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"ctx\s*:\s*Context\s*<\s*([a-zA-Z0-9_]+)\s*>").unwrap());

// `(pub\s+)?([a-zA-Z0-9_]+)\s*:\s*(AccountInfo|UncheckedAccount|Account)`
static FIELDS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(pub\s+)?([a-zA-Z0-9_]+)\s*:\s*(AccountInfo|UncheckedAccount|Account)").unwrap()
});

// Prefix of the Python `instructions` pattern, up to and including the opening
// brace of the function body. The trailing lazy body capture
// `([\s\S]*?)(?=\n\s*(?:pub\s+fn|fn)|\Z)` is handled by manual scanning because
// the `regex` crate does not support lookahead.
//
// Python: `pub\s+fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{`
//   - `(.*?)` is lazy and (default flags) does NOT cross newlines.
//   - `[^{]*` matches any non-`{` char including newlines.
static FN_PREFIX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"pub\s+fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

// Body terminator lookahead: `\n\s*(?:pub\s+fn|fn)`.
static BODY_TERM_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\n\s*(?:pub\s+fn|fn)").unwrap());

/// One match of the Python `instructions` regex: (name, args, body).
struct Instruction {
    name: String,
    args: String,
    body: String,
}

/// Replicates `re.findall(r'pub\s+fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*(?:pub\s+fn|fn)|\Z)', code)`.
///
/// Strategy: repeatedly search for the prefix (name, args, `{`) starting at a
/// running cursor; then find the lazy body terminator (earliest position where
/// `\n\s*(?:pub\s+fn|fn)` matches, else end-of-string) and resume the next
/// search from that zero-width lookahead position — exactly as `re.finditer`
/// does.
fn find_instructions(code: &str) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor <= code.len() {
        let hay = &code[cursor..];
        let caps = match FN_PREFIX_RE.captures(hay) {
            Some(c) => c,
            None => break,
        };
        let whole = caps.get(0).unwrap();
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        let args = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();

        // Absolute byte offset just past the `{`.
        let body_start = cursor + whole.end();

        // Lazy `[\s\S]*?` up to the first terminator position, else end.
        let rest = &code[body_start..];
        let body_end = match BODY_TERM_RE.find(rest) {
            Some(m) => body_start + m.start(),
            None => code.len(),
        };
        let body = code[body_start..body_end].to_string();

        out.push(Instruction { name, args, body });

        // Resume from the zero-width lookahead position, mirroring re.finditer.
        cursor = body_end;
    }
    out
}

/// Mirrors `is_strict_mode()`.
///
/// Strict unless the env var `PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE` is set to
/// a value that (case-insensitively) is not "true". If unset, falls back to a
/// config file lookup (`~/.antigravitycli/config.json`, then a path relative to
/// the Python module). Defaults to strict (`true`) when no signal is present.
fn is_strict_mode() -> bool {
    if let Ok(v) = std::env::var("PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE") {
        return v.to_lowercase() == "true";
    }

    // Config-file fallback. The primary path is `~/.antigravitycli/config.json`.
    let mut config_path: Option<std::path::PathBuf> = None;
    if let Some(home) = std::env::var_os("HOME") {
        let p = std::path::Path::new(&home).join(".antigravitycli/config.json");
        if p.exists() {
            config_path = Some(p);
        }
    }
    // The Python secondary path is module-relative; we cannot reconstruct it
    // reliably from Rust, so we only honor the primary path. If neither exists,
    // default to strict, matching the Python `return True` tail.
    if let Some(path) = config_path {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                match data.get("PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE") {
                    // bool(value): mirror Python truthiness for the common cases.
                    Some(serde_json::Value::Bool(b)) => return *b,
                    Some(serde_json::Value::Null) => return false,
                    Some(serde_json::Value::Number(n)) => {
                        return n.as_f64().map(|f| f != 0.0).unwrap_or(true);
                    }
                    Some(serde_json::Value::String(s)) => return !s.is_empty(),
                    Some(serde_json::Value::Array(a)) => return !a.is_empty(),
                    Some(serde_json::Value::Object(o)) => return !o.is_empty(),
                    // Key missing -> data.get(..., True) default.
                    None => return true,
                }
            }
        }
    }
    true
}

pub fn audit_signer_assertion(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_instructions: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let instructions = find_instructions(code);

    for instr in &instructions {
        let name = &instr.name;
        let args = &instr.args;
        let body = &instr.body;

        // Look for context loading, e.g. ctx: Context<Stake> or ctx: Context<Claims>
        if let Some(ctx_caps) = CTX_RE.captures(args) {
            let struct_name = ctx_caps.get(1).map(|m| m.as_str()).unwrap_or("");

            // Search the rust file for the corresponding account struct definition.
            // struct_pattern = #\[derive\([^)]*Accounts[^)]*\)\][\s\S]*?struct\s+NAME[\s\S]*?\{([\s\S]*?)\}
            let struct_pattern = format!(
                r"#\[derive\([^)]*Accounts[^)]*\)\][\s\S]*?struct\s+{}[\s\S]*?\{{([\s\S]*?)\}}",
                regex::escape(struct_name)
            );
            let struct_re = Regex::new(&struct_pattern).unwrap();

            if let Some(struct_caps) = struct_re.captures(code) {
                let struct_body = struct_caps.get(1).map(|m| m.as_str()).unwrap_or("");

                // Anchor fields.
                for fld in FIELDS_RE.captures_iter(struct_body) {
                    let field_name = fld.get(2).map(|m| m.as_str()).unwrap_or("");
                    let field_type = fld.get(3).map(|m| m.as_str()).unwrap_or("");

                    // Attributes above this field.
                    // attribute_match = #\[account\(([^)]*)\)\]\s*(pub\s+)?{field_name}\s*:
                    let mut has_signer_attribute = false;
                    let attr_pattern = format!(
                        r"#\[account\(([^)]*)\)\]\s*(pub\s+)?{}\s*:",
                        field_name
                    );
                    let attr_re = Regex::new(&attr_pattern).unwrap();
                    if let Some(attr_caps) = attr_re.captures(struct_body) {
                        let attr_content = attr_caps.get(1).map(|m| m.as_str()).unwrap_or("");
                        if attr_content.contains("signer") {
                            has_signer_attribute = true;
                        }
                    }

                    if field_type == "AccountInfo" || field_type == "UncheckedAccount" {
                        let lname = field_name.to_lowercase();
                        if lname.contains("authority")
                            || lname.contains("signer")
                            || lname.contains("user")
                            || lname.contains("owner")
                        {
                            // Check if body manually asserts is_signer / .key.
                            let manual_signer_check = body
                                .contains(&format!("{}.is_signer", field_name))
                                || body.contains(&format!("{}.key", field_name));

                            if !has_signer_attribute && !manual_signer_check {
                                vulnerable_instructions.push(name.clone());
                                flagged_findings.push(format!(
                                    "Solana instruction '{name}' uses accounts struct '{struct_name}' where field \
'{field_name}' of type '{field_type}' has authority-like name but lacks Anchor \
'#[account(signer)]' attribute and no explicit '.is_signer' verification was found \
in the instruction body. This is vulnerable to signature verification bypass exploits."
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    let mut is_secure = vulnerable_instructions.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SOLANA_SIGNER_ASSERTION".to_string();
        } else {
            status = "WARN_SOLANA_SIGNER_ASSERTION".to_string();
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
    let out = audit_signer_assertion(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_signer_assertion(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    const VULN: &str = "#[derive(Accounts)]\n\
pub struct Stake<'info> {\n\
    #[account(mut)]\n\
    pub authority: AccountInfo<'info>,\n\
}\n\
\n\
pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {\n\
    let x = 1;\n\
    Ok(())\n\
}\n";

    const SAFE_ATTR: &str = "#[derive(Accounts)]\n\
pub struct Stake<'info> {\n\
    #[account(signer)]\n\
    pub authority: AccountInfo<'info>,\n\
}\n\
\n\
pub fn stake(ctx: Context<Stake>) -> Result<()> {\n\
    Ok(())\n\
}\n";

    const SAFE_MANUAL: &str = "#[derive(Accounts)]\n\
pub struct Stake<'info> {\n\
    #[account(mut)]\n\
    pub authority: AccountInfo<'info>,\n\
}\n\
\n\
pub fn stake(ctx: Context<Stake>) -> Result<()> {\n\
    require!(ctx.accounts.authority.is_signer, Err);\n\
    Ok(())\n\
}\n";

    #[test]
    #[serial]
    fn vulnerable_instruction_flagged() {
        let o = run(VULN);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_SIGNER_ASSERTION");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_instructions, vec!["stake"]);
    }

    #[test]
    #[serial]
    fn signer_attribute_passes() {
        let o = run(SAFE_ATTR);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_instructions.is_empty());
    }

    #[test]
    #[serial]
    fn manual_is_signer_passes() {
        let o = run(SAFE_MANUAL);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    #[serial]
    fn warn_mode_coerces_secure() {
        std::env::set_var("PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE", "false");
        let o = run(VULN);
        std::env::remove_var("PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE");
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_SOLANA_SIGNER_ASSERTION");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_instructions, vec!["stake"]);
    }

    #[test]
    #[serial]
    fn empty_input_passes() {
        std::env::set_var("PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE", "true");
        let o = run("");
        std::env::remove_var("PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
