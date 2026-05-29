//! Port of `pi_micro_agents/pi_rust_solana_borsh_serialization_leak.py`.
//!
//! Specialized Rust/Solana micro-agent that audits Borsh data structural
//! alignment risking memory leakage. Behaviour is a line-for-line mirror of the
//! Python original.

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
    match std::env::var("PI_SOLANA_BORSH_LEAK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Python:
//   re.finditer(
//     r'#\[derive\([^)]*(BorshSerialize|AnchorSerialize)[^)]*\)\]\s*(?:pub\s+)?struct\s+([a-zA-Z0-9_]+)',
//     code)
// Two capture groups; `match.group(2)` is the struct name. No lookaround /
// backreferences, so this translates directly. `[^)]*` and `\s*` behave
// identically in the Rust `regex` crate and CPython.
static STRUCT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"#\[derive\([^)]*(BorshSerialize|AnchorSerialize)[^)]*\)\]\s*(?:pub\s+)?struct\s+([a-zA-Z0-9_]+)",
    )
    .unwrap()
});

pub fn audit_borsh_leak(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find structs with BorshSerialize or AnchorSerialize
    for caps in STRUCT_RE.captures_iter(code) {
        let struct_name = &caps[2];

        // Find fields in this struct. Simple parser to look for dynamic/unbounded
        // collections or raw padding.
        //
        // Python builds this pattern dynamically:
        //   re.search(r'struct\s+' + struct_name + r'\s*\{([\s\S]*?)\}', code)
        // `struct_name` is matched by `[a-zA-Z0-9_]+`, so it contains no regex
        // metacharacters; `regex::escape` is therefore a no-op that keeps the
        // match semantics identical to the (unescaped) Python construction. Like
        // Python's `re.search`, this scans the WHOLE `code` and returns the first
        // `struct <name> { ... }` block found, regardless of the derive match's
        // position. `[\s\S]*?` is a lazy match to the first `}`.
        let block_re = Regex::new(&format!(
            r"struct\s+{}\s*\{{([\s\S]*?)\}}",
            regex::escape(struct_name)
        ))
        .unwrap();

        if let Some(block_caps) = block_re.captures(code) {
            let fields = &block_caps[1];
            // Check for dynamic structures or potential uninitialized data leaks
            // (missing explicit padding or custom serialization bounds).
            if fields.contains("Vec<") || fields.contains("String") {
                vulnerable_elements.push(struct_name.to_string());
                flagged_findings.push(format!(
                    "Struct '{struct_name}' derives BorshSerialize/AnchorSerialize but contains dynamic length types (Vec or String) \
without explicit field sizes or strict bounds checking. This risks serialization misalignment or data leakage during custom memory zeroing."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 65.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SOLANA_BORSH_LEAK".to_string();
        } else {
            status = "WARN_SOLANA_BORSH_LEAK".to_string();
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
    let out = audit_borsh_leak(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_borsh_leak(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_struct_without_dynamic_types_passes() {
        std::env::remove_var("PI_SOLANA_BORSH_LEAK_STRICT_MODE");
        let o = run("#[derive(BorshSerialize)]\npub struct Account { amount: u64, owner: Pubkey }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    #[serial]
    fn vec_field_flagged_strict() {
        std::env::remove_var("PI_SOLANA_BORSH_LEAK_STRICT_MODE");
        let o = run("#[derive(BorshSerialize)]\nstruct Ledger { entries: Vec<u8> }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_BORSH_LEAK");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_elements, vec!["Ledger"]);
    }

    #[test]
    #[serial]
    fn string_field_warn_when_not_strict() {
        std::env::set_var("PI_SOLANA_BORSH_LEAK_STRICT_MODE", "false");
        let o = run("#[derive(AnchorSerialize)]\npub struct Meta { name: String }");
        std::env::remove_var("PI_SOLANA_BORSH_LEAK_STRICT_MODE");
        // not strict -> WARN path, is_secure coerced back to True
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_SOLANA_BORSH_LEAK");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_elements, vec!["Meta"]);
    }
}
