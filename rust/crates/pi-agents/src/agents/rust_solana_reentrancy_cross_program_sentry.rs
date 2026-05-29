//! Port of `pi_micro_agents/pi_rust_solana_reentrancy_cross_program_sentry.py`.
//!
//! Specialized Rust/Solana micro-agent that audits CPI (cross-program
//! invocation) execution patterns to prevent state reentrancy: it flags
//! instruction handlers that mutate local state *after* invoking an external
//! program. Behaviour is a line-for-line mirror of the Python original.

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

/// Mirrors `is_strict_mode()`: strict unless the env var is set, in which case
/// strict iff its value is (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_SOLANA_REENTRANCY_CROSS_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Python: re.findall(r'fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// Group 1 = name, Group 2 = args, Group 3 = body. `.` does not match newlines
// (matching Python's default flags); `[\s\S]` matches everything. No lookaround.
static METHOD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

// Python: re.split(r'invoke(_signed)?\s*\(', body)
static INVOKE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"invoke(_signed)?\s*\(").unwrap());

/// Reproduces Python `re.split(INVOKE_RE, body)` semantics, including the
/// captured optional group (or `None`) interleaved between segments. We only
/// need two facts about the result: whether `len(parts) > 1` and the value of
/// `parts[-1]`. Because the regex always ends with a literal `(`, the final
/// segment is exactly the text following the *last* match.
fn invoke_split_last<'a>(body: &'a str) -> Option<&'a str> {
    let mut last_end: Option<usize> = None;
    for m in INVOKE_RE.find_iter(body) {
        last_end = Some(m.end());
    }
    // `len(parts) > 1` is true iff there was at least one match.
    last_end.map(|end| &body[end..])
}

pub fn audit_reentrancy_cross(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for caps in METHOD_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // args (group 2) is captured by Python but unused beyond unpacking.
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        if body.contains("invoke") || body.contains("invoke_signed") {
            // CPI invocation exists. Check for state mutation *after* the invoke.
            if let Some(post_cpi_code) = invoke_split_last(body) {
                if post_cpi_code.contains('=')
                    || post_cpi_code.contains("mut ")
                    || post_cpi_code.contains("serialize")
                {
                    vulnerable_elements.push(name.to_string());
                    flagged_findings.push(format!(
                        "Instruction handler '{name}' invokes CPI before finalizing its internal state mutations. \
Solana transactions are atomic, but executing external programs before completing local updates risks semantic state confusion or reentrancy vulnerability."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SOLANA_REENTRANCY_CROSS".to_string();
        } else {
            status = "WARN_SOLANA_REENTRANCY_CROSS".to_string();
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
    let out = audit_reentrancy_cross(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_reentrancy_cross(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_no_cpi_passes() {
        let o = run("fn safe(a: u8) {\n    let x = 1;\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn cpi_then_mutation_flagged() {
        let o = run("fn handler(ctx: Context) -> Result {\n    invoke(&ix, &accounts)?;\n    ctx.state.value = 5;\n}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_REENTRANCY_CROSS");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_elements, vec!["handler"]);
    }

    #[test]
    fn cpi_with_no_post_mutation_secure() {
        // invoke present but nothing matching `=`, `mut `, or `serialize` after it.
        let o = run("fn handler(ctx: Context) {\n    invoke(&ix)?;\n    Ok(())\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
