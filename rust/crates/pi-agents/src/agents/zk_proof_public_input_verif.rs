//! Port of `pi_micro_agents/pi_zk_proof_public_input_verif.py`.
//!
//! Specialized ZK validation micro-agent that audits Solidity verifier
//! contracts for unconstrained or missing public input assertions. Behaviour
//! is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub solidity_code: String,
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

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the env var `PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE`:
///   - if set, returns `env_val.lower() == "true"`.
///   - if unset, it falls back to reading a `~/.antigravitycli/config.json`
///     (or a sibling repo file), defaulting to `True` when neither exists or
///     parsing fails.
///
/// This port mirrors the env-var branch exactly and, like the reference
/// `jwt_none_sentry.rs` port, treats the "unset" case as strict (`true`),
/// which matches the Python default when no config file overrides it. See the
/// parity spec deviations note about the config-file fallback.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Matches the function header portion of the Python regex
/// `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{`.
///
/// `.` in the args group does NOT match a newline (Python's default, no
/// DOTALL), so we keep the regex crate's default (also no `s` flag).
static FUNC_HEADER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

/// Replicates the body-terminating lookahead `(?=\n\s*function|\Z)`: the body
/// (group 3, lazy `[\s\S]*?`) ends at the earliest position where the next
/// `function` declaration begins (`\n\s*function`) or at end of input.
static NEXT_FUNC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n\s*function").unwrap());

/// Body-internal input validation checks
/// `(require\s*\(\s*input|require\s*\(\s*publicInput|assert\s*\(\s*input)`.
static REQUIRE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(require\s*\(\s*input|require\s*\(\s*publicInput|assert\s*\(\s*input)").unwrap()
});

/// `(if\s*\(\s*input|if\s*\(\s*publicInput)`.
static IF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(if\s*\(\s*input|if\s*\(\s*publicInput)").unwrap());

/// Reproduces Python's `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)', code)`.
///
/// The Rust `regex` crate has no lookahead, so we find each function header
/// with `FUNC_HEADER_RE`, then compute the body by scanning forward for the
/// next `\n\s*function` (or end of string). `re.findall` advances past each
/// full match (the lookahead is zero-width, so the match end == the body end),
/// so the next search resumes exactly at the body end.
fn find_func_blocks(code: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    let mut pos = 0usize;
    while pos <= code.len() {
        let caps = match FUNC_HEADER_RE.captures_at(code, pos) {
            Some(c) => c,
            None => break,
        };
        let whole = caps.get(0).unwrap();
        let name = caps.get(1).unwrap().as_str().to_string();
        let args = caps.get(2).unwrap().as_str().to_string();
        let body_start = whole.end();
        // Body is lazy: ends at the earliest `\n\s*function` at or after the
        // body start, else at end of string (`\Z`).
        let body_end = match NEXT_FUNC_RE.find_at(code, body_start) {
            Some(m) => m.start(),
            None => code.len(),
        };
        let body = code[body_start..body_end].to_string();
        out.push((name, args, body));
        // Advance to the match end (== body_end). Guard against zero-width
        // stalls (cannot happen here since the header is non-empty, but mirror
        // re.findall's monotonic progress safely).
        pos = if body_end > pos { body_end } else { pos + 1 };
    }
    out
}

pub fn audit_public_input(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let func_blocks = find_func_blocks(code);

    for (name, _args, body) in func_blocks.iter() {
        let name_lower = name.to_lowercase();
        if name_lower.contains("verifyproof") || name_lower.contains("verifyzk") {
            if body.contains("input") || body.contains("publicInput") {
                let mut has_input_validation = false;
                if REQUIRE_RE.is_match(body) {
                    has_input_validation = true;
                }
                if IF_RE.is_match(body) {
                    has_input_validation = true;
                }

                if !has_input_validation {
                    vulnerable_funcs.push(name.clone());
                    flagged_findings.push(format!(
                        "ZK verifier caller function '{name}' handles public inputs but lacks matching require/assert \
checks to verify that the public inputs match the caller's expected state parameters. \
This can allow attackers to supply arbitrary public input arrays for valid proofs, bypassing system constraints."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZK_PUBLIC_INPUT".to_string();
        } else {
            status = "WARN_ZK_PUBLIC_INPUT".to_string();
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
    let out = audit_public_input(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_public_input(&Input {
            file_path: "Verifier.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_verify_with_require_passes() {
        std::env::remove_var("PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE");
        let code = "function verifyProof(uint a, uint[] input) public {\n    require(input[0] == expected);\n    return true;\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn unchecked_input_flagged_strict() {
        std::env::remove_var("PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE");
        let code = "function verifyProof(uint a, uint[] input) public {\n    bool ok = doStuff(input);\n    return ok;\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZK_PUBLIC_INPUT");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["verifyProof".to_string()]);
    }

    #[test]
    #[serial]
    fn unchecked_input_warn_when_not_strict() {
        std::env::set_var("PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE", "false");
        let code = "function verifyZK(bytes proof, uint[] input) external {\n    uint x = input.length;\n}";
        let o = run(code);
        // non-strict -> WARN path, is_secure coerced back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ZK_PUBLIC_INPUT");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["verifyZK".to_string()]);
        std::env::remove_var("PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn empty_code_passes() {
        std::env::remove_var("PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE");
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.flagged_findings.is_empty());
    }
}
