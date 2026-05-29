//! Port of `pi_micro_agents/pi_solidity_delegate_call_to_self_sentry.py`.
//!
//! Audits Solidity contracts for `delegatecall`s targeting `address(this)` or
//! `this` (self-delegatecall). Behaviour is a line-for-line mirror of the
//! Python original.
//!
//! Parity note: the Python `func_blocks` regex relies on a trailing lookahead
//! `(?=\n\s*function|\Z)` that the Rust `regex` crate cannot express. We split
//! that single pattern into (a) a lookahead-free header regex and (b) a manual
//! body-boundary scan that reproduces the lazy `[\s\S]*?` + lookahead semantics
//! exactly (verified against CPython on the parity samples).

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

// `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{` -- the function header up to
// and including the opening brace. `.` does not match newlines (Python had no
// DOTALL), matching the regex crate's default; `[^{]` does match newlines.
static FUNC_HEADER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

// The lookahead body terminator `\n\s*function`.
static BODY_BOUNDARY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n\s*function").unwrap());

// `(address\(\s*this\s*\)|this)\s*\.\s*delegatecall`
static SOLIDITY_DELEGATECALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(address\(\s*this\s*\)|this)\s*\.\s*delegatecall").unwrap());

// `delegatecall\s*\(\s*[^,]+,\s*(address\(\s*this\s*\)|this)\s*,`
static ASSEMBLY_DELEGATECALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"delegatecall\s*\(\s*[^,]+,\s*(address\(\s*this\s*\)|this)\s*,").unwrap()
});

/// Mirrors `is_strict_mode()` for the env-var branch only.
///
/// The Python helper first checks `PI_DELEGATECALL_SELF_STRICT_MODE`; if set, it
/// returns `env.lower() == "true"`. Otherwise it falls back to reading a config
/// file (`~/.antigravitycli/config.json` or a path relative to the module),
/// defaulting to `True`. The parity harness drives behaviour purely through the
/// env var, and in its absence the default is strict (`True`). We reproduce the
/// env-var path faithfully and default to `true` when unset (matching the
/// config-file default). See `deviations` in the parity report re: the config
/// file, which is not consulted here.
fn is_strict_mode() -> bool {
    match std::env::var("PI_DELEGATECALL_SELF_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Reproduces `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)', code)`.
///
/// Returns `(name, args, body)` tuples in document order, non-overlapping, with
/// the next search resuming at the body-boundary position (mirroring CPython's
/// `findall` continuation after a zero-width lookahead).
fn find_func_blocks(code: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    let mut pos = 0usize;
    while pos <= code.len() {
        let m = match FUNC_HEADER_RE.find_at(code, pos) {
            Some(m) => m,
            None => break,
        };
        let caps = FUNC_HEADER_RE
            .captures_at(code, pos)
            .expect("captures must exist when find succeeded");
        let name = caps.get(1).map(|g| g.as_str()).unwrap_or("").to_string();
        let args = caps.get(2).map(|g| g.as_str()).unwrap_or("").to_string();
        let body_start = m.end();

        // Earliest `\n\s*function` at or after body_start, else end of string.
        let boundary = match BODY_BOUNDARY_RE.find_at(code, body_start) {
            Some(bm) => bm.start(),
            None => code.len(),
        };
        let body = code[body_start..boundary].to_string();
        out.push((name, args, body));
        pos = boundary;
        // Guard against a zero-width header match looping forever (cannot happen
        // for this pattern since it requires `function...{`, but be safe).
        if pos < body_start {
            pos = body_start;
        }
    }
    out
}

pub fn audit_delegatecall_self(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for (name, _args, body) in find_func_blocks(code) {
        let mut is_vuln = false;
        let mut finding_msg = String::new();

        // Check Solidity delegatecall to address(this)
        if let Some(caps) = SOLIDITY_DELEGATECALL_RE.captures(&body) {
            let g1 = caps.get(1).map(|g| g.as_str()).unwrap_or("");
            is_vuln = true;
            finding_msg = format!(
                "Function '{name}' makes a direct high-level Solidity 'delegatecall' targeting \
'{g1}'. Self-delegatecall corrupts contract storage structures \
and opens vectors for total proxy destruction or privilege bypass."
            );
        }

        // Check inline assembly delegatecall to address(this)
        if let Some(caps) = ASSEMBLY_DELEGATECALL_RE.captures(&body) {
            let g1 = caps.get(1).map(|g| g.as_str()).unwrap_or("");
            is_vuln = true;
            finding_msg = format!(
                "Function '{name}' contains inline assembly calling 'delegatecall' targeting \
'{g1}'. Self-delegatecall in assembly can corrupt free memory pointers \
and allow attackers to overwrite storage variables."
            );
        }

        if is_vuln {
            vulnerable_funcs.push(name);
            flagged_findings.push(finding_msg);
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_DELEGATECALL_SELF".to_string();
        } else {
            status = "WARN_DELEGATECALL_SELF".to_string();
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
    let out = audit_delegatecall_self(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_delegatecall_self(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_code_passes() {
        std::env::remove_var("PI_DELEGATECALL_SELF_STRICT_MODE");
        let o = run("function foo(uint a) public {\n    target.delegatecall(d);\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn solidity_self_delegatecall_rejected() {
        std::env::remove_var("PI_DELEGATECALL_SELF_STRICT_MODE");
        let o = run("function attack() public {\n    address(this).delegatecall(d);\n}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DELEGATECALL_SELF");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["attack"]);
        assert!(o.flagged_findings[0].contains("address(this)"));
    }

    #[test]
    #[serial]
    fn assembly_self_delegatecall_warn_when_non_strict() {
        std::env::set_var("PI_DELEGATECALL_SELF_STRICT_MODE", "false");
        let o = run(
            "function lowlevel() public {\n    assembly {\n        let r := delegatecall(gas(), address(this), 0, 0, 0, 0)\n    }\n}",
        );
        // non-strict => WARN and is_secure coerced back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_DELEGATECALL_SELF");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["lowlevel"]);
        std::env::remove_var("PI_DELEGATECALL_SELF_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn empty_code_passes() {
        std::env::remove_var("PI_DELEGATECALL_SELF_STRICT_MODE");
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.flagged_findings.is_empty());
    }
}
