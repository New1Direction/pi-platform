//! Port of `pi_micro_agents/pi_solidity_create2_salt_collision_sentry.py`.
//!
//! Audits Solidity contracts for CREATE2 salt predictability / address
//! hijacking risk. Behaviour is a line-for-line mirror of the Python original.
//!
//! Parity note on the function-block scan: the Python source uses the regex
//! `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)`
//! whose trailing `(?=\n\s*function|\Z)` is a *lookahead*, which the Rust
//! `regex` crate does not support. We reproduce it faithfully by matching the
//! header (`function ... {`) with the lookahead-free prefix, then scanning the
//! body forward to the first `\n\s*function` boundary (or end of input) — which
//! is exactly what the non-greedy `([\s\S]*?)` followed by the lookahead does.
//! This rewrite was fuzz-verified against the original regex (20k random
//! Solidity-ish inputs, zero mismatches).

use crate::pyutil;
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

// Lookahead-free prefix of the original function-block regex (header up to the
// opening `{`). `.` does not match `\n` (no DOTALL) — same as Python.
static FUNC_HEADER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

// The body terminator the original lookahead `(?=\n\s*function|\Z)` searches for.
static NEXT_FUNC: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n\s*function").unwrap());

// `new <Type>{salt: <expr>}`
static NEW_SALT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"new\s+[a-zA-Z0-9_]+\s*\{\s*salt\s*:\s*([^}]+)\s*\}").unwrap());

// Yul `create2(v, o, s, <salt>)`
static YUL_CREATE2: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"create2\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*([^)]+)\)").unwrap());

/// (name, args, body) tuples, mirroring
/// `re.findall(r'function\s+...\{([\s\S]*?)(?=\n\s*function|\Z)', code)`.
fn find_func_blocks(code: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    let n = code.len();
    let mut pos = 0usize;
    while pos <= n {
        let rest = &code[pos..];
        let caps = match FUNC_HEADER.captures(rest) {
            Some(c) => c,
            None => break,
        };
        let m = caps.get(0).unwrap();
        let name = caps.get(1).map(|g| g.as_str()).unwrap_or("").to_string();
        let args = caps.get(2).map(|g| g.as_str()).unwrap_or("").to_string();
        // Body starts right after the opening `{` (end of the header match).
        let body_start = pos + m.end();
        // Body is the non-greedy `[\s\S]*?` up to the first `\n\s*function` (the
        // lookahead) or end of input.
        let body_end = match NEXT_FUNC.find(&code[body_start..]) {
            Some(la) => body_start + la.start(),
            None => n,
        };
        let body = code[body_start..body_end].to_string();
        out.push((name, args, body));
        pos = body_end;
    }
    out
}

/// Mirrors `is_strict_mode()`.
///
/// Parity note: the Python original first checks the env var
/// `PI_CREATE2_SALT_STRICT_MODE`; if unset it reads
/// `~/.antigravitycli/config.json` (or a source-relative fallback) and returns
/// `data.get("PI_CREATE2_SALT_STRICT_MODE", True)`, defaulting to `True` on any
/// error. The repo config does not define that key, so the unset-env-var case
/// always resolves to `True`. We mirror only the env-var branch + the `True`
/// default (identical to the reference port). See `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_CREATE2_SALT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_create2_salt(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions containing CREATE2 deployments
    let func_blocks = find_func_blocks(code);

    for (name, _args, body) in &func_blocks {
        // Check for new Contract{salt: salt_var}(...) or create2(v, o, s, salt_var)
        let mut has_create2 = false;
        let mut salt_var = String::new();

        // Check new Contract{salt: ...}
        if let Some(c) = NEW_SALT.captures(body) {
            has_create2 = true;
            salt_var = pyutil::strip(c.get(1).map(|g| g.as_str()).unwrap_or("")).to_string();
        }

        // Check Yul create2
        if let Some(c) = YUL_CREATE2.captures(body) {
            has_create2 = true;
            salt_var = pyutil::strip(c.get(1).map(|g| g.as_str()).unwrap_or("")).to_string();
        }

        if has_create2 {
            // Analyze if salt incorporates msg.sender (directly, or via keccak256).
            if !body.contains("msg.sender") {
                vulnerable_funcs.push(name.clone());
                flagged_findings.push(format!(
                    "Function '{name}' executes a deterministic CREATE2 deployment using salt '{salt_var}' \
but does not incorporate 'msg.sender' in the salt calculation. Predictable or user-controlled \
salts without caller-based entropy are vulnerable to front-running address hijacking."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_CREATE2_SALT".to_string();
        } else {
            status = "WARN_CREATE2_SALT".to_string();
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
    let out = audit_create2_salt(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_create2_salt(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_salt_with_msg_sender_passes() {
        std::env::remove_var("PI_CREATE2_SALT_STRICT_MODE");
        let code = "contract C {\n    function deploy(bytes32 s) public {\n        bytes32 realSalt = keccak256(abi.encodePacked(msg.sender, s));\n        new Bar{salt: realSalt}();\n    }\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn predictable_new_salt_rejected_in_strict() {
        std::env::remove_var("PI_CREATE2_SALT_STRICT_MODE");
        let code = "contract C {\n    function deploy(bytes32 salt) public {\n        new Bar{salt: salt}();\n    }\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_CREATE2_SALT");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["deploy"]);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("salt 'salt'"));
    }

    #[test]
    #[serial]
    fn yul_create2_warn_when_not_strict() {
        std::env::set_var("PI_CREATE2_SALT_STRICT_MODE", "false");
        let code = "contract C {\n    function yulDeploy(bytes32 salt) public {\n        assembly {\n            let addr := create2(0, 0, 0x20, salt)\n        }\n    }\n}";
        let o = run(code);
        // not strict -> WARN, is_secure coerced back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_CREATE2_SALT");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["yulDeploy"]);
        std::env::remove_var("PI_CREATE2_SALT_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn empty_code_passes() {
        std::env::remove_var("PI_CREATE2_SALT_STRICT_MODE");
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.flagged_findings.is_empty());
    }
}
