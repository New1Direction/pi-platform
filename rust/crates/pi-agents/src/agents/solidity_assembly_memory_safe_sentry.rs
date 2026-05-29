//! Port of `pi_micro_agents/pi_solidity_assembly_memory_safe_sentry.py`.
//!
//! Audits Solidity assembly blocks explicitly marked `("memory-safe")` to make
//! sure they don't `mstore`/`mstore8` below offset `0x80` (scratch space, the
//! free-memory pointer, or the zero slot). Behaviour is a line-for-line mirror
//! of the Python original.

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
/// The Python helper consults the `PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE` env var
/// first; if unset it falls back to an antigravity config file whose default is
/// `True`. The reference Rust ports collapse the config-file fallback into the
/// same `true` default, so strict unless the env var is set to a value that is
/// not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Prefix of the Python function-block pattern, up to and including the opening
// brace. The Python pattern has a trailing lookahead `(?=\n\s*function|\Z)`
// that the `regex` crate does not support; the body extent it controls is
// computed manually in `find_function_blocks`.
//
// Python: r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)'
static FUNC_PREFIX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

// Boundary the trailing lookahead anchored on: `\n` followed by `\s*function`.
static FUNC_BOUNDARY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n\s*function").unwrap());

// Python: r'assembly\s*\(\s*["\']memory-safe["\']\s*\)\s*\{([\s\S]*?)\}'
static ASSEMBLY_SAFE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"assembly\s*\(\s*["']memory-safe["']\s*\)\s*\{([\s\S]*?)\}"#).unwrap()
});

// Python: r'mstore(8)?\s*\(\s*(0x[0-7][0-9a-fA-F]?|[0-9]+)\s*,'
static MSTORE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"mstore(8)?\s*\(\s*(0x[0-7][0-9a-fA-F]?|[0-9]+)\s*,").unwrap());

/// Faithful emulation of
/// `re.findall(r'function\s+(...)...\{([\s\S]*?)(?=\n\s*function|\Z)', code)`.
///
/// Returns `(name, args, body)` tuples. The body runs from just after the
/// opening brace to the earliest `\n\s*function` boundary (or end of string),
/// and the next search resumes at that boundary — exactly like Python's
/// non-overlapping `findall` over the full lookahead pattern.
fn find_function_blocks(code: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos <= code.len() {
        let slice = &code[pos..];
        let caps = match FUNC_PREFIX_RE.captures(slice) {
            Some(c) => c,
            None => break,
        };
        let name = caps.get(1).map_or("", |m| m.as_str()).to_string();
        let args = caps.get(2).map_or("", |m| m.as_str()).to_string();
        // Absolute byte offset just past the opening brace (= match end).
        let body_start = pos + caps.get(0).unwrap().end();
        // Find the earliest boundary at or after body_start.
        let rest = &code[body_start..];
        let body_end = match FUNC_BOUNDARY_RE.find(rest) {
            Some(m) => body_start + m.start(),
            None => code.len(),
        };
        let body = code[body_start..body_end].to_string();
        out.push((name, args, body));
        pos = body_end;
    }
    out
}

pub fn audit_assembly_memory_safe(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions containing assembly blocks
    let func_blocks = find_function_blocks(code);

    for (name, _args, body) in &func_blocks {
        // Check if there is an assembly "memory-safe" marker
        if let Some(asm_caps) = ASSEMBLY_SAFE_RE.captures(body) {
            let assembly_body = asm_caps.get(1).map_or("", |m| m.as_str());

            // Look for mstore or mload targeting scratch spaces (< 0x80)
            if let Some(mstore_caps) = MSTORE_RE.captures(assembly_body) {
                let offset_str = mstore_caps.get(2).map_or("", |m| m.as_str());
                let offset: i64 = if offset_str.starts_with("0x") {
                    i64::from_str_radix(&offset_str[2..], 16).unwrap_or(128)
                } else {
                    offset_str.parse::<i64>().unwrap_or(128)
                };

                if offset < 128 {
                    // less than 0x80
                    vulnerable_funcs.push(name.clone());
                    flagged_findings.push(format!(
                        "Function '{name}' contains an assembly block explicitly marked as 'memory-safe' \
but performs 'mstore' to memory offset '{offset_str}' (< 0x80). Writing below 0x80 \
corrupts scratchpad memory, the free memory pointer, or the zero slot, violating Solidity's \
memory safety assumptions."
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
            status = "REJECTED_ASSEMBLY_MEMORY_SAFE".to_string();
        } else {
            status = "WARN_ASSEMBLY_MEMORY_SAFE".to_string();
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
    let out = audit_assembly_memory_safe(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_assembly_memory_safe(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_high_memory_passes() {
        std::env::remove_var("PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE");
        let o = run("contract C {\n    function clean(uint256 x) public {\n        assembly (\"memory-safe\") {\n            mstore(0x80, x)\n        }\n    }\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn write_to_free_memory_pointer_flagged() {
        std::env::remove_var("PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE");
        let o = run("contract C {\n    function bad(uint256 x) internal {\n        assembly (\"memory-safe\") {\n            mstore(0x40, x)\n        }\n    }\n}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ASSEMBLY_MEMORY_SAFE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
    }

    #[test]
    #[serial]
    fn non_strict_env_warns_and_coerces_secure() {
        std::env::set_var("PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE", "false");
        let o = run("contract C {\n    function bad() public {\n        assembly (\"memory-safe\") {\n            mstore8(0x0, 1)\n        }\n    }\n}");
        std::env::remove_var("PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE");
        assert!(o.is_secure); // coerced back to true
        assert_eq!(o.status, "WARN_ASSEMBLY_MEMORY_SAFE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
    }

    #[test]
    #[serial]
    fn unmarked_assembly_ignored() {
        std::env::remove_var("PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE");
        let o = run("contract C {\n    function raw() public {\n        assembly {\n            mstore(0x00, 1)\n        }\n    }\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
