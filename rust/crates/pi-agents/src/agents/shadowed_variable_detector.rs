//! Port of `pi_micro_agents/pi_shadowed_variable_detector.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for state-level
//! variable shadowing and unused functions/parameters. Behaviour is a
//! line-for-line mirror of the Python original.

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

// `re.sub(r'//.*', '', code)` -- by default `.` does not match newline, so this
// strips line comments per physical line.
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());
// `re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)` -- `(?s)` makes `.` match
// newlines; non-greedy `.*?` matches the shortest block comment.
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

// Original Python state-var pattern uses a negative lookahead:
//   r'\b(address|uint256|bytes32|bool|string)\b\s+(?:public|private|internal)?\s*(?!constant|immutable)([a-zA-Z0-9_]+)\s*;'
// The Rust `regex` crate has no lookahead, so we drop `(?!constant|immutable)`
// and post-filter group(2) against the `constant`/`immutable` prefixes. A
// 200k-case fuzz against the original confirmed exact equivalence (see the
// parity report `deviations`).
static STATE_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(address|uint256|bytes32|bool|string)\b\s+(?:public|private|internal)?\s*([a-zA-Z0-9_]+)\s*;")
        .unwrap()
});

// `re.compile(r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(')`
static FUNC_DECL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// `re.search(r'\b(?:function|constructor)\b\s*[a-zA-Z0-9_]*\s*\(([^)]*)\)', cleaned_body)`
static PARAM_HEADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:function|constructor)\b\s*[a-zA-Z0-9_]*\s*\(([^)]*)\)").unwrap()
});

// `re.sub(r'[^a-zA-Z0-9_]', '', var_name)`
static NON_IDENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^a-zA-Z0-9_]").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python resolution order:
///   1. env `PI_SHADOW_STRICT_MODE` -> `value.lower() == "true"`
///   2. `~/.antigravitycli/config.json` then the in-repo
///      `../../.antigravitycli/config.json`, reading the `PI_SHADOW_STRICT_MODE`
///      key (default True)
///   3. default True
///
/// The config-file fallback is environment-dependent; in this repo the config
/// file lacks the key, so `data.get(..., True)` yields True. Therefore, when the
/// env var is unset the effective result is `true`, which this function
/// reproduces. See `deviations` in the parity report: the config-file branch is
/// intentionally collapsed to the default-True behaviour.
fn is_strict_mode() -> bool {
    match std::env::var("PI_SHADOW_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `extract_solidity_functions(solidity_code)`.
///
/// Returns `(func_name, func_body, start_line)` tuples. All offsets are byte
/// offsets; every structural delimiter used here (`{`, `}`, `;`, `\n`) is ASCII,
/// so byte arithmetic produces the same substrings and line counts as Python's
/// code-point arithmetic.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let mut functions: Vec<(String, String, usize)> = Vec::new();
    let bytes = solidity_code.as_bytes();
    let code_len = solidity_code.len();

    for caps in FUNC_DECL_RE.captures_iter(solidity_code) {
        let m = caps.get(0).unwrap();
        let keyword = caps.get(1).map(|c| c.as_str()).unwrap_or("");
        let name = caps.get(2).map(|c| c.as_str()).unwrap_or("");

        let func_name = if keyword == "function" {
            name.to_string()
        } else if keyword == "constructor" {
            "constructor".to_string()
        } else if keyword == "fallback" {
            "fallback".to_string()
        } else {
            "receive".to_string()
        };

        let start_idx = m.start();
        // start_line = solidity_code[:start_idx].count('\n') + 1
        let start_line = solidity_code[..start_idx].matches('\n').count() + 1;

        // semicolon_idx = solidity_code.find(';', start_idx)
        let semicolon_idx = solidity_code[start_idx..]
            .find(';')
            .map(|p| (start_idx + p) as i64)
            .unwrap_or(-1);
        // brace_idx = solidity_code.find('{', start_idx)
        let brace_idx_opt = solidity_code[start_idx..].find('{').map(|p| start_idx + p);
        let brace_idx: i64 = brace_idx_opt.map(|v| v as i64).unwrap_or(-1);

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue
        if brace_idx == -1 || (semicolon_idx != -1 && semicolon_idx < brace_idx) {
            continue;
        }

        let brace_idx = brace_idx as usize;
        let mut brace_count: i64 = 1;
        let mut curr_idx = brace_idx + 1;
        while curr_idx < code_len && brace_count > 0 {
            let ch = bytes[curr_idx];
            if ch == b'{' {
                brace_count += 1;
            } else if ch == b'}' {
                brace_count -= 1;
            }
            curr_idx += 1;
        }

        if brace_count == 0 {
            let func_body = solidity_code[start_idx..curr_idx].to_string();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

pub fn audit_shadowed(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Clean comments.
    let code_clean = LINE_COMMENT_RE.replace_all(code, "");
    let code_clean = BLOCK_COMMENT_RE.replace_all(&code_clean, "");

    // Collect state variables.
    // state_vars = [match.group(2) for match in state_var_pattern.finditer(code_clean)]
    let mut state_vars: Vec<String> = Vec::new();
    for caps in STATE_VAR_RE.captures_iter(&code_clean) {
        let g2 = caps.get(2).map(|c| c.as_str()).unwrap_or("");
        // Reproduce the dropped `(?!constant|immutable)` negative lookahead.
        if g2.starts_with("constant") || g2.starts_with("immutable") {
            continue;
        }
        state_vars.push(g2.to_string());
    }

    let functions = extract_solidity_functions(code);

    for (func_name, func_body, start_line) in functions {
        // Clean comments for func body.
        let cleaned_body = LINE_COMMENT_RE.replace_all(&func_body, "");
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "").to_string();

        // Extract parameter list.
        let mut params: Vec<String> = Vec::new();
        if let Some(caps) = PARAM_HEADER_RE.captures(&cleaned_body) {
            let param_block = caps.get(1).map(|c| c.as_str()).unwrap_or("");
            // raw_params = param_block.split(",")
            for rp in param_block.split(',') {
                // parts = rp.strip().split()
                let parts: Vec<&str> = pyutil::strip(rp).split_whitespace().collect();
                if !parts.is_empty() {
                    // var_name = parts[-1].strip()
                    let mut var_name = pyutil::strip(parts[parts.len() - 1]).to_string();
                    if var_name.starts_with("memory")
                        || var_name.starts_with("calldata")
                        || var_name.starts_with("storage")
                    {
                        if parts.len() >= 2 {
                            // var_name = parts[-2].strip()
                            var_name = pyutil::strip(parts[parts.len() - 2]).to_string();
                        }
                    }
                    // Sanitize identifier.
                    let var_name = NON_IDENT_RE.replace_all(&var_name, "").to_string();
                    if !var_name.is_empty() {
                        params.push(var_name);
                    }
                }
            }
        }

        // Mode 1: Variable Shadowing Scan.
        for param in &params {
            if state_vars.contains(param) {
                vulnerable_funcs.push(func_name.clone());
                flagged_findings.push(format!(
                    "Function '{func_name}' on Line {start_line} contains parameter '{param}' \
which shadows a state-level variable declaration with the same name. \
This shadowing can lead to logic errors and security oversights."
                ));
            }
        }

        // Mode 2: Unused Variables Audit.
        // brace_idx = cleaned_body.find('{')
        if let Some(brace_idx) = cleaned_body.find('{') {
            // body_only = cleaned_body[brace_idx + 1:]
            let body_only = &cleaned_body[brace_idx + 1..];
            for param in &params {
                // param_ref_pattern = re.compile(r'\b' + re.escape(param) + r'\b')
                let pat = format!(r"\b{}\b", regex::escape(param));
                let param_ref_pattern = Regex::new(&pat).unwrap();
                if !param_ref_pattern.is_match(body_only) {
                    // Ensure we don't flag if it's already shadowed.
                    if !vulnerable_funcs.contains(&func_name) {
                        flagged_findings.push(format!(
                            "Optimization warning: Function '{func_name}' on Line {start_line} declares \
parameter '{param}' which is never used in the function body. \
Remove unused parameters to save gas on deployment and execution."
                        ));
                    }
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
            status = "REJECTED_SHADOW_VULNERABILITY".to_string();
        } else {
            status = "WARN_SHADOW_VULNERABILITY".to_string();
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
    let out = audit_shadowed(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_shadowed(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[serial]
    #[test]
    fn clean_contract_passes() {
        std::env::remove_var("PI_SHADOW_STRICT_MODE");
        let o = run("uint256 public total;\nfunction set(uint256 amount) public { total = amount; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[serial]
    #[test]
    fn shadowing_rejected_strict() {
        std::env::set_var("PI_SHADOW_STRICT_MODE", "true");
        let o = run("address public owner;\nfunction take(address owner) public { owner = msg.sender; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SHADOW_VULNERABILITY");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["take"]);
    }

    #[serial]
    #[test]
    fn shadowing_warn_when_not_strict() {
        std::env::set_var("PI_SHADOW_STRICT_MODE", "false");
        let o = run("address public owner;\nfunction take(address owner) public { owner = msg.sender; }");
        // non-strict coerces is_secure back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_SHADOW_VULNERABILITY");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["take"]);
        std::env::remove_var("PI_SHADOW_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn unused_param_flagged_but_secure() {
        std::env::remove_var("PI_SHADOW_STRICT_MODE");
        let o = run("function noop(uint256 ghost) public { uint256 x = 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("never used"));
    }
}
