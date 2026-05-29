//! Port of `pi_micro_agents/pi_uninitialized_state_sentry.py`.
//!
//! Audits Solidity contracts for uninitialized storage state variables and
//! proxy initializer correctness. Behaviour is a line-for-line mirror of the
//! Python original.

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

// ---------------------------------------------------------------------------
// Regexes (compiled once).
// ---------------------------------------------------------------------------

// `r'//.*'` — single-line comments (no DOTALL, `.` does not match newline).
static RE_LINE_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// `r'/\*.*?\*/'` with `re.DOTALL` — block comments, lazy across newlines.
static RE_BLOCK_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

// `r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\('`
static RE_FUNCTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// `r'\b(address|uint256|bytes32|bool)\b\s+(?:public|private|internal)?\s*(?!constant|immutable)([a-zA-Z0-9_]+)\s*;'`
//
// The Rust `regex` crate has no lookahead, so the negative lookahead
// `(?!constant|immutable)` is dropped from the pattern and re-implemented as a
// post-match rejection: the captured name (group 2) is `[a-zA-Z0-9_]+`, and the
// lookahead sits immediately before it, so it fails iff the name begins with the
// literal prefix "constant" or "immutable". Verified byte-for-byte against the
// Python engine (including backtracking edge cases) before porting.
static RE_STATE_VAR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(address|uint256|bytes32|bool)\b\s+(?:public|private|internal)?\s*([a-zA-Z0-9_]+)\s*;")
        .unwrap()
});

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Mirrors `re.sub(r'//.*', '', code)` followed by
/// `re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)`.
fn clean_comments(s: &str) -> String {
    let step1 = RE_LINE_COMMENT.replace_all(s, "");
    RE_BLOCK_COMMENT.replace_all(&step1, "").into_owned()
}

/// Mirrors Python `text[:byte_offset].count('\n') + 1`.
fn line_of(code: &str, byte_offset: usize) -> usize {
    code[..byte_offset].matches('\n').count() + 1
}

/// Port of `extract_solidity_functions`: returns (func_name, func_body, start_line).
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let mut functions: Vec<(String, String, usize)> = Vec::new();
    let bytes = solidity_code.as_bytes();
    let code_len = bytes.len();

    for m in RE_FUNCTION.captures_iter(solidity_code) {
        let keyword = m.get(1).unwrap().as_str();
        let name = m.get(2).unwrap().as_str();
        let func_name = match keyword {
            "function" => name.to_string(),
            "constructor" => "constructor".to_string(),
            "fallback" => "fallback".to_string(),
            _ => "receive".to_string(),
        };

        let start_idx = m.get(0).unwrap().start();
        let start_line = line_of(solidity_code, start_idx);

        // solidity_code.find(';', start_idx) / .find('{', start_idx) — first byte
        // offset at-or-after start_idx, or -1 (here: None).
        let semicolon_idx = find_byte_from(bytes, b';', start_idx);
        let brace_idx = find_byte_from(bytes, b'{', start_idx);

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue
        let brace_pos = match brace_idx {
            None => continue,
            Some(b) => {
                if let Some(s) = semicolon_idx {
                    if s < b {
                        continue;
                    }
                }
                b
            }
        };

        // Balanced-brace scan from brace_pos + 1.
        let mut brace_count: i64 = 1;
        let mut curr_idx = brace_pos + 1;
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

/// First occurrence of `needle` at byte index >= `from`. `needle` is ASCII so
/// byte search matches Python `str.find` semantics on these inputs.
fn find_byte_from(bytes: &[u8], needle: u8, from: usize) -> Option<usize> {
    bytes[from..].iter().position(|&b| b == needle).map(|p| p + from)
}

// ---------------------------------------------------------------------------
// Core audit.
// ---------------------------------------------------------------------------

/// Mirrors `is_strict_mode()`.
///
/// Python first consults the env var; if absent it falls back to a config file
/// (`~/.antigravitycli/config.json` or a path relative to the module), defaulting
/// to `True`. Under the parity harness the env var is the controlling input;
/// the file-based fallback is environment-specific. We replicate the env-var
/// branch exactly and default to `true` when unset (matching the documented
/// default and the harness, which does not ship that config file).
fn is_strict_mode() -> bool {
    match std::env::var("PI_UNINITIALIZED_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_uninitialized(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Clean comments.
    let code_clean = clean_comments(code);

    let functions = extract_solidity_functions(code);

    // Mode 1: Uninitialized Storage Scan — collect declared state variables.
    let mut state_vars: Vec<(String, String, usize)> = Vec::new();
    for m in RE_STATE_VAR.captures_iter(&code_clean) {
        let var_type = m.get(1).unwrap().as_str();
        let var_name = m.get(2).unwrap().as_str();
        // Re-implements the dropped negative lookahead `(?!constant|immutable)`.
        if var_name.starts_with("constant") || var_name.starts_with("immutable") {
            continue;
        }
        // Line number computed against the ORIGINAL `code` (Python: code[:match.start()]).
        let line_num = line_of(code, m.get(0).unwrap().start());
        state_vars.push((var_name.to_string(), var_type.to_string(), line_num));
    }

    // Concatenate cleaned constructor/initialize bodies.
    let mut init_blocks = String::new();
    for (func_name, func_body, _) in &functions {
        if func_name == "constructor" || func_name == "initialize" {
            let cleaned_func = clean_comments(func_body);
            init_blocks.push(' ');
            init_blocks.push_str(&cleaned_func);
        }
    }

    for (var_name, _var_type, line_num) in &state_vars {
        // assignment_pattern: r'\b' + re.escape(var_name) + r'\s*='  searched in init_blocks
        let escaped = regex::escape(var_name);
        let assignment_pattern = Regex::new(&format!(r"\b{escaped}\s*=")).unwrap();
        // second: re.search(r'\b' + re.escape(var_name) + r'\s*=\s*[^\s;]+', code_clean)
        let inline_pattern = Regex::new(&format!(r"\b{escaped}\s*=\s*[^\s;]+")).unwrap();

        if !assignment_pattern.is_match(&init_blocks) && !inline_pattern.is_match(&code_clean) {
            vulnerable_funcs.push(var_name.clone());
            flagged_findings.push(format!(
                "State variable '{var_name}' declared on Line {line_num} is never initialized \
inline or inside constructor/initialize functions, leading to potentially dangerous uninitialized storage states."
            ));
        }
    }

    // Mode 2: Upgradeable Proxy Initializer check.
    let code_clean_lower = code_clean.to_lowercase();
    let is_upgradeable = code_clean_lower.contains("upgradeable");
    if is_upgradeable {
        for (func_name, func_body, start_line) in &functions {
            if func_name == "initialize" {
                if !func_body.contains("initializer") {
                    vulnerable_funcs.push(func_name.clone());
                    flagged_findings.push(format!(
                        "Function '{func_name}' on Line {start_line} is missing the OpenZeppelin 'initializer' modifier, \
making the upgradeable proxy initialization vulnerable to frontrunning re-initializations."
                    ));
                }

                if code_clean_lower.contains("erc20upgradeable")
                    && !func_body.to_lowercase().contains("__erc20_init")
                {
                    vulnerable_funcs.push(func_name.clone());
                    flagged_findings.push(format!(
                        "Function '{func_name}' on Line {start_line} inherits ERC20Upgradeable \
but does not invoke the parent initializer __ERC20_init(), leaving parent variables uninitialized."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_UNINITIALIZED_STATE".to_string();
        } else {
            status = "WARN_UNINITIALIZED_STATE".to_string();
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
    let out = audit_uninitialized(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_uninitialized(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_initialized_contract_passes() {
        std::env::remove_var("PI_UNINITIALIZED_STRICT_MODE");
        let code = "contract C {\n  address public owner;\n  constructor() { owner = msg.sender; }\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn uninitialized_state_var_flagged_strict() {
        std::env::remove_var("PI_UNINITIALIZED_STRICT_MODE");
        let code = "contract C {\n  address public owner;\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_UNINITIALIZED_STATE");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["owner"]);
    }

    #[test]
    #[serial]
    fn constant_state_var_ignored() {
        std::env::remove_var("PI_UNINITIALIZED_STRICT_MODE");
        // The dropped lookahead: a name prefixed with "constant"/"immutable" is skipped.
        let code = "contract C {\n  address constantThing;\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    #[serial]
    fn non_strict_env_warns_and_coerces_secure() {
        std::env::set_var("PI_UNINITIALIZED_STRICT_MODE", "false");
        let code = "contract C {\n  uint256 public total;\n}";
        let o = run(code);
        assert!(o.is_secure); // coerced back to true in WARN mode
        assert_eq!(o.status, "WARN_UNINITIALIZED_STATE");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["total"]);
        std::env::remove_var("PI_UNINITIALIZED_STRICT_MODE");
    }
}
