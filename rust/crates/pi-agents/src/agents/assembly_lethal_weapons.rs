//! Port of `pi_micro_agents/pi_assembly_lethal_weapons.py`.
//!
//! Web3 micro-agent that audits Solidity contracts for dangerous Yul/assembly
//! memory practices (overwriting the free-memory pointer / scratch space) and
//! flags assembly `div`/`mul` by powers of two that should use `shr`/`shl`.
//! Behaviour is a line-for-line mirror of the Python original.

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
/// The Python version first consults the `PI_ASSEMBLY_STRICT_MODE` env var and,
/// if it is unset, falls back to reading `~/.antigravitycli/config.json` (and
/// a repo-local copy), defaulting to `True`. To stay deterministic and avoid
/// filesystem coupling, this port mirrors only the env-var branch and treats
/// "unset" as strict (`True`), matching the Python default when no config file
/// is present. See `deviations` in the parity report.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ASSEMBLY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// ---- Regexes (compiled once) -------------------------------------------------

// r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\('
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// r'//.*'  (note: Python's `.` does not match newline -> default behaviour)
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// r'/\*.*?\*/' with re.DOTALL -> (?s)
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

// r'\bmstore\(\s*(0x0|0x20|0|32)\s*,'
static MSTORE_LOW_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bmstore\(\s*(0x0|0x20|0|32)\s*,").unwrap());

// r'\bmstore\(\s*(0x40|64)\s*,'
static MSTORE_FMP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bmstore\(\s*(0x40|64)\s*,").unwrap());

// r'\bdiv\(\s*([a-zA-Z0-9_]+)\s*,\s*(2|4|8|16|32|64|128|256)\s*\)'
static DIV_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bdiv\(\s*([a-zA-Z0-9_]+)\s*,\s*(2|4|8|16|32|64|128|256)\s*\)").unwrap()
});

// r'\bmul\(\s*([a-zA-Z0-9_]+)\s*,\s*(2|4|8|16|32|64|128|256)\s*\)'
static MUL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bmul\(\s*([a-zA-Z0-9_]+)\s*,\s*(2|4|8|16|32|64|128|256)\s*\)").unwrap()
});

/// Mirrors `extract_solidity_functions`: returns `(func_name, func_body, start_line)`.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let mut functions: Vec<(String, String, usize)> = Vec::new();
    let bytes = solidity_code.as_bytes();
    let code_len = bytes.len();

    for caps in FUNC_RE.captures_iter(solidity_code) {
        let keyword = caps.get(1).unwrap().as_str();
        let name = caps.get(2).unwrap().as_str();
        let func_name: String = match keyword {
            "function" => name.to_string(),
            "constructor" => "constructor".to_string(),
            "fallback" => "fallback".to_string(),
            _ => "receive".to_string(),
        };

        let start_idx = caps.get(0).unwrap().start();
        // solidity_code[:start_idx].count('\n') + 1
        let start_line = solidity_code[..start_idx].matches('\n').count() + 1;

        // solidity_code.find(';', start_idx)  -> None == -1
        let semicolon_idx = find_byte(bytes, b';', start_idx);
        let brace_idx = find_byte(bytes, b'{', start_idx);

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

/// Equivalent of Python `str.find(ch, start)`: returns the byte index of the
/// first occurrence of `ch` at or after `start`, or `None` (Python `-1`).
fn find_byte(bytes: &[u8], ch: u8, start: usize) -> Option<usize> {
    if start >= bytes.len() {
        return None;
    }
    bytes[start..].iter().position(|&b| b == ch).map(|p| p + start)
}

pub fn audit_assembly(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    for (func_name, func_body, start_line) in &functions {
        // cleaned_body = re.sub(r'//.*', '', func_body)
        let cleaned_body = LINE_COMMENT_RE.replace_all(func_body, "");
        // cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "").to_string();

        // Check if using inline assembly
        if cleaned_body.contains("assembly") {
            // Mode 1: Assembly Memory Corruption Audit
            if MSTORE_LOW_RE.is_match(&cleaned_body) || MSTORE_FMP_RE.is_match(&cleaned_body) {
                let lower = cleaned_body.to_lowercase();
                if !lower.contains("allocate") && !lower.contains("free memory") {
                    vulnerable_funcs.push(func_name.clone());
                    flagged_findings.push(format!(
                        "Function '{func_name}' on Line {start_line} contains assembly that directly overwrites \
the free memory pointer (0x40) or reserved scratch space (0x00-0x3f). This can corrupt Solidity memory."
                    ));
                }
            }

            // Mode 2: Assembly Optimizations
            if DIV_RE.is_match(&cleaned_body) {
                flagged_findings.push(format!(
                    "Assembly Optimization: Function '{func_name}' on Line {start_line} uses 'div' division by \
a power of two in assembly. Using 'shr' (shift right) is more gas-efficient."
                ));
            }

            if MUL_RE.is_match(&cleaned_body) {
                flagged_findings.push(format!(
                    "Assembly Optimization: Function '{func_name}' on Line {start_line} uses 'mul' multiplication by \
a power of two in assembly. Using 'shl' (shift left) is more gas-efficient."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ASSEMBLY_RISK".to_string();
        } else {
            status = "WARN_ASSEMBLY_RISK".to_string();
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
    let out = audit_assembly(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_assembly(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_contract_passes() {
        std::env::set_var("PI_ASSEMBLY_STRICT_MODE", "true");
        let o = run("function foo() public { uint x = 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        std::env::remove_var("PI_ASSEMBLY_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn fmp_overwrite_rejected_in_strict() {
        std::env::set_var("PI_ASSEMBLY_STRICT_MODE", "true");
        let o = run("function bad() public { assembly { mstore(0x40, 0x80) } }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ASSEMBLY_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
        std::env::remove_var("PI_ASSEMBLY_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn fmp_overwrite_warns_when_not_strict() {
        std::env::set_var("PI_ASSEMBLY_STRICT_MODE", "false");
        let o = run("function bad() public { assembly { mstore(0x40, 0x80) } }");
        // non-strict path coerces is_secure back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ASSEMBLY_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
        std::env::remove_var("PI_ASSEMBLY_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn div_mul_optimization_flagged_but_secure() {
        std::env::set_var("PI_ASSEMBLY_STRICT_MODE", "true");
        let o = run("function opt(uint a) public { assembly { let r := div(a, 2) let q := mul(a, 4) } }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.flagged_findings.len(), 2);
        std::env::remove_var("PI_ASSEMBLY_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn allocate_suppresses_memory_finding() {
        std::env::set_var("PI_ASSEMBLY_STRICT_MODE", "true");
        // "allocate" appears in real code (not a stripped comment), so the
        // memory-corruption finding is suppressed.
        let o = run("function alloc() public { uint allocate = 1; assembly { mstore(0x40, 0x80) } }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
        std::env::remove_var("PI_ASSEMBLY_STRICT_MODE");
    }
}
