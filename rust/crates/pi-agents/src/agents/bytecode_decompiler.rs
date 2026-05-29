//! Port of `pi_micro_agents/pi_bytecode_decompiler.py`.
//!
//! Specialized Web3 micro-agent that audits EVM bytecode strings and Solidity
//! inline assembly for security issues and gas efficiency. Behaviour is a
//! line-for-line mirror of the Python original.

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

// --- Compiled regexes (mirror the Python `re` patterns) ---

// re.sub(r'\s+', '', code)
static WS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());
// re.match(r'^[0-9a-f]+$', cleaned)  (whitespace already removed -> $ == end of text)
static HEX_ALL: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-f]+$").unwrap());
// re.sub(r'//.*', '', code)  ('.' excludes newline in both Python and Rust)
static LINE_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());
// re.sub(r'/\*.*?\*/', '', code_clean, flags=re.DOTALL)
static BLOCK_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());
// re.finditer(r'\bassembly\s*\{([^}]*)\}', code_clean)
static ASSEMBLY: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bassembly\s*\{([^}]*)\}").unwrap());
// re.search(r'mstore\(\s*(0x[0-1]?[0-9a-fA-F]|0|1|2|3)[^,]*\s*,', block_content)
static BAD_SCRATCH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"mstore\(\s*(0x[0-1]?[0-9a-fA-F]|0|1|2|3)[^,]*\s*,").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: the Python original, when the env var is unset, falls back to reading a
/// JSON config file (`~/.antigravitycli/config.json` or a repo-relative path)
/// and ultimately defaults to `True`. This port mirrors the reference port and
/// only consults the env var, defaulting to `true` when unset. See module-level
/// deviation notes.
fn is_strict_mode() -> bool {
    match std::env::var("PI_BYTECODE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `is_raw_bytecode(code)`.
fn is_raw_bytecode(code: &str) -> bool {
    let mut cleaned = WS.replace_all(code, "").to_lowercase();
    if cleaned.starts_with("0x") {
        cleaned = cleaned[2..].to_string();
    }
    HEX_ALL.is_match(&cleaned) && cleaned.chars().count() >= 10
}

/// Slice `s` by *character* index (Python str slicing semantics) and count the
/// number of `'\n'` characters in `s[..char_end]`. Mirrors
/// `code[:start_idx].count('\n')` where `start_idx` is a char index.
fn newlines_before_char(s: &str, char_end: usize) -> usize {
    s.chars()
        .take(char_end)
        .filter(|&c| c == '\n')
        .count()
}

pub fn audit_bytecode(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    if is_raw_bytecode(code) {
        // Mode 1: Raw EVM Bytecode Threat Audit
        let mut bytecode_hex = WS.replace_all(code, "").to_lowercase();
        if bytecode_hex.starts_with("0x") {
            bytecode_hex = bytecode_hex[2..].to_string();
        }

        if bytecode_hex.contains("ff") {
            vulnerable_funcs.push("raw_bytecode".to_string());
            flagged_findings.push(
                "Raw EVM bytecode contains the SELFDESTRUCT opcode (0xff) which can cause sudden contract destruction.".to_string(),
            );
        }
        if bytecode_hex.contains("f4") {
            vulnerable_funcs.push("raw_bytecode".to_string());
            flagged_findings.push(
                "Raw EVM bytecode contains the DELEGATECALL opcode (0xf4) which poses arbitrary execution hazards.".to_string(),
            );
        }
    } else {
        // Mode 2: Solidity Inline Assembly Audit & Gas Efficiency Check
        // Clean comments
        let code_clean = LINE_COMMENT.replace_all(code, "");
        let code_clean = BLOCK_COMMENT.replace_all(&code_clean, "").to_string();

        // Find inline assembly blocks: assembly { ... }
        for (i, caps) in ASSEMBLY.captures_iter(&code_clean).enumerate() {
            let m = caps.get(0).unwrap();
            let block_content = caps.get(1).map(|g| g.as_str()).unwrap_or("");
            // Python: start_idx = match.start() (char index into code_clean)
            let start_byte = m.start();
            let char_start = code_clean[..start_byte].chars().count();
            // Python: start_line = code[:start_idx].count('\n') + 1
            // (intentionally slices the ORIGINAL `code` at the cleaned offset)
            let start_line = newlines_before_char(code, char_start) + 1;

            // Check for selfdestruct or delegatecall inside assembly block
            if block_content.contains("selfdestruct(") || block_content.contains("suicide(") {
                vulnerable_funcs.push(format!("assembly_block_{}", i + 1));
                flagged_findings.push(format!(
                    "Inline assembly block on Line {start_line} contains a selfdestruct opcode call."
                ));
            }
            if block_content.contains("delegatecall(") {
                // Let's see if it's safe (EIP-1967 proxy storage slot reference).
                if !code_clean
                    .contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
                {
                    vulnerable_funcs.push(format!("assembly_block_{}", i + 1));
                    flagged_findings.push(format!(
                        "Inline assembly block on Line {start_line} uses delegatecall without EIP-1967 slot safety."
                    ));
                }
            }

            // Gas efficiency: warn on manual writes to reserved scratch space.
            if block_content.contains("mstore(") && block_content.contains("0x40") {
                if let Some(bad) = BAD_SCRATCH.captures(block_content) {
                    let whole = bad.get(0).unwrap().as_str();
                    flagged_findings.push(format!(
                        "Optimization warning: Inline assembly block on Line {start_line} writes to reserved scratch space memory: {whole}"
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
            status = "REJECTED_BYTECODE_VULNERABILITY".to_string();
        } else {
            status = "WARN_BYTECODE_VULNERABILITY".to_string();
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
    let out = audit_bytecode(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_bytecode(&Input {
            file_path: "f.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_solidity_passes() {
        std::env::remove_var("PI_BYTECODE_STRICT_MODE");
        std::env::set_var("PI_BYTECODE_STRICT_MODE", "true");
        let o = run("function ok() public { assembly { let x := mload(0x40) } }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        std::env::remove_var("PI_BYTECODE_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn raw_bytecode_selfdestruct_flagged() {
        std::env::set_var("PI_BYTECODE_STRICT_MODE", "true");
        // 12 hex chars including "ff" -> raw bytecode path
        let o = run("0x60606040ff52");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_BYTECODE_VULNERABILITY");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["raw_bytecode"]);
        std::env::remove_var("PI_BYTECODE_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn assembly_selfdestruct_warn_mode_coerces_secure() {
        std::env::set_var("PI_BYTECODE_STRICT_MODE", "false");
        let o = run("function nuke() public { assembly { selfdestruct(0) } }");
        // not strict -> WARN status, is_secure coerced back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_BYTECODE_VULNERABILITY");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["assembly_block_1"]);
        std::env::remove_var("PI_BYTECODE_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn delegatecall_with_eip1967_slot_is_safe() {
        std::env::set_var("PI_BYTECODE_STRICT_MODE", "true");
        let code = "bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc; \
function p() public { assembly { let r := delegatecall(gas(), impl, 0, 0, 0, 0) } }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        std::env::remove_var("PI_BYTECODE_STRICT_MODE");
    }
}
