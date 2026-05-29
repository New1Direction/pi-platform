//! Port of `pi_micro_agents/pi_tx_origin_sentry.py`.
//!
//! Audits Solidity contracts for unsafe `tx.origin` authentication and
//! EIP-2771 (meta-transaction) compliance. Behaviour mirrors the Python
//! original line-for-line.

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
/// PARITY NOTE: the Python original, when the env var is unset, also consults
/// `~/.antigravitycli/config.json` and then `<repo>/.antigravitycli/config.json`,
/// defaulting to `True` if the file is missing or the key is absent/truthy. The
/// Rust port only honours the env var and otherwise returns `true`. This matches
/// Python whenever the config file is absent or sets the key to a truthy value;
/// it diverges only if a config file explicitly sets the key to a falsy value
/// while the env var is unset. See the parity spec, which pins the env var on
/// strict-mode-sensitive samples to keep both sides deterministic.
fn is_strict_mode() -> bool {
    match std::env::var("PI_TXORIGIN_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// `\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(`
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// `//.*`  -- line comments (no DOTALL: `.` does not match `\n`).
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// `/\*.*?\*/` with re.DOTALL -> `(?s)`.
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

/// Mirrors `extract_solidity_functions`. Returns `(func_name, func_body, start_line)`.
///
/// Index arithmetic is done over the char sequence (mirroring Python `str`
/// semantics where indices and `.find()` operate on code points).
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let chars: Vec<char> = solidity_code.chars().collect();
    let code_len = chars.len();

    // Map from byte offset -> char index, so we can translate regex byte
    // positions to Python-style char positions.
    let mut byte_to_char: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (ci, (bpos, _)) in solidity_code.char_indices().enumerate() {
        byte_to_char.insert(bpos, ci);
    }

    let mut functions: Vec<(String, String, usize)> = Vec::new();

    for caps in FUNC_RE.captures_iter(solidity_code) {
        let keyword = caps.get(1).unwrap().as_str();
        let name = caps.get(2).unwrap().as_str();
        let func_name = match keyword {
            "function" => name.to_string(),
            "constructor" => "constructor".to_string(),
            "fallback" => "fallback".to_string(),
            _ => "receive".to_string(),
        };

        let m = caps.get(0).unwrap();
        let start_idx = *byte_to_char.get(&m.start()).unwrap();

        // start_line = solidity_code[:start_idx].count('\n') + 1
        let start_line = chars[..start_idx].iter().filter(|&&c| c == '\n').count() + 1;

        // solidity_code.find(';', start_idx) / .find('{', start_idx)
        let semicolon_idx = find_char_from(&chars, ';', start_idx);
        let brace_idx = find_char_from(&chars, '{', start_idx);

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue
        let brace_pos = match brace_idx {
            None => continue,
            Some(b) => b,
        };
        if let Some(s) = semicolon_idx {
            if s < brace_pos {
                continue;
            }
        }

        let mut brace_count: i64 = 1;
        let mut curr_idx = brace_pos + 1;
        while curr_idx < code_len && brace_count > 0 {
            let ch = chars[curr_idx];
            if ch == '{' {
                brace_count += 1;
            } else if ch == '}' {
                brace_count -= 1;
            }
            curr_idx += 1;
        }

        if brace_count == 0 {
            let func_body: String = chars[start_idx..curr_idx].iter().collect();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

/// Python `str.find(ch, start)` over a char slice: returns the char index of the
/// first occurrence at or after `start`, or `None` (Python's `-1`).
fn find_char_from(chars: &[char], target: char, start: usize) -> Option<usize> {
    if start > chars.len() {
        return None;
    }
    chars[start..]
        .iter()
        .position(|&c| c == target)
        .map(|p| p + start)
}

pub fn audit_tx_origin(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    // is_eip2771_compliant = "erc2771" in code.lower() or "istrustedforwarder" in code.lower()
    let code_lower = code.to_lowercase();
    let is_eip2771_compliant =
        code_lower.contains("erc2771") || code_lower.contains("istrustedforwarder");

    for (func_name, func_body, start_line) in &functions {
        // Clean comments
        let cleaned_body = LINE_COMMENT_RE.replace_all(func_body, "");
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "");
        let cleaned_body: &str = &cleaned_body;

        // Mode 1: tx.origin Phishing Scan
        if cleaned_body.contains("tx.origin") {
            vulnerable_funcs.push(func_name.clone());
            flagged_findings.push(format!(
                "Function '{func_name}' on Line {start_line} uses 'tx.origin' for authorization/verification, \
which makes the contract highly vulnerable to phishing attacks (via malicious intermediary smart contracts)."
            ));
        }

        // Mode 2: EIP-2771 Compliance Check
        if is_eip2771_compliant && cleaned_body.contains("msg.sender") {
            if !cleaned_body.contains("_msgSender(") {
                flagged_findings.push(format!(
                    "Compliance warning: Function '{func_name}' on Line {start_line} accesses msg.sender directly \
in an ERC-2771 context. Recommend using standard EIP-2771 message sender helper '_msgSender()' instead."
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
            status = "REJECTED_TXORIGIN_VULNERABILITY".to_string();
        } else {
            status = "WARN_TXORIGIN_VULNERABILITY".to_string();
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
    let out = audit_tx_origin(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_tx_origin(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_contract_passes() {
        std::env::set_var("PI_TXORIGIN_STRICT_MODE", "true");
        let o = run("contract C { function f() public { require(msg.sender == owner); } }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        std::env::remove_var("PI_TXORIGIN_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn tx_origin_rejected_in_strict_mode() {
        std::env::set_var("PI_TXORIGIN_STRICT_MODE", "true");
        let o = run("contract C { function login() public { require(tx.origin == owner); } }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TXORIGIN_VULNERABILITY");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["login"]);
        std::env::remove_var("PI_TXORIGIN_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn tx_origin_warn_in_non_strict_mode() {
        std::env::set_var("PI_TXORIGIN_STRICT_MODE", "false");
        let o = run("contract C { function login() public { require(tx.origin == owner); } }");
        // is_secure coerced back to true in WARN path
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_TXORIGIN_VULNERABILITY");
        assert_eq!(o.vulnerable_functions, vec!["login"]);
        std::env::remove_var("PI_TXORIGIN_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn eip2771_compliance_warning() {
        std::env::set_var("PI_TXORIGIN_STRICT_MODE", "true");
        let o = run(
            "import ERC2771Context; contract C { function f() public { address a = msg.sender; } }",
        );
        // No tx.origin -> secure, but a compliance finding is emitted.
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("Compliance warning"));
        std::env::remove_var("PI_TXORIGIN_STRICT_MODE");
    }
}
