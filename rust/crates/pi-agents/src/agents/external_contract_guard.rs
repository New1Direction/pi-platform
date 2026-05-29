//! Port of `pi_micro_agents/pi_external_contract_guard.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for untrusted
//! external contract calls and ERC-20 interface mismatches. Behaviour is a
//! line-for-line mirror of the Python original.

// NOTE: this agent does not use pyutil::splitlines / pyutil::strip — the Python
// original never calls `.splitlines()` or `.strip()`. Function extraction is
// done by regex + manual brace matching with code-point indexing (mirrored here
// via a `Vec<char>`), and all other matching is whole-string regex / substring.
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
// This agent does not call `.splitlines()` / `.strip()` in the Python original,
// so `crate::pyutil` is intentionally not imported.

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

// re.compile(r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(')
// 2 capture groups -> captures_iter. No flags.
static FUNC_DECL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// re.search(r'\bfunction\b\s+([a-zA-Z0-9_]+)\s*\(\s*address\s+([a-zA-Z0-9_]+)\b', func_body)
// 2 capture groups. No flags.
static ADDRESS_PARAM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bfunction\b\s+([a-zA-Z0-9_]+)\s*\(\s*address\s+([a-zA-Z0-9_]+)\b").unwrap()
});

// re.sub(r'//.*', '', s) — `.` does not match newline (no DOTALL), same default
// in Python and the Rust regex crate.
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// re.sub(r'/\*.*?\*/', '', s, flags=re.DOTALL) -> (?s) so `.` spans newlines.
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

/// Mirrors `extract_solidity_functions(solidity_code)` returning
/// `(func_name, func_body, start_line)` tuples.
///
/// Indexing is by Unicode code point (a `Vec<char>`) to match Python's `str`
/// indexing semantics for `.find(...)`, slicing, and `start_idx`/`curr_idx`
/// arithmetic exactly. The regex returns byte offsets, which are converted to
/// code-point indices below.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let mut functions: Vec<(String, String, usize)> = Vec::new();

    // chars[i] is the i-th code point; char_byte[i] is its byte offset.
    let chars: Vec<char> = solidity_code.chars().collect();
    let char_byte: Vec<usize> = solidity_code.char_indices().map(|(b, _)| b).collect();
    let code_len = chars.len();

    // Map a byte offset (from the regex) to a code-point index.
    let byte_to_char_idx = |byte: usize| -> usize {
        // char_byte is sorted ascending; find first entry == byte.
        match char_byte.binary_search(&byte) {
            Ok(i) => i,
            // byte should always land on a char boundary for match starts.
            Err(i) => i,
        }
    };

    // Build a code-point substring helper: solidity_code[a:b] in Python terms.
    let slice = |a: usize, b: usize| -> String { chars[a..b].iter().collect() };

    for caps in FUNC_DECL_RE.captures_iter(solidity_code) {
        let keyword = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let name = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        let func_name: String = if keyword == "function" {
            name.to_string()
        } else if keyword == "constructor" {
            "constructor".to_string()
        } else if keyword == "fallback" {
            "fallback".to_string()
        } else {
            "receive".to_string()
        };

        // start_idx = match.start()  (Python: code-point index)
        let start_byte = caps.get(0).unwrap().start();
        let start_idx = byte_to_char_idx(start_byte);

        // start_line = solidity_code[:start_idx].count('\n') + 1
        let start_line = chars[..start_idx].iter().filter(|&&c| c == '\n').count() + 1;

        // semicolon_idx = solidity_code.find(';', start_idx)  (-1 if not found)
        let semicolon_idx: i64 = chars[start_idx..]
            .iter()
            .position(|&c| c == ';')
            .map(|p| (start_idx + p) as i64)
            .unwrap_or(-1);
        // brace_idx = solidity_code.find('{', start_idx)
        let brace_idx_opt: Option<usize> = chars[start_idx..]
            .iter()
            .position(|&c| c == '{')
            .map(|p| start_idx + p);
        let brace_idx: i64 = brace_idx_opt.map(|v| v as i64).unwrap_or(-1);

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue
        if brace_idx == -1 || (semicolon_idx != -1 && semicolon_idx < brace_idx) {
            continue;
        }

        let brace_idx_u = brace_idx as usize;
        let mut brace_count: i64 = 1;
        let mut curr_idx = brace_idx_u + 1;
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
            // func_body = solidity_code[start_idx:curr_idx]
            let func_body = slice(start_idx, curr_idx);
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

/// Mirrors `is_strict_mode()`.
///
/// Python resolution order:
///   1. env `PI_EXTERNAL_STRICT_MODE` -> `value.lower() == "true"`
///   2. `~/.antigravitycli/config.json` then the in-repo
///      `../../.antigravitycli/config.json`, reading the
///      `PI_EXTERNAL_STRICT_MODE` key with `bool(data.get(..., True))`
///   3. default True
///
/// The config-file fallback is environment-dependent and is intentionally
/// collapsed to the default-True behaviour here (env var only). See `deviations`
/// in the parity report.
fn is_strict_mode() -> bool {
    match std::env::var("PI_EXTERNAL_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_external(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    // Clean comments (computed in the Python original but never used; preserved
    // for fidelity, has no effect on output).
    let code_clean = LINE_COMMENT_RE.replace_all(code, "").into_owned();
    let _code_clean = BLOCK_COMMENT_RE.replace_all(&code_clean, "").into_owned();

    for (func_name, func_body, start_line) in &functions {
        // cleaned_body = re.sub(r'//.*', '', func_body); then strip block comments (DOTALL)
        let cleaned_body = LINE_COMMENT_RE.replace_all(func_body, "").into_owned();
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "").into_owned();

        // Mode 1: Untrusted External Contract call checking
        // address_param_match = re.search(..., func_body)  (note: raw func_body)
        if let Some(caps) = ADDRESS_PARAM_RE.captures(func_body) {
            let setter_func = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let param_name = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();

            // re.search(r'\b' + re.escape(param_name) + r'\s*=\s*[a-zA-Z0-9_]+', cleaned_body)
            let assign_pat = format!(
                r"\b{}\s*=\s*[a-zA-Z0-9_]+",
                regex::escape(&param_name)
            );
            let assign_re = Regex::new(&assign_pat).unwrap();
            if assign_re.is_match(&cleaned_body) {
                // if not any(check in cleaned_body for check in ["address(0)", "0x0"])
                let has_check =
                    cleaned_body.contains("address(0)") || cleaned_body.contains("0x0");
                if !has_check {
                    vulnerable_funcs.push(setter_func.clone());
                    flagged_findings.push(format!(
                        "Function '{setter_func}' on Line {start_line} accepts external address parameter '{param_name}' \
and assigns it without checking if it is address(0), risking silent bricking or logic failures."
                    ));
                }
            }
        }

        // Mode 2: Interface Match check
        // if "transfer(" in cleaned_body or "transferfrom(" in cleaned_body:
        if cleaned_body.contains("transfer(") || cleaned_body.contains("transferfrom(") {
            // if not any(safe in cleaned_body.lower() for safe in ["safetransfer", "require(", "assert("])
            let lower = cleaned_body.to_lowercase();
            let has_safe = lower.contains("safetransfer")
                || lower.contains("require(")
                || lower.contains("assert(");
            if !has_safe {
                flagged_findings.push(format!(
                    "Interface Warning: Function '{func_name}' on Line {start_line} performs a raw ERC-20 transfer \
or transferFrom call without wrapping it in SafeERC20 or verifying its return value boolean."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_EXTERNAL_RISK".to_string();
        } else {
            status = "WARN_EXTERNAL_RISK".to_string();
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
    let out = audit_external(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_external(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn safe_contract_passes() {
        // Has require() so the transfer is considered checked; no address setter.
        std::env::remove_var("PI_EXTERNAL_STRICT_MODE");
        let o = run("function send(uint a) public { require(a > 0); token.transfer(b, a); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        // No safe-wrapper finding because require( is present.
        assert!(o.flagged_findings.is_empty());
    }

    // NOTE on the Python quirk mirrored here: Mode 1 only fires when the
    // *parameter name itself* appears on the LHS of an assignment
    // (`param = ...`), not `stateVar = param`. So the param `owner` is
    // reassigned below to trigger the finding.
    #[test]
    #[serial]
    fn unchecked_address_setter_rejected_in_strict() {
        std::env::remove_var("PI_EXTERNAL_STRICT_MODE");
        let o = run("function setOwner(address owner) public { owner = resolve(); }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_EXTERNAL_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["setOwner"]);
    }

    #[test]
    #[serial]
    fn unchecked_address_setter_warns_when_not_strict() {
        std::env::set_var("PI_EXTERNAL_STRICT_MODE", "false");
        let o = run("function setOwner(address owner) public { owner = resolve(); }");
        // is_secure coerced back to true in non-strict mode.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_EXTERNAL_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["setOwner"]);
        std::env::remove_var("PI_EXTERNAL_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn raw_transfer_flagged_without_vulnerable_func() {
        std::env::remove_var("PI_EXTERNAL_STRICT_MODE");
        let o = run("function payout() public { token.transfer(to, amount); }");
        // Interface warning is a finding but not a vulnerable_function, so secure.
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.vulnerable_functions.len(), 0);
        assert_eq!(o.flagged_findings.len(), 1);
    }
}
