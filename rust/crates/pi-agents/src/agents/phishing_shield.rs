//! Port of `pi_micro_agents/pi_phishing_shield.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for callback
//! `msg.sender` phishing vectors and EIP-3009/EIP-2612 permit (`deadline`)
//! compliance. Behaviour is a line-for-line mirror of the Python original.
//!
//! The Python original does NOT use `.splitlines()` / `.strip()`; it extracts
//! function bodies with a manual brace-matching scanner (`extract_solidity_
//! functions`) and then applies substring/regex checks. Python `str` indexing
//! is by Unicode code point, so this port scans over a `Vec<char>` and maps the
//! regex (byte-offset) match starts to char indices to stay byte-faithful even
//! for non-ASCII input.

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

// re.compile(r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(')
// 2 capture groups -> captures_iter. No flags. `[a-zA-Z0-9_]*` group 2 may match
// the empty string. The Rust regex crate has no lookaround/backrefs; none used.
static FUNC_DECL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// re.sub(r'//.*', '', func_body) — `.` does not span newlines in either engine,
// so this strips a `//` line comment to the end of its line.
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL) -> `(?s)`.
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python resolution order:
///   1. env `PI_PHISHING_STRICT_MODE` -> `value.lower() == "true"`
///   2. `~/.antigravitycli/config.json` then the in-repo
///      `../../.antigravitycli/config.json`, reading the
///      `PI_PHISHING_STRICT_MODE` key (default `True`)
///   3. default `True`
///
/// The config-file fallback is environment-dependent; in this repo the config
/// file is absent / lacks the key, so `data.get(..., True)` yields `True`.
/// Therefore, when the env var is unset the effective result is `true`, which
/// this function reproduces. The config-file branch is intentionally collapsed
/// to the default-True behaviour — see `deviations` in the parity report.
fn is_strict_mode() -> bool {
    match std::env::var("PI_PHISHING_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirror of Python `extract_solidity_functions`.
///
/// Returns `(func_name, func_body, start_line)` triples. Indexing follows
/// Python's code-point semantics: the scan and all slices operate on a
/// `Vec<char>`, and regex match starts (byte offsets) are converted to char
/// indices.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let mut functions: Vec<(String, String, usize)> = Vec::new();
    let chars: Vec<char> = solidity_code.chars().collect();
    let code_len = chars.len();

    for caps in FUNC_DECL_RE.captures_iter(solidity_code) {
        let m = caps.get(0).unwrap();
        let keyword = caps.get(1).map(|g| g.as_str()).unwrap_or("");
        let name = caps.get(2).map(|g| g.as_str()).unwrap_or("");

        let func_name: String = if keyword == "function" {
            name.to_string()
        } else if keyword == "constructor" {
            "constructor".to_string()
        } else if keyword == "fallback" {
            "fallback".to_string()
        } else {
            "receive".to_string()
        };

        // start_idx = match.start() — char index (Python str index).
        let start_idx = solidity_code[..m.start()].chars().count();

        // start_line = solidity_code[:start_idx].count('\n') + 1
        let start_line = chars[..start_idx].iter().filter(|&&c| c == '\n').count() + 1;

        // semicolon_idx = solidity_code.find(';', start_idx)  (-1 if absent)
        let semicolon_idx = find_char(&chars, ';', start_idx);
        // brace_idx = solidity_code.find('{', start_idx)
        let brace_idx = find_char(&chars, '{', start_idx);

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue
        if brace_idx == -1 || (semicolon_idx != -1 && semicolon_idx < brace_idx) {
            continue;
        }
        let brace_idx = brace_idx as usize;

        let mut brace_count: i64 = 1;
        let mut curr_idx = brace_idx + 1;
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
            let func_body: String = chars[start_idx..curr_idx].iter().collect();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

/// Mirror of Python `str.find(ch, start)`: first index of `ch` at or after
/// `start`, or `-1` when absent.
fn find_char(chars: &[char], target: char, start: usize) -> i64 {
    let mut i = start;
    while i < chars.len() {
        if chars[i] == target {
            return i as i64;
        }
        i += 1;
    }
    -1
}

pub fn audit_phishing(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    for (func_name, func_body, start_line) in functions {
        // cleaned_body = re.sub(r'//.*', '', func_body)
        let cleaned_body = LINE_COMMENT_RE.replace_all(&func_body, "");
        // cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "").to_string();

        let func_name_lower = func_name.to_lowercase();

        // Mode 1: msg.sender phishing vector.
        if func_name_lower.contains("ontokentransfer") || func_name_lower.contains("tokensreceived")
        {
            // if "msg.sender" in cleaned_body and not any(check in cleaned_body
            //     for check in ["require(", "revert("]):
            if cleaned_body.contains("msg.sender")
                && !(cleaned_body.contains("require(") || cleaned_body.contains("revert("))
            {
                vulnerable_funcs.push(func_name.clone());
                flagged_findings.push(format!(
                    "Function '{func_name}' on Line {start_line} acts as a token transfer callback \
but accesses 'msg.sender' without explicit validation or require gates, risking message-sender phishing attacks."
                ));
            }
        }

        // Mode 2: EIP-3009/EIP-2612 permit compliance.
        if func_name_lower.contains("permit") {
            let cleaned_body_lower = cleaned_body.to_lowercase();
            // if "deadline" in cleaned_body.lower() and not any(cond in
            //     cleaned_body.lower() for cond in ["block.timestamp", "now"]):
            if cleaned_body_lower.contains("deadline")
                && !(cleaned_body_lower.contains("block.timestamp")
                    || cleaned_body_lower.contains("now"))
            {
                flagged_findings.push(format!(
                    "Permit Warning: Function '{func_name}' on Line {start_line} accepts a 'deadline' parameter \
but does not validate it against the current block.timestamp, violating EIP-2612 specification guidelines."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_PHISHING_RISK".to_string();
        } else {
            status = "WARN_PHISHING_RISK".to_string();
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
    let out = audit_phishing(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_phishing(&Input {
            file_path: "Token.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[serial]
    #[test]
    fn clean_contract_passes() {
        std::env::remove_var("PI_PHISHING_STRICT_MODE");
        let o = run(
            "function totalSupply() public view returns (uint256) { return _totalSupply; }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[serial]
    #[test]
    fn callback_msg_sender_rejected_strict() {
        std::env::set_var("PI_PHISHING_STRICT_MODE", "true");
        let o = run(
            "function onTokenTransfer(address from, uint256 amount) external { balances[msg.sender] += amount; }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_PHISHING_RISK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["onTokenTransfer"]);
        std::env::remove_var("PI_PHISHING_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn callback_with_require_is_safe() {
        std::env::remove_var("PI_PHISHING_STRICT_MODE");
        let o = run(
            "function tokensReceived(address operator) external { require(msg.sender == token); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[serial]
    #[test]
    fn callback_non_strict_warns_and_secure() {
        std::env::set_var("PI_PHISHING_STRICT_MODE", "false");
        let o = run(
            "function onTokenTransfer(address from, uint256 amount) external { balances[msg.sender] += amount; }",
        );
        // non-strict coerces is_secure back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_PHISHING_RISK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["onTokenTransfer"]);
        std::env::remove_var("PI_PHISHING_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn permit_without_timestamp_warns_but_secure() {
        std::env::remove_var("PI_PHISHING_STRICT_MODE");
        let o = run(
            "function permit(address owner, uint256 deadline) external { _approve(owner, value); }",
        );
        // Permit warning does not add to vulnerable_functions -> still secure.
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
        assert_eq!(o.flagged_findings.len(), 1);
    }
}
