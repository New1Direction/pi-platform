//! Port of `pi_micro_agents/pi_solidity_flash_loan_attack.py`.
//!
//! Specialized DeFi micro-agent that audits Solidity contracts for vulnerable
//! flash loan integration patterns. Behaviour is a line-for-line mirror of the
//! Python original.
//!
//! Parity note: the Python source extracts function blocks with the regex
//!     `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)`
//! which uses a lookahead `(?=...)` that the Rust `regex` crate cannot express.
//! We therefore match only the prefix portion
//!     `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{`
//! with `regex`, then compute the body end manually by replicating the
//! non-greedy `[\s\S]*?(?=\n\s*function|\Z)` terminator: the body extends from
//! just after the opening `{` up to (but not including) the first literal `\n`
//! that is followed by zero or more whitespace characters and then the literal
//! word `function`, or to end-of-string. Scanning then continues from that body
//! end position, exactly mirroring `re.finditer`'s non-overlapping advance over
//! a zero-width lookahead terminator.

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

/// Prefix of the Python function-block regex (everything up to and including
/// the opening brace). `(?s)` is intentionally NOT set, so `.` (used in the
/// args group `(.*?)`) does not match `\n`, exactly like the Python default.
static FUNC_PREFIX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

/// Mirrors `re.search(r'(msg\.sender\s*==\s*[a-zA-Z0-9_]+)', body)`.
static SENDER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"msg\.sender\s*==\s*[a-zA-Z0-9_]+").unwrap());

/// Mirrors `is_strict_mode()`: the env var, when present, decides (case
/// insensitive "true" == strict). When absent, Python consults an
/// `~/.antigravitycli/config.json` (or a sibling fallback) and defaults to
/// strict (True) when that file is missing or unreadable. We mirror only the
/// env-var precedence and the missing-config default of `true`. See
/// `deviations`: the config-file branch is not replicated.
fn is_strict_mode() -> bool {
    match std::env::var("PI_SOLIDITY_FLASH_LOAN_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Returns true if `\s*` matches the whitespace run starting at byte index
/// `i` within `bytes` and the literal word `function` follows immediately
/// after that run. Mirrors the lookahead `\s*function` applied right after a
/// literal `\n`. `\s` here uses the ASCII whitespace set plus the additional
/// characters Python's `\s` recognizes for `str` patterns are not handled
/// specially; for parity with the Python default `\s` we rely on
/// `char::is_whitespace`, which covers the same practical inputs.
fn whitespace_then_function(s: &str, mut i: usize) -> bool {
    let bytes = s.as_bytes();
    while i < bytes.len() {
        // Decode the char at byte position `i`.
        let ch = s[i..].chars().next().unwrap();
        if ch.is_whitespace() {
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    s[i..].starts_with("function")
}

/// Computes the body-end byte offset given the byte offset `body_start`
/// (just after the opening `{`), replicating the non-greedy
/// `[\s\S]*?(?=\n\s*function|\Z)` terminator.
fn find_body_end(s: &str, body_start: usize) -> usize {
    let bytes = s.as_bytes();
    let mut i = body_start;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            // Position right after the newline.
            let after = i + 1;
            if whitespace_then_function(s, after) {
                return i; // body ends just before this newline
            }
        }
        // Advance one char.
        let ch = s[i..].chars().next().unwrap();
        i += ch.len_utf8();
    }
    // No terminator found -> body runs to end of string (\Z).
    s.len()
}

pub fn audit_flash_loan(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Replicate `re.findall` over the lookahead-terminated pattern: find the
    // prefix, then determine the body via the manual terminator, then continue
    // scanning from the body-end position (the zero-width lookahead means the
    // overall match ends at the body end).
    let mut search_pos = 0usize;
    while search_pos <= code.len() {
        let caps = match FUNC_PREFIX_RE.captures_at(code, search_pos) {
            Some(c) => c,
            None => break,
        };
        let name = caps.get(1).unwrap().as_str();
        let args = caps.get(2).unwrap().as_str();
        // Byte offset just after the opening `{` (end of the whole prefix match).
        let body_start = caps.get(0).unwrap().end();
        let body_end = find_body_end(code, body_start);
        let body = &code[body_start..body_end];

        // ----- per-function vulnerability logic (line-for-line) -----
        let name_lower = name.to_lowercase();
        if ["executeoperation", "flashloan", "receiveflashloan"]
            .iter()
            .any(|x| name_lower.contains(x))
        {
            let mut has_sender_verification = false;
            if SENDER_RE.is_match(body) {
                has_sender_verification = true;
            }
            if args.contains("onlyPool")
                || args.contains("onlyLendingPool")
                || body.contains("onlyPool")
                || body.contains("onlyLendingPool")
            {
                has_sender_verification = true;
            }

            if !has_sender_verification {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Flash loan callback function '{name}' is implemented but lacks structural \
verification of the caller ('msg.sender'). An attacker could call this callback directly \
to manipulate internal storage structures or drain contract reserves."
                ));
            }
        }

        // Advance to the body-end (zero-width lookahead terminator). Guard
        // against non-advancing matches (empty body at search_pos) to avoid an
        // infinite loop while preserving find-the-next-match semantics.
        if body_end > search_pos {
            search_pos = body_end;
        } else {
            // Body ended at or before where we started; step forward one char.
            let next = body_end
                + code[body_end..]
                    .chars()
                    .next()
                    .map(|c| c.len_utf8())
                    .unwrap_or(1);
            search_pos = next;
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_FLASH_LOAN".to_string();
        } else {
            status = "WARN_FLASH_LOAN".to_string();
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
    let out = audit_flash_loan(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_flash_loan(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_contract_passes() {
        let code = "contract C {\n    function executeOperation(address a) external returns (bool) {\n        require(msg.sender == pool);\n    }\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn vulnerable_callback_flagged() {
        let code = "contract C {\n    function executeOperation(address a) external returns (bool) {\n        drain();\n    }\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_FLASH_LOAN");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["executeOperation"]);
    }

    #[test]
    fn modifier_in_body_is_safe() {
        // `onlyLendingPool` appearing in the body marks the callback safe.
        let code = "function receiveFlashLoan(uint amt) external {\n    onlyLendingPool();\n    doThing();\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn modifier_after_parens_is_still_flagged() {
        // Parity gotcha: `onlyPool` in the Solidity modifier position (after the
        // parens) is NOT captured by the args group `(.*?)`, so the function is
        // still flagged — matching the Python original exactly.
        let code = "function flashLoan(uint amt) onlyPool external {\n    doThing();\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["flashLoan"]);
    }

    #[test]
    fn non_callback_function_ignored() {
        let code = "function transfer(address to, uint amt) public {\n    balances[to] += amt;\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
