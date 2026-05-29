//! Port of `pi_micro_agents/pi_solidity_erc20_transfer_recipient_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity code to ensure ERC20
//! transfers validate the target recipient address (not `address(0)`,
//! `address(this)`, or a `0x0` dead address) to prevent lost/locked funds.
//! Behaviour is a line-for-line mirror of the Python original.

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

// Python (line 56):
//   re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)', code)
//
// The Rust `regex` crate does NOT support the trailing lookahead `(?=...)`. The
// lookahead is emulated manually: we match the prefix (everything up to and
// including the opening `{`) with `FUNC_PREFIX_RE`, then take the body as the
// shortest span from the end of that match until either `\n\s*function`
// (BODY_END_RE) or end-of-string -- exactly what the lazy `([\s\S]*?)` followed
// by the lookahead `(?=\n\s*function|\Z)` produces.
//
// NOTE: there is no DOTALL flag, so `.` (in `(.*?)`) does not match a newline,
// matching Rust's default. `[\s\S]` explicitly matches any char incl. newline.
// The next `re.findall` iteration resumes from the END of the (zero-width
// lookahead) match, i.e. from the computed body end.
static FUNC_PREFIX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

// Python lookahead alternative `\n\s*function` — the body terminator.
static BODY_END_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n\s*function").unwrap());

// Python (line 60):
//   re.findall(r'\.\s*(transfer|transferFrom)\s*\(([^)]+)\)', body)
// Two capture groups -> captures_iter, yielding (method, params).
static TRANSFER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.\s*(transfer|transferFrom)\s*\(([^)]+)\)").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var
/// `PI_TRANSFER_RECIPIENT_STRICT_MODE` is set to a value that is not
/// (case-insensitively) "true".
///
/// DEVIATION: the Python original additionally falls back to reading
/// `~/.antigravitycli/config.json` (then a module-relative
/// `.antigravitycli/config.json`) when the env var is unset. That fallback
/// defaults to `True` (strict) when the file is missing or unparseable, so the
/// env-var-only behaviour here matches the Python default. We do NOT read the
/// config file; callers should set the env var explicitly to exercise the
/// non-strict branch.
fn is_strict_mode() -> bool {
    match std::env::var("PI_TRANSFER_RECIPIENT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_transfer_recipient(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all function blocks (re.findall with 3 groups: name, args, body),
    // emulating the trailing lookahead manually.
    let mut pos = 0usize;
    while pos <= code.len() {
        let caps = match FUNC_PREFIX_RE.captures_at(code, pos) {
            Some(c) => c,
            None => break,
        };
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // Group 2 (args) is captured by Python but unused in the loop body.
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        let body_start = caps.get(0).unwrap().end();
        // Lazy `([\s\S]*?)(?=\n\s*function|\Z)` => shortest body until the next
        // `\n\s*function` or end of string.
        let body_end = match BODY_END_RE.find_at(code, body_start) {
            Some(m) => m.start(),
            None => code.len(),
        };
        let body = &code[body_start..body_end];

        // Match transfers: token.transfer(recipient, amount) or
        // token.transferFrom(sender, recipient, amount).
        let transfers: Vec<(&str, &str)> = TRANSFER_RE
            .captures_iter(body)
            .map(|c| {
                (
                    c.get(1).map(|m| m.as_str()).unwrap_or(""),
                    c.get(2).map(|m| m.as_str()).unwrap_or(""),
                )
            })
            .collect();

        if !transfers.is_empty() {
            for (method, params) in &transfers {
                // Python: param_list = [p.strip() for p in params.split(",")]
                let param_list: Vec<String> = params
                    .split(',')
                    .map(|p| pyutil::strip(p).to_string())
                    .collect();
                if !param_list.is_empty() {
                    // recipient = first param for "transfer", second for
                    // "transferFrom" (or "" if missing).
                    let recipient: String = if *method == "transfer" {
                        param_list[0].clone()
                    } else if param_list.len() > 1 {
                        param_list[1].clone()
                    } else {
                        String::new()
                    };
                    if !recipient.is_empty() {
                        // Check if body contains validations for this recipient.
                        let mut has_validation = false;
                        // Python patterns (recipient interpolated raw, NOT escaped):
                        //   address\s*\(\s*0\s*\)
                        //   address\s*\(\s*this\s*\)
                        //   0x0
                        let patterns = [
                            r"address\s*\(\s*0\s*\)",
                            r"address\s*\(\s*this\s*\)",
                            r"0x0",
                        ];
                        for pat in patterns.iter() {
                            // Python builds two dynamic regexes with the recipient
                            // text interpolated *without* re.escape, so any regex
                            // metacharacters in `recipient` act as regex syntax.
                            // We mirror this exactly (no escaping). If the pattern
                            // fails to compile, Python's re.compile would raise;
                            // here we treat a compile failure as "no match" for
                            // that pattern (see deviations) and continue.
                            let p1 =
                                format!(r"require\s*\(\s*{recipient}\s*!=\s*{pat}");
                            let p2 =
                                format!(r"require\s*\(\s*{pat}\s*!=\s*{recipient}");
                            let m1 = Regex::new(&p1).map(|re| re.is_match(body)).unwrap_or(false);
                            let m2 = Regex::new(&p2).map(|re| re.is_match(body)).unwrap_or(false);
                            if m1 || m2 {
                                has_validation = true;
                                break;
                            }
                        }

                        if !has_validation {
                            vulnerable_funcs.push(name.to_string());
                            flagged_findings.push(format!(
                                "Function '{name}' performs a token '{method}' to recipient '{recipient}' \
without validating the recipient is not address(0), address(this), or a blacklisted \
dead address. This can cause locked or burned user tokens."
                            ));
                            break;
                        }
                    }
                }
            }
        }

        // Advance: the overall match was zero-width at body_end (lookahead), so
        // the next search begins there. Guard against no forward progress.
        if body_end > pos {
            pos = body_end;
        } else {
            pos += 1;
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 65.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_TRANSFER_RECIPIENT".to_string();
        } else {
            status = "WARN_TRANSFER_RECIPIENT".to_string();
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
    let out = audit_transfer_recipient(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_transfer_recipient(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn validated_transfer_passes() {
        std::env::remove_var("PI_TRANSFER_RECIPIENT_STRICT_MODE");
        let code = "function pay(address to, uint amt) public {\n\
            require(to != address(0), \"zero\");\n\
            token.transfer(to, amt);\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn unvalidated_transfer_flagged_strict() {
        std::env::set_var("PI_TRANSFER_RECIPIENT_STRICT_MODE", "true");
        let code = "function pay(address to, uint amt) public {\n\
            token.transfer(to, amt);\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TRANSFER_RECIPIENT");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_functions, vec!["pay"]);
        assert_eq!(o.flagged_findings.len(), 1);
        std::env::remove_var("PI_TRANSFER_RECIPIENT_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn unvalidated_transfer_warn_non_strict() {
        std::env::set_var("PI_TRANSFER_RECIPIENT_STRICT_MODE", "false");
        let code = "function pay(address to, uint amt) public {\n\
            token.transferFrom(from, to, amt);\n}";
        let o = run(code);
        // Non-strict: flagged but is_secure coerced back to true, WARN status.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_TRANSFER_RECIPIENT");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_functions, vec!["pay"]);
        std::env::remove_var("PI_TRANSFER_RECIPIENT_STRICT_MODE");
    }
}
