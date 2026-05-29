//! Port of `pi_micro_agents/pi_solidity_block_timestamp_interval_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for safe
//! `block.timestamp` interval boundaries in staking/vesting/distribution
//! functions. Behaviour is a line-for-line mirror of the Python original.

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
// (BODY_END_RE) or end-of-string -- exactly what the lazy `([\s\S]*?)` with the
// lookahead produces. This mirrors the fuzz-verified approach already used by
// `solidity_array_length_sentry.rs`.
//
// NOTE: there is no DOTALL flag, so `.` (in `(.*?)`) does not match newline,
// matching Rust's default. `[\s\S]` explicitly matches any char incl. newline.
static FUNC_PREFIX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

// Python: lookahead `\n\s*function` -- used here as the body terminator.
static BODY_END_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n\s*function").unwrap());

// Python (line 65):
//   re.search(r'(block\.timestamp\s*(>=|>)\s*[a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+)', body)
static INTERVAL_RE_1: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(block\.timestamp\s*(>=|>)\s*[a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+)").unwrap()
});

// Python (line 67):
//   re.search(r'([a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+\s*(<=|<)\s*block\.timestamp)', body)
static INTERVAL_RE_2: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+\s*(<=|<)\s*block\.timestamp)").unwrap()
});

// Python (line 69):
//   re.search(r'(block\.timestamp\s*-\s*[a-zA-Z0-9_]+\s*(>=|>)\s*[a-zA-Z0-9_]+)', body)
static INTERVAL_RE_3: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(block\.timestamp\s*-\s*[a-zA-Z0-9_]+\s*(>=|>)\s*[a-zA-Z0-9_]+)").unwrap()
});

// Python (line 73): keywords flagged when present (lowercased) in the function name.
const KEYWORDS: [&str; 6] = ["stake", "vest", "distribute", "claim", "reward", "withdraw"];

/// Mirrors `is_strict_mode()`: strict unless the env var
/// `PI_TIMESTAMP_INTERVAL_STRICT_MODE` is set to a value that is not
/// (case-insensitively) "true".
///
/// DEVIATION: the Python original additionally falls back to reading
/// `~/.antigravitycli/config.json` (then a module-relative
/// `.antigravitycli/config.json`) when the env var is unset. That fallback
/// defaults to `True` (strict) when the file is missing or unparseable, so the
/// env-var-only behaviour here matches the Python default. We do NOT read the
/// config file; callers should set the env var explicitly to exercise the
/// non-strict branch. This matches the convention used by the other ported
/// Solidity sentries (e.g. `solidity_array_length_sentry.rs`).
fn is_strict_mode() -> bool {
    match std::env::var("PI_TIMESTAMP_INTERVAL_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_timestamp_interval(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Target functions commonly doing timestamp-based distribution, staking, or
    // vesting. `re.findall` with 3 groups -> iterate (name, args, body),
    // emulating the trailing lookahead manually. `finditer` continues from the
    // end of the (zero-width-lookahead) match, i.e. from the computed body end.
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

        // Check if block.timestamp is referenced.
        if body.contains("block.timestamp") {
            // Search for an interval-checking pattern.
            let mut has_interval_validation = false;
            if INTERVAL_RE_1.is_match(body) {
                has_interval_validation = true;
            }
            if INTERVAL_RE_2.is_match(body) {
                has_interval_validation = true;
            }
            if INTERVAL_RE_3.is_match(body) {
                has_interval_validation = true;
            }

            // Staking, vesting, or distribution functions must validate interval
            // spacing. Python: any(x in name.lower() for x in KEYWORDS).
            let name_lower = name.to_lowercase();
            if KEYWORDS.iter().any(|x| name_lower.contains(x)) {
                if !has_interval_validation {
                    vulnerable_funcs.push(name.to_string());
                    flagged_findings.push(format!(
                        "Function '{name}' references 'block.timestamp' in a staking, reward, or vesting context \
but lacks structural time-interval threshold checks (e.g. require(block.timestamp >= lastClaim + INTERVAL)). \
This can allow premature claims or trigger mathematical distribution inconsistencies."
                    ));
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
            status = "REJECTED_TIMESTAMP_INTERVAL".to_string();
        } else {
            status = "WARN_TIMESTAMP_INTERVAL".to_string();
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
    let out = audit_timestamp_interval(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_timestamp_interval(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_with_interval_check_passes() {
        std::env::remove_var("PI_TIMESTAMP_INTERVAL_STRICT_MODE");
        let code = "function claim() external {\n\
            require(block.timestamp >= lastClaim + INTERVAL);\n\
            payout();\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn missing_interval_check_flagged_strict() {
        std::env::set_var("PI_TIMESTAMP_INTERVAL_STRICT_MODE", "true");
        let code = "function claimReward() external {\n\
            uint256 t = block.timestamp;\n\
            payout(t);\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TIMESTAMP_INTERVAL");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_functions, vec!["claimReward"]);
        assert_eq!(o.flagged_findings.len(), 1);
        std::env::remove_var("PI_TIMESTAMP_INTERVAL_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn missing_interval_check_warn_non_strict() {
        std::env::set_var("PI_TIMESTAMP_INTERVAL_STRICT_MODE", "false");
        let code = "function withdraw() public {\n\
            if (block.timestamp > 0) { send(); }\n}";
        let o = run(code);
        // Non-strict: flagged but is_secure coerced back to true, WARN status.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_TIMESTAMP_INTERVAL");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_functions, vec!["withdraw"]);
        std::env::remove_var("PI_TIMESTAMP_INTERVAL_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn non_keyword_function_ignored() {
        std::env::remove_var("PI_TIMESTAMP_INTERVAL_STRICT_MODE");
        // Uses block.timestamp but name has no staking/vesting keyword.
        let code = "function getNow() public {\n\
            uint256 t = block.timestamp;\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }
}
