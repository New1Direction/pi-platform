//! Port of `pi_micro_agents/pi_solidity_array_length_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity dynamic array parameters
//! to prevent block gas limit DoS via unbounded iteration loops. Behaviour is a
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

// Python (line 56):
//   re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*(external|public)[\s\S]*?\{([\s\S]*?)(?=\n\s*function|\Z)', code)
//
// The Rust `regex` crate does NOT support the trailing lookahead `(?=...)`. The
// lookahead is emulated manually: we match the prefix (everything up to and
// including the opening `{`) with `FUNC_PREFIX_RE`, then take the body as the
// shortest span from the end of that match until either `\n\s*function`
// (BODY_END_RE) or end-of-string -- exactly what the lazy `([\s\S]*?)` with the
// lookahead produces. This was fuzz-verified against the Python regex
// (20000+ random/token-based inputs, zero mismatches).
//
// NOTE: there is no DOTALL flag, so `.` (in `(.*?)`) does not match newline,
// matching Rust's default. `[\s\S]` explicitly matches any char incl. newline.
static FUNC_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*(external|public)[\s\S]*?\{").unwrap()
});

// Python: lookahead `\n\s*function` — used here as the body terminator.
static BODY_END_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n\s*function").unwrap());

// Python (line 60):
//   re.findall(r'([a-zA-Z0-9_]+)\[\]\s*(?:calldata|memory)?\s*([a-zA-Z0-9_]+)', args)
// Two capture groups -> captures_iter. The `(?:...)` non-capturing group is
// supported by the Rust regex crate.
static ARRAY_PARAM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9_]+)\[\]\s*(?:calldata|memory)?\s*([a-zA-Z0-9_]+)").unwrap()
});

/// Mirrors `is_strict_mode()`: strict unless the env var
/// `PI_ARRAY_LENGTH_STRICT_MODE` is set to a value that is not
/// (case-insensitively) "true".
///
/// DEVIATION: the Python original additionally falls back to reading
/// `~/.antigravitycli/config.json` (then a module-relative
/// `.antigravitycli/config.json`) when the env var is unset. That fallback
/// defaults to `True` (strict) when the file is missing or unparseable, and the
/// repo's config currently also yields strict, so the env-var-only behaviour
/// here matches the Python default. We do NOT read the config file; callers
/// should set the env var explicitly to exercise the non-strict branch.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ARRAY_LENGTH_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_array_length(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all public/external functions (re.findall with 4 groups), emulating
    // the trailing lookahead manually. `finditer` continues from the end of the
    // (zero-width-lookahead) match, i.e. from the computed body end.
    let mut pos = 0usize;
    while pos <= code.len() {
        let caps = match FUNC_PREFIX_RE.captures_at(code, pos) {
            Some(c) => c,
            None => break,
        };
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        // Group 3 (visibility) is captured by Python but unused in the loop body.
        let _visibility = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        let body_start = caps.get(0).unwrap().end();
        // Lazy `([\s\S]*?)(?=\n\s*function|\Z)` => shortest body until the next
        // `\n\s*function` or end of string.
        let body_end = match BODY_END_RE.find_at(code, body_start) {
            Some(m) => m.start(),
            None => code.len(),
        };
        let body = &code[body_start..body_end];

        // Check if there is an array parameter in signature.
        let array_matches: Vec<(&str, &str)> = ARRAY_PARAM_RE
            .captures_iter(args)
            .map(|c| {
                (
                    c.get(1).map(|m| m.as_str()).unwrap_or(""),
                    c.get(2).map(|m| m.as_str()).unwrap_or(""),
                )
            })
            .collect();

        if !array_matches.is_empty() {
            for (_arr_type, arr_name) in &array_matches {
                // Check if there is a loop iterating up to this array's length.
                // Python: rf'{arr_name}.length' in body  (plain substring; the
                // `.` is literal here because `in` is not a regex op).
                if body.contains(&format!("{arr_name}.length")) {
                    // Look for limit checks on the array's length.
                    // Python: re.search(rf'require\s*\(\s*{arr_name}\.length\s*(<=|<)', body)
                    let mut has_limit_check = false;
                    let limit_pattern = format!(
                        r"require\s*\(\s*{}\.length\s*(<=|<)",
                        regex::escape(arr_name)
                    );
                    let limit_re = Regex::new(&limit_pattern).unwrap();
                    if limit_re.is_match(body) {
                        has_limit_check = true;
                    }

                    if !has_limit_check {
                        vulnerable_funcs.push(name.to_string());
                        flagged_findings.push(format!(
                            "Function '{name}' processes dynamic array parameter '{arr_name}' \
and iterates over its length without enforcing a maximum limit check. \
An attacker or user could pass a massive array causing block gas limit exhaustion DoS."
                        ));
                        break;
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
    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ARRAY_LENGTH".to_string();
        } else {
            status = "WARN_ARRAY_LENGTH".to_string();
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
    let out = audit_array_length(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_array_length(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_with_limit_check_passes() {
        std::env::remove_var("PI_ARRAY_LENGTH_STRICT_MODE");
        let code = "function safe(uint256[] calldata data) external {\n\
            require(data.length <= MAX, \"too big\");\n\
            for (uint i=0; i<data.length; i++) { sum += data[i]; }\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn unbounded_array_loop_flagged_strict() {
        std::env::set_var("PI_ARRAY_LENGTH_STRICT_MODE", "true");
        let code = "function bad(address[] memory users) public {\n\
            for (uint i=0; i<users.length; i++) { pay(users[i]); }\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ARRAY_LENGTH");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
        assert_eq!(o.flagged_findings.len(), 1);
        std::env::remove_var("PI_ARRAY_LENGTH_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn unbounded_array_loop_warn_non_strict() {
        std::env::set_var("PI_ARRAY_LENGTH_STRICT_MODE", "false");
        let code = "function bad(address[] memory users) public {\n\
            for (uint i=0; i<users.length; i++) { pay(users[i]); }\n}";
        let o = run(code);
        // Non-strict: flagged but is_secure coerced back to true, WARN status.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ARRAY_LENGTH");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
        std::env::remove_var("PI_ARRAY_LENGTH_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn private_function_ignored() {
        std::env::remove_var("PI_ARRAY_LENGTH_STRICT_MODE");
        // No external/public visibility -> not matched at all.
        let code = "function priv(uint[] memory a) private { for(uint i;i<a.length;i++){} }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }
}
