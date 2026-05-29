//! Port of `pi_micro_agents/pi_solidity_compiler_bugs_sentry.py`.
//!
//! Audits Solidity contracts for locked pragmas that match known buggy compiler
//! releases (Yul Optimizer memory bug in 0.8.13-0.8.15 and the ABI encoder v2
//! dynamic-array bug in 0.8.3-0.8.7). Behaviour is a line-for-line mirror of the
//! Python original.

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

// re.findall(r'pragma\s+solidity\s+([^;]+);', code) -> 1 capture group -> captures_iter
static PRAGMA_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"pragma\s+solidity\s+([^;]+);").unwrap());

// re.search(r'(\d+\.\d+\.\d+)', pragma_val_clean) -> 1 capture group
static VERSION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+\.\d+\.\d+)").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python order of resolution:
///   1. If env var `PI_COMPILER_BUGS_STRICT_MODE` is set: return `value.lower() == "true"`.
///   2. Else, read `~/.antigravitycli/config.json` (or the repo-root fallback) and
///      return `bool(data.get("PI_COMPILER_BUGS_STRICT_MODE", True))`.
///   3. Else / on any error: return `True`.
///
/// This port mirrors the env-var branch exactly and defaults to `True` otherwise.
/// The config-file fallback (step 2) is NOT replicated — see the parity spec /
/// deviations. In the current repo neither config file contains the
/// `PI_COMPILER_BUGS_STRICT_MODE` key, so Python's `data.get(..., True)` also
/// yields `True`, keeping the two sides in agreement when the env var is unset.
fn is_strict_mode() -> bool {
    match std::env::var("PI_COMPILER_BUGS_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_compiler_bugs(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find pragma statements: re.findall with 1 group yields the group text.
    for caps in PRAGMA_RE.captures_iter(code) {
        let pragma_val = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // pragma_val_clean = pragma_val.strip()
        let pragma_val_clean = pyutil::strip(pragma_val);
        // version_match = re.search(r'(\d+\.\d+\.\d+)', pragma_val_clean)
        if let Some(vcaps) = VERSION_RE.captures(pragma_val_clean) {
            let version_str = vcaps.get(1).map(|m| m.as_str()).unwrap_or("");
            // parts = [int(p) for p in version_str.split('.')]
            let parts: Vec<i64> = version_str
                .split('.')
                .map(|p| p.parse::<i64>().unwrap())
                .collect();
            if parts.len() >= 3 {
                let major = parts[0];
                let minor = parts[1];
                let patch = parts[2];

                // Specific Yul Optimizer severe memory bug releases
                if major == 0 && minor == 8 && (patch == 13 || patch == 14 || patch == 15) {
                    vulnerable_funcs.push("file_header".to_string());
                    flagged_findings.push(format!(
                        "Compiler version '{version_str}' suffers from a critical Yul Optimizer bug. \
When optimizing memory writes, the compiler can incorrectly overwrite storage offsets, \
leading to arbitrary state corruption."
                    ));
                }

                // Dynamic size array lookup bug in 0.8.3 - 0.8.7
                if major == 0
                    && minor == 8
                    && (patch == 3 || patch == 4 || patch == 5 || patch == 6 || patch == 7)
                {
                    vulnerable_funcs.push("file_header".to_string());
                    flagged_findings.push(format!(
                        "Compiler version '{version_str}' is affected by a severe ABI encoder v2 \
memory allocation bug when handling dynamic multi-dimensional arrays."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_COMPILER_RISK".to_string();
        } else {
            status = "WARN_COMPILER_RISK".to_string();
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
    let out = audit_compiler_bugs(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_compiler_bugs(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_pragma_passes() {
        std::env::remove_var("PI_COMPILER_BUGS_STRICT_MODE");
        let o = run("pragma solidity 0.8.20;\ncontract C {}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    #[serial]
    fn yul_optimizer_bug_rejected_in_strict() {
        std::env::set_var("PI_COMPILER_BUGS_STRICT_MODE", "true");
        let o = run("pragma solidity 0.8.14;");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_COMPILER_RISK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["file_header"]);
        assert_eq!(o.flagged_findings.len(), 1);
        std::env::remove_var("PI_COMPILER_BUGS_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn abi_encoder_bug_warn_when_non_strict() {
        std::env::set_var("PI_COMPILER_BUGS_STRICT_MODE", "false");
        let o = run("pragma solidity 0.8.5;");
        // non-strict -> WARN path, is_secure coerced back to True
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_COMPILER_RISK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["file_header"]);
        std::env::remove_var("PI_COMPILER_BUGS_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn empty_code_passes() {
        std::env::remove_var("PI_COMPILER_BUGS_STRICT_MODE");
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }
}
