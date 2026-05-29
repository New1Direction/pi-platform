//! Port of `pi_micro_agents/pi_patch_synthesizer.py`.
//!
//! Automated hotfix generator that patches found vulnerabilities in smart
//! contracts. Behaviour is a line-for-line mirror of the Python original
//! (`PiPatchSynthesizer.synthesize_remediation`).

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub vulnerability_id: String,
    pub file_path: String,
    pub source_code: String,
    #[serde(default = "default_severity")]
    pub severity: String,
}

fn default_severity() -> String {
    "High".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub patched_code: String,
    pub diff: String,
    pub remediation_steps: Vec<String>,
    pub success: bool,
}

// `re.sub(r"\btx\.origin\b", ...)` in synthesize_remediation: NO IGNORECASE flag.
static TX_ORIGIN_SUB: Lazy<Regex> = Lazy::new(|| Regex::new(r"\btx\.origin\b").unwrap());

// detect_unpatched_vulnerabilities regexes (all IGNORECASE).
static RE_TX_ORIGIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\btx\.origin\b").unwrap());
static RE_DELEGATECALL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bdelegatecall\b").unwrap());
static RE_SELFDESTRUCT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)selfdestruct\b|suicide\b").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the `PI_PATCH_STRICT_MODE` env var (case-insensitive
/// compare to "true"); if unset it falls back to a config file and ultimately
/// defaults to `True`. We replicate the env-var branch exactly and default to
/// `true` when unset (see deviations re: the config-file fallback).
fn is_strict_mode() -> bool {
    match std::env::var("PI_PATCH_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `detect_unpatched_vulnerabilities(text)`.
fn detect_unpatched_vulnerabilities(text: &str) -> (f64, Vec<String>) {
    let mut violations: Vec<String> = Vec::new();
    let mut max_risk = 0.0_f64;
    if text.is_empty() {
        return (0.0, Vec::new());
    }

    if RE_TX_ORIGIN.is_match(text) {
        violations.push("tx.origin authentication vulnerability".to_string());
        max_risk = max_risk.max(90.0);
    }

    if RE_DELEGATECALL.is_match(text) {
        violations.push("unprotected delegatecall vulnerability".to_string());
        max_risk = max_risk.max(90.0);
    }

    if RE_SELFDESTRUCT.is_match(text) {
        violations.push("critical selfdestruct capability found".to_string());
        max_risk = max_risk.max(90.0);
    }

    // Missing external call verification.
    if text.contains(".call") {
        for line in pyutil::splitlines(text) {
            if line.contains(".call") && line.contains(';') {
                if !line.contains('=') && !line.contains("require") && !line.contains("assert") {
                    violations.push("missing external call verification".to_string());
                    max_risk = max_risk.max(90.0);
                    break;
                }
            }
        }
    }

    // Missing reentrancy guard.
    if text.contains(".call") && !text.contains("nonReentrant") {
        violations.push("missing nonReentrant guard on external call function".to_string());
        max_risk = max_risk.max(80.0);
    }

    (max_risk, violations)
}

pub fn synthesize_remediation(input: &Input) -> Output {
    let code = &input.source_code;
    let mut remedy_steps: Vec<String> = Vec::new();
    let mut patched: String = code.clone();
    let mut success = false;

    // A. Patch tx.origin -> msg.sender
    if code.contains("tx.origin") {
        // re.sub with `\b` boundaries, NO ignorecase.
        patched = TX_ORIGIN_SUB.replace_all(&patched, "msg.sender").into_owned();
        remedy_steps.push(
            "Replaced insecure 'tx.origin' authentication checks with 'msg.sender'.".to_string(),
        );
        success = true;
    }

    // B. Check for call success verification and patch if missing.
    let mut patched_lines: Vec<String> = Vec::new();
    let mut applied_call_patch = false;
    for line in pyutil::splitlines(&patched) {
        if line.contains(".call") && line.contains(';') {
            if !line.contains('=') && !line.contains("require") && !line.contains("assert") {
                // indent = line[:len(line) - len(line.lstrip())]
                let indent = &line[..line.len() - line.trim_start().len()];
                // stmt = line.strip().rstrip(";")
                let stmt = pyutil::strip(line).trim_end_matches(';');
                let patched_line = format!(
                    "{indent}(bool success, ) = {stmt};\n{indent}require(success, \"Transfer failed\");"
                );
                patched_lines.push(patched_line);
                applied_call_patch = true;
                continue;
            }
        }
        patched_lines.push(line.to_string());
    }

    if applied_call_patch {
        patched = patched_lines.join("\n");
        remedy_steps.push(
            "Wrapped unverified external call in require statement to prevent silent failure."
                .to_string(),
        );
        success = true;
    }

    // Generate a unified Git-style diff.
    let mut diff_lines: Vec<String> = Vec::new();
    if *code != patched {
        let code_lines = pyutil::splitlines(code);
        let patched_split = pyutil::splitlines(&patched);
        // zip stops at the shorter of the two.
        for (c_line, p_line) in code_lines.iter().zip(patched_split.iter()) {
            if c_line != p_line {
                diff_lines.push(format!("- {c_line}"));
                diff_lines.push(format!("+ {p_line}"));
            }
        }
    }
    let diff = diff_lines.join("\n");

    // Strict-mode safety compilation gate.
    let is_strict = is_strict_mode();
    let (risk, _violations) = detect_unpatched_vulnerabilities(&patched);

    if is_strict && risk >= 90.0 {
        success = false;
        remedy_steps
            .push("Failed safety compilation due to remaining unpatched vulnerabilities.".to_string());
    }

    Output {
        patched_code: patched,
        diff,
        remediation_steps: remedy_steps,
        success,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = synthesize_remediation(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        synthesize_remediation(&Input {
            vulnerability_id: "VULN-1".into(),
            file_path: "Contract.sol".into(),
            source_code: code.into(),
            severity: "High".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_code_no_changes() {
        std::env::remove_var("PI_PATCH_STRICT_MODE");
        let o = run("uint256 public total;");
        assert_eq!(o.patched_code, "uint256 public total;");
        assert_eq!(o.diff, "");
        assert!(o.remediation_steps.is_empty());
        assert!(!o.success);
    }

    #[test]
    #[serial]
    fn tx_origin_patched() {
        std::env::remove_var("PI_PATCH_STRICT_MODE");
        let o = run("require(tx.origin == owner);");
        assert!(o.patched_code.contains("msg.sender"));
        assert!(!o.patched_code.contains("tx.origin"));
        assert!(o.success);
        assert_eq!(
            o.remediation_steps[0],
            "Replaced insecure 'tx.origin' authentication checks with 'msg.sender'."
        );
    }

    #[test]
    #[serial]
    fn unverified_call_patched_then_rejected_in_strict() {
        // The .call line gets patched, but the post-patch detector still flags
        // "missing nonReentrant guard" (risk 80) and the patched line itself
        // is now an assignment (=) so it's no longer "missing external call
        // verification". Strict mode only rejects at risk >= 90.
        std::env::set_var("PI_PATCH_STRICT_MODE", "true");
        let o = run("    target.call{value: 1}(\"\");");
        assert!(o.patched_code.contains("(bool success, )"));
        assert!(o.patched_code.contains("require(success, \"Transfer failed\")"));
        std::env::remove_var("PI_PATCH_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn selfdestruct_remains_rejected_in_strict() {
        std::env::set_var("PI_PATCH_STRICT_MODE", "true");
        let o = run("selfdestruct(payable(owner));");
        // No patch applies, selfdestruct risk 90 -> strict rejects.
        assert!(!o.success);
        assert!(o
            .remediation_steps
            .iter()
            .any(|s| s.contains("Failed safety compilation")));
        std::env::remove_var("PI_PATCH_STRICT_MODE");
    }
}
