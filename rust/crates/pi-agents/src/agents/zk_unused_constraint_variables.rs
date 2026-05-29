//! Port of `pi_micro_agents/pi_zk_unused_constraint_variables.py`.
//!
//! Specialized ZK micro-agent that audits Circom circuits for defined
//! signals/variables completely omitted from constraints. Behaviour is a
//! line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub circom_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_signals: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZK_UNUSED_CONSTRAINT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// re.findall(r'template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// 3 groups -> captures_iter. `.*?` (group 2) does not match newlines (no DOTALL
// in Python); `[\s\S]*?` (group 3) matches everything including newlines.
static TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// re.findall(r'signal\s+(?:input|output)?\s*([a-zA-Z0-9_]+)', body)
// 1 group -> captures_iter.
static SIGNAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"signal\s+(?:input|output)?\s*([a-zA-Z0-9_]+)").unwrap()
});

pub fn audit_unused_variables(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_signals: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // templates = re.findall(...) -> list of (tname, params, body)
    for caps in TEMPLATE_RE.captures_iter(code) {
        let tname = caps.get(1).map_or("", |m| m.as_str());
        // params (group 2) is unused beyond destructuring in Python.
        let body = caps.get(3).map_or("", |m| m.as_str());

        // declarations = re.findall(r'signal\s+(?:input|output)?\s*([a-zA-Z0-9_]+)', body)
        let declarations: Vec<&str> = SIGNAL_RE
            .captures_iter(body)
            .map(|c| c.get(1).map_or("", |m| m.as_str()))
            .collect();

        // constraint_statements = [stmt for stmt in body.split(';')
        //     if any(op in stmt for op in ['<==', '==>', '==='])]
        let constraint_statements: Vec<&str> = body
            .split(';')
            .filter(|stmt| {
                stmt.contains("<==") || stmt.contains("==>") || stmt.contains("===")
            })
            .collect();

        for sig in &declarations {
            // is_used = any(re.search(rf'\b{sig}\b', stmt) for stmt in constraint_statements)
            // `sig` is drawn from [a-zA-Z0-9_]+, so it contains no regex
            // metacharacters; build the pattern the same way Python does.
            let pattern = format!(r"\b{sig}\b");
            let word_re = Regex::new(&pattern).unwrap();
            let mut is_used = false;
            for stmt in &constraint_statements {
                if word_re.is_match(stmt) {
                    is_used = true;
                    break;
                }
            }
            if !is_used {
                vulnerable_signals.push((*sig).to_string());
                flagged_findings.push(format!(
                    "Template '{tname}': Declared signal '{sig}' is never bound or used in any constraint equations (<==, ==>, ===). \
Unconstrained signals let attackers manipulate inputs without altering the proof validation flow."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_signals.is_empty();
    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZK_UNUSED_CONSTRAINT".to_string();
        } else {
            status = "WARN_ZK_UNUSED_CONSTRAINT".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_signals,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_unused_variables(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_unused_variables(&Input {
            file_path: "f.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn all_signals_constrained_passes() {
        let o = run("template Foo(n) { signal input a; signal output b; b <== a + 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    fn unused_signal_flagged() {
        let o = run("template Foo(n) { signal input a; signal output b; signal c; b <== a + 1; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZK_UNUSED_CONSTRAINT");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_signals, vec!["c"]);
    }

    #[test]
    fn no_templates_is_secure() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_signals.is_empty());
    }
}
