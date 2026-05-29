//! Port of `pi_micro_agents/pi_zk_circom_underconstrained_sentry.py`.
//!
//! Audits ZK Circom circuits for underconstrained signal assignments: signals
//! assigned with the non-constraining operators `<--` / `-->` that lack a
//! corresponding `===` constraint, which can leave the circuit forgeable.
//! Behaviour mirrors the Python original line-for-line.
//!
//! PARITY NOTE: the Python agent derives the audited signal set via
//! `set(left_assigns + right_assigns)`, whose iteration order is governed by
//! CPython per-process hash randomization (`PYTHONHASHSEED`). The Python
//! ordering of `vulnerable_signals` / `flagged_findings` is therefore
//! NON-DETERMINISTIC across processes whenever a template has >1 vulnerable
//! signal. This port deduplicates preserving first-seen insertion order; the
//! parity spec declares `NORMALIZE = ["vulnerable_signals", "flagged_findings"]`
//! so those fields are compared order-insensitively.

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

// Header of a Circom template: `template NAME(args) {`. The Python source uses
// the single regex
//   template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*\{([\s\S]*?)(?=\ntemplate|\Z)
// The trailing `(?=\ntemplate|\Z)` lookahead is unsupported by the `regex`
// crate, so we split it: this matches the header (`.` excludes `\n`, matching
// Python without re.DOTALL — args may not span lines) and the body is then
// scanned manually up to the next `\ntemplate` or end of string.
static TEMPLATE_HEADER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*\{").unwrap());

// `NAME <--`  (1 capture group)
static LEFT_ASSIGN: Lazy<Regex> = Lazy::new(|| Regex::new(r"([a-zA-Z0-9_]+)\s*<--").unwrap());

// `--> NAME`  (1 capture group)
static RIGHT_ASSIGN: Lazy<Regex> = Lazy::new(|| Regex::new(r"-->\s*([a-zA-Z0-9_]+)").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// PARITY NOTE: the Python original, when the env var is *unset*, falls back to
/// `~/.antigravitycli/config.json` then `<repo>/.antigravitycli/config.json`,
/// returning `bool(data.get("PI_CIRCOM_UNDERCONSTRAINED_STRICT_MODE", True))`,
/// else `True`. Neither config file defines that key in this deployment, so the
/// fallback resolves to `True` — identical to the `Err(_) => true` arm below.
/// A future config.json that set the key to `false` would diverge; see the
/// agent's `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_CIRCOM_UNDERCONSTRAINED_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Replicate `re.findall(template ... (?=\ntemplate|\Z))`: yields
/// `(name, args, body)` tuples in document order. The body of each template
/// extends from just after `{` up to (but not including) the next occurrence of
/// `\ntemplate` at/after that point, or to end-of-string. After each match the
/// next search resumes at that body-end position (the zero-width lookahead),
/// exactly as CPython's `re.findall` does.
fn find_templates(code: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos <= code.len() {
        let hay = &code[pos..];
        let caps = match TEMPLATE_HEADER.captures(hay) {
            Some(c) => c,
            None => break,
        };
        let m = caps.get(0).unwrap();
        let name = caps.get(1).map(|g| g.as_str()).unwrap_or("").to_string();
        let args = caps.get(2).map(|g| g.as_str()).unwrap_or("").to_string();
        // Absolute byte offset of the char just after `{`.
        let body_start = pos + m.end();
        // Find the next "\ntemplate" at/after body_start; else end of string.
        let body_end = match code[body_start..].find("\ntemplate") {
            Some(rel) => body_start + rel,
            None => code.len(),
        };
        let body = code[body_start..body_end].to_string();
        out.push((name, args, body));
        // `pos` strictly increases: body_start = pos + m.end() and the literal
        // `template` guarantees m.end() >= 8, so body_end >= body_start > pos.
        // The next findall search resumes at body_end (the zero-width lookahead).
        pos = body_end;
    }
    out
}

pub fn audit(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_sigs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for (name, _args, body) in find_templates(code) {
        // left_assigns: NAME <--   (group 1)
        let left_assigns: Vec<String> = LEFT_ASSIGN
            .captures_iter(&body)
            .map(|c| c[1].to_string())
            .collect();
        // right_assigns: --> NAME  (group 1)
        let right_assigns: Vec<String> = RIGHT_ASSIGN
            .captures_iter(&body)
            .map(|c| c[1].to_string())
            .collect();

        // Python: assigned_signals = set(left_assigns + right_assigns).
        // Deduplicate preserving first-seen insertion order (deterministic).
        let mut assigned_signals: Vec<String> = Vec::new();
        for sig in left_assigns.iter().chain(right_assigns.iter()) {
            if !assigned_signals.contains(sig) {
                assigned_signals.push(sig.clone());
            }
        }

        for sig in &assigned_signals {
            // constrained if `{sig}\s*===` OR `===\s*{sig}` matches the body.
            // sig matches [a-zA-Z0-9_]+ so contains no regex-special chars; the
            // raw interpolation mirrors the Python f-string regex exactly.
            let before = Regex::new(&format!(r"{}\s*===", sig)).unwrap();
            let after = Regex::new(&format!(r"===\s*{}", sig)).unwrap();
            let constrained = before.is_match(&body) || after.is_match(&body);

            if !constrained {
                vulnerable_sigs.push(sig.clone());
                flagged_findings.push(format!(
                    "Signal '{sig}' in template '{name}' is assigned using a non-constraining operator \
('<--' or '-->') but lacks a corresponding '===' constraint. This makes the circuit \
underconstrained, allowing potential proof forgery."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_sigs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_CIRCOM_UNDERCONSTRAINED".to_string();
        } else {
            status = "WARN_CIRCOM_UNDERCONSTRAINED".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_signals: vulnerable_sigs,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        // ensure deterministic strict mode for assertions that depend on status
        std::env::remove_var("PI_CIRCOM_UNDERCONSTRAINED_STRICT_MODE");
        audit(&Input {
            file_path: "circuit.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn constrained_signal_passes() {
        let o = run("template A() {\n out <-- a;\n out === a;\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    #[serial]
    fn underconstrained_left_assign_flagged() {
        let o = run("template A() {\n out <-- a;\n}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_CIRCOM_UNDERCONSTRAINED");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_signals, vec!["out".to_string()]);
    }

    #[test]
    #[serial]
    fn underconstrained_right_assign_flagged() {
        let o = run("template A() {\n in --> b;\n}");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_signals, vec!["b".to_string()]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    #[serial]
    fn non_strict_env_warns() {
        std::env::set_var("PI_CIRCOM_UNDERCONSTRAINED_STRICT_MODE", "false");
        let o = audit(&Input {
            file_path: "c.circom".into(),
            circom_code: "template A() {\n out <-- a;\n}".into(),
            check_level: "STRICT".into(),
        });
        std::env::remove_var("PI_CIRCOM_UNDERCONSTRAINED_STRICT_MODE");
        assert!(o.is_secure); // coerced back to true on WARN path
        assert_eq!(o.status, "WARN_CIRCOM_UNDERCONSTRAINED");
        assert_eq!(o.risk_score, 90.0);
    }

    #[test]
    #[serial]
    fn two_templates_one_swallows_inline_keyword() {
        // a `template` keyword mid-line (not after \n) is swallowed into the
        // previous body, so only one template (A) is detected here.
        let o = run("template A() {\n x <-- 1; template B() { z <-- 9; }\n}");
        // both x and z are underconstrained, both attributed to template A
        assert_eq!(o.vulnerable_signals.len(), 2);
        assert!(o.flagged_findings.iter().all(|f| f.contains("template 'A'")));
    }
}
