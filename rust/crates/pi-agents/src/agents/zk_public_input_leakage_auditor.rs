//! Port of `pi_micro_agents/pi_zk_public_input_leakage_auditor.py`.
//!
//! Audits Circom templates for leakage of private witnesses into public
//! signals/commitments. Behaviour is a line-for-line mirror of the Python
//! original.

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

// Python: re.findall(r'template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
//
// Notes on parity:
//  * `(.*?)` for params: Python without DOTALL means `.` does NOT match `\n`,
//    so params is restricted to a single line. We replicate with `(?-s)` not
//    needed since the default for the `regex` crate is `.` not matching `\n`.
//  * `[\s\S]*?` for body: matches across newlines (any char), non-greedy.
//  * `[^{]*` between `)` and `{`: any char except `{` (newlines allowed).
// The `regex` crate is leftmost-first like Python's `re`, and with non-greedy
// quantifiers the produced matches are equivalent for this pattern.
static TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Python: re.findall(
//   r'([a-zA-Z0-9_]*pub[a-zA-Z0-9_]*|[a-zA-Z0-9_]*out[a-zA-Z0-9_]*)'
//   r'\s*(?:<==|<--|=)\s*'
//   r'([a-zA-Z0-9_]*secret[a-zA-Z0-9_]*|[a-zA-Z0-9_]*priv[a-zA-Z0-9_]*)',
//   body, re.IGNORECASE)
//
// `(?:...)` non-capturing group is supported by the `regex` crate.
static ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)([a-zA-Z0-9_]*pub[a-zA-Z0-9_]*|[a-zA-Z0-9_]*out[a-zA-Z0-9_]*)\s*(?:<==|<--|=)\s*([a-zA-Z0-9_]*secret[a-zA-Z0-9_]*|[a-zA-Z0-9_]*priv[a-zA-Z0-9_]*)",
    )
    .unwrap()
});

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZK_PUBLIC_INPUT_LEAKAGE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_public_input_leakage(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_signals: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for caps in TEMPLATE_RE.captures_iter(code) {
        let tname = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let params = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Find public/private specifications in main component or standard markers
        if params.contains("public") || body.contains("public") {
            // Scans if private signals or secret parameters are exposed via direct
            // assignment to a public signal. Matches patterns where a signal
            // identified with 'secret' or 'priv' is assigned to an 'out'/'pub'
            // signal.
            for acaps in ASSIGN_RE.captures_iter(body) {
                let public_sig = acaps.get(1).map(|m| m.as_str()).unwrap_or("");
                let private_sig = acaps.get(2).map(|m| m.as_str()).unwrap_or("");
                vulnerable_signals.push(private_sig.to_string());
                flagged_findings.push(format!(
                    "Template '{tname}': Leakage detected where private witness '{private_sig}' is assigned to public signal '{public_sig}'. \
Exposing private inputs in public components completely undermines zero-knowledge privacy properties."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_signals.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZK_PUBLIC_INPUT_LEAKAGE".to_string();
        } else {
            status = "WARN_ZK_PUBLIC_INPUT_LEAKAGE".to_string();
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
    let out = audit_public_input_leakage(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_public_input_leakage(&Input {
            file_path: "circuit.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        // No template marked public, no leakage.
        let o = run("template Foo(n) { signal input a; signal output b; b <== a; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    fn private_leaked_to_public_flagged() {
        // public marker present in body; pubOut <== secretWitness leaks.
        let code =
            "template Leaky(n) { signal public pubOut; signal pubOut; pubOut <== secretWitness; }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZK_PUBLIC_INPUT_LEAKAGE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_signals, vec!["secretWitness"]);
    }

    #[test]
    fn public_in_params_with_priv_assignment() {
        // 'public' appears in the params list; outVal = privData leaks via '='.
        let code = "template T(public m) { outVal = privData; }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_signals, vec!["privData"]);
        assert_eq!(o.risk_score, 80.0);
    }

    #[test]
    fn empty_input_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }
}
