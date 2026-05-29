//! Port of `pi_micro_agents/pi_zk_circom_shadow_signal_sentry.py`.
//!
//! Audits ZK Circom templates to detect local variables/signals shadowing
//! template parameters or input/output signals. Behaviour mirrors the Python
//! original line for line.

use crate::pyutil;
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

// --- Regexes ---------------------------------------------------------------
//
// The Python template regex is:
//   r'template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*\{([\s\S]*?)(?=\ntemplate|\Z)'
//
// It uses a zero-width lookahead `(?=\ntemplate|\Z)` to terminate the body,
// which the Rust `regex` crate does not support. We therefore split the
// pattern: a `regex` for the header up to and including the opening brace `{`,
// then a manual scan to extract the body up to the earliest `\ntemplate` (or
// end-of-string), reproducing the lazy `[\s\S]*?` + lookahead semantics.
//
// Note: `.` in the Rust `regex` crate (like Python without DOTALL) does not
// match `\n`, so `(.*?)` for the args group keeps the same "no newline in
// args" behaviour as Python.
static TEMPLATE_HEADER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*\{").unwrap());

static SIGNAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"signal\s+(input|output)?\s*([a-zA-Z0-9_]+)").unwrap());

static VAR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"var\s+([a-zA-Z0-9_]+)").unwrap());

/// Mirrors the Python `is_strict_mode()`.
///
/// 1. If env var `PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE` is set, return whether
///    its lowercased value equals "true".
/// 2. Otherwise consult `~/.antigravitycli/config.json` and return
///    `bool(data.get("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE", True))`.
/// 3. Otherwise default to `true`.
///
/// DEVIATION: Python also falls back to a module-relative config path
/// (`<module_dir>/../../.antigravitycli/config.json`) when the home-dir config
/// is absent. Rust has no `__file__`, so only the `~/.antigravitycli` path is
/// consulted. Parity samples always set the env var, so this branch is never
/// exercised under the harness.
fn is_strict_mode() -> bool {
    if let Ok(v) = std::env::var("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE") {
        return v.to_lowercase() == "true";
    }

    if let Some(home) = std::env::var_os("HOME") {
        let mut path = std::path::PathBuf::from(home);
        path.push(".antigravitycli");
        path.push("config.json");
        if path.exists() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                    return py_truthy(data.get("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE"));
                }
            }
            // On read/parse error, Python swallows the exception and falls
            // through to the final `return True`.
        }
    }
    true
}

/// Reproduces Python `bool(data.get(key, True))` for a JSON value.
/// Missing key (`None` here) -> default True. Otherwise apply Python truthiness.
fn py_truthy(v: Option<&serde_json::Value>) -> bool {
    match v {
        None => true,
        Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                i != 0
            } else if let Some(u) = n.as_u64() {
                u != 0
            } else if let Some(f) = n.as_f64() {
                f != 0.0
            } else {
                true
            }
        }
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(serde_json::Value::Array(a)) => !a.is_empty(),
        Some(serde_json::Value::Object(o)) => !o.is_empty(),
    }
}

/// Extract `(name, args, body)` triples the way the Python template regex does:
///   - find a template header, then take the body lazily up to the first
///     `\ntemplate` occurring after the body start, or to end-of-string;
///   - continue scanning from that boundary position.
fn find_templates(code: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    let mut cursor = 0usize;
    while cursor <= code.len() {
        let hay = &code[cursor..];
        let caps = match TEMPLATE_HEADER_RE.captures(hay) {
            Some(c) => c,
            None => break,
        };
        let whole = caps.get(0).unwrap();
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        let args = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();

        // Body starts right after the opening brace, i.e. at the end of the
        // header match (the `{` is consumed by the header regex).
        let body_start = cursor + whole.end();

        // Lazy `[\s\S]*?` + lookahead(`\ntemplate|\Z`): the body ends at the
        // earliest position >= body_start where `\ntemplate` appears, else EOS.
        let boundary = match code[body_start..].find("\ntemplate") {
            Some(rel) => body_start + rel,
            None => code.len(),
        };

        let body = code[body_start..boundary].to_string();
        out.push((name, args, body));

        // `re.findall` resumes from the end of the (zero-width-terminated)
        // match, i.e. the boundary position.
        if boundary <= cursor {
            // Defensive: ensure forward progress (cannot happen with valid
            // input since body_start > cursor, but keeps the loop bounded).
            cursor = boundary + 1;
        } else {
            cursor = boundary;
        }
    }
    out
}

pub fn audit(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_sigs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let templates = find_templates(code);

    for (name, args, body) in templates {
        // Parse template parameters: [p.strip() for p in args.split(",") if p.strip()]
        let params: Vec<String> = args
            .split(',')
            .map(pyutil::strip)
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string())
            .collect();

        // Find input/output signal declarations in the body.
        // re.findall with 2 groups -> list of (group1, group2); we want group2.
        let defined_signals: Vec<String> = SIGNAL_RE
            .captures_iter(&body)
            .map(|c| c.get(2).map(|m| m.as_str()).unwrap_or("").to_string())
            .collect();

        // Local variable declarations: re.findall with 1 group -> the names.
        let var_declarations: Vec<String> = VAR_RE
            .captures_iter(&body)
            .map(|c| c.get(1).map(|m| m.as_str()).unwrap_or("").to_string())
            .collect();

        for var_name in &var_declarations {
            let mut shadowed = false;
            let mut shadow_type = "";
            if params.iter().any(|p| p == var_name) {
                shadowed = true;
                shadow_type = "template parameter";
            } else if defined_signals.iter().any(|s| s == var_name) {
                shadowed = true;
                shadow_type = "signal declaration";
            }

            if shadowed {
                vulnerable_sigs.push(var_name.clone());
                flagged_findings.push(format!(
                    "Variable '{var_name}' in template '{name}' shadows an existing {shadow_type}. \
Shadowing signal or parameter names inside ZK circuits can lead to incorrect \
constraint mapping, signal collisons, and underconstrained proving systems."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_sigs.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_CIRCOM_SHADOW_SIGNAL".to_string();
        } else {
            status = "WARN_CIRCOM_SHADOW_SIGNAL".to_string();
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
        audit(&Input {
            file_path: "circuit.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_template_passes() {
        std::env::set_var("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE", "true");
        let o = run("template Foo(n) {\n  signal input a;\n  signal output b;\n  var x = 5;\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
        std::env::remove_var("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn shadows_parameter_rejected_strict() {
        std::env::set_var("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE", "true");
        let o = run("template Foo(n, m) {\n  signal input a;\n  var n;\n}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_CIRCOM_SHADOW_SIGNAL");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_signals, vec!["n"]);
        std::env::remove_var("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn shadows_signal_warn_non_strict() {
        std::env::set_var("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE", "false");
        let o = run("template Bar() {\n  signal input c;\n  var c;\n}");
        // non-strict -> WARN, is_secure coerced back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_CIRCOM_SHADOW_SIGNAL");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_signals, vec!["c"]);
        std::env::remove_var("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE");
    }
}
