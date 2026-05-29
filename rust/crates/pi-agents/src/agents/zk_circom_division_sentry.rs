//! Port of `pi_micro_agents/pi_zk_circom_division_sentry.py`.
//!
//! Specialized ZK micro-agent that audits Circom circuits for under-constrained
//! division and division-by-zero vulnerabilities. Behaviour is a line-for-line
//! mirror of the Python original.

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

// Find templates:
//   template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}
// (.) does not match newline by default in both Python `re` and the `regex`
// crate, matching Python's default (no DOTALL flag used here).
static TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Find any division statement, e.g. `a <-- b / c` or similar.
//   ([a-zA-Z0-9_]+)\s*(?:<--|-->|=)\s*([a-zA-Z0-9_]+)\s*(?:/|\\)\s*([a-zA-Z0-9_]+)
static DIV_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9_]+)\s*(?:<--|-->|=)\s*([a-zA-Z0-9_]+)\s*(?:/|\\)\s*([a-zA-Z0-9_]+)")
        .unwrap()
});

/// Mirrors `is_strict_mode()`.
///
/// In Python, when the env var is unset the agent falls back to reading a
/// `~/.antigravitycli/config.json` (or a repo-relative copy) and ultimately
/// defaults to `True`. The Rust port mirrors the env-var branch faithfully;
/// see `deviations` re: the config-file fallback (env var precedence is
/// preserved, which is what the parity samples exercise).
fn is_strict_mode() -> bool {
    match std::env::var("PI_CIRCOM_DIVISION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        // Python would consult the config file here; absent the file it
        // ultimately defaults to True, which is the value we return.
        Err(_) => true,
    }
}

pub fn audit_circom_division(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_signals: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find templates
    for caps in TEMPLATE_RE.captures_iter(code) {
        let tname = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let _params = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Find any division statement, e.g. a <-- b / c or similar
        for m in DIV_RE.captures_iter(body) {
            let dest = m.get(1).map(|x| x.as_str()).unwrap_or("");
            let _num = m.get(2).map(|x| x.as_str()).unwrap_or("");
            let divisor = m.get(3).map(|x| x.as_str()).unwrap_or("");

            // Check if divisor is constrained to be non-zero
            // (e.g. divisor === 0 or divisor !== 0 or assert(divisor != 0)).
            // The divisor only ever contains [a-zA-Z0-9_], so it carries no
            // regex metacharacters and is safe to interpolate raw, exactly as
            // the Python f-string patterns do.
            let p1 = Regex::new(&format!(r"\b{}\s*!==?\s*0", divisor)).unwrap();
            let p2 = Regex::new(&format!(r"assert\s*\(\s*{}\s*!=?\s*0\s*\)", divisor)).unwrap();
            let p3 = Regex::new(&format!(r"{}\s*===\s*0", divisor)).unwrap();

            let is_constrained =
                p1.is_match(body) || p2.is_match(body) || p3.is_match(body);

            if !is_constrained {
                vulnerable_signals.push(divisor.to_string());
                flagged_findings.push(format!(
                    "Template '{tname}' performs division using divisor '{divisor}' \
to assign signal '{dest}', but does not explicitly constrain '{divisor}' to be non-zero. \
This may lead to division-by-zero execution panic or under-constrained malicious inputs during proof generation."
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
            status = "REJECTED_CIRCOM_DIVISION".to_string();
        } else {
            status = "WARN_CIRCOM_DIVISION".to_string();
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
    let out = audit_circom_division(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        // Ensure strict mode for deterministic assertions unless a test
        // overrides it.
        std::env::set_var("PI_CIRCOM_DIVISION_STRICT_MODE", "true");
        audit_circom_division(&Input {
            file_path: "circuit.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn unconstrained_division_flagged() {
        let o = run("template Foo(n) {\n  b <-- a / c;\n}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_CIRCOM_DIVISION");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_signals, vec!["c"]);
    }

    #[test]
    #[serial]
    fn constrained_division_passes() {
        let o = run("template Bar() {\n  d <-- e / f;\n  assert(f != 0);\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    #[serial]
    fn warn_mode_coerces_secure() {
        std::env::set_var("PI_CIRCOM_DIVISION_STRICT_MODE", "false");
        let o = audit_circom_division(&Input {
            file_path: "circuit.circom".into(),
            circom_code: "template Foo() {\n  b <-- a / c;\n}".into(),
            check_level: "STRICT".into(),
        });
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_CIRCOM_DIVISION");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_signals, vec!["c"]);
        std::env::set_var("PI_CIRCOM_DIVISION_STRICT_MODE", "true");
    }
}
