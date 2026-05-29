//! Port of `pi_micro_agents/pi_zero_trust_execution_domain.py`.
//!
//! Specialized environment micro-agent that audits execution shell profiles or
//! tmux configs for permission escalations or lack of sandbox boundary
//! restrictions. Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub domain_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_elements: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Mirrors the single Python regex. Outer parens form group(1); the alternation
// lives inside that group. No lookahead/lookbehind/backreferences are used, so
// this translates directly to the Rust `regex` crate.
//
// Python: r'(tmux\s+-S\s+/[a-zA-Z0-9_/]+|tmux\s+run-shell\s+-[b]*\s*"*[a-zA-Z0-9_\-\s]+"*|chmod\s+777|permit-root)'
static UNCONSTRAINED_TMUX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(tmux\s+-S\s+/[a-zA-Z0-9_/]+|tmux\s+run-shell\s+-[b]*\s*"*[a-zA-Z0-9_\-\s]+"*|chmod\s+777|permit-root)"#,
    )
    .unwrap()
});

/// Mirrors `is_strict_mode()`:
/// 1. If the env var is set, return `env_val.lower() == "true"`.
/// 2. Else look for `~/.antigravitycli/config.json`; if missing, fall back to
///    the config relative to the Python module (`<module>/../../.antigravitycli/config.json`).
/// 3. If a config exists, return `bool(data.get(KEY, True))`.
/// 4. Otherwise default to `True`.
fn is_strict_mode() -> bool {
    if let Ok(env_val) = std::env::var("PI_ZERO_TRUST_EXEC_DOMAIN_STRICT_MODE") {
        return env_val.to_lowercase() == "true";
    }

    // Replicate os.path.expanduser("~/.antigravitycli/config.json").
    let mut config_path: Option<std::path::PathBuf> = None;
    if let Some(home) = home_dir() {
        let p = home.join(".antigravitycli").join("config.json");
        if p.exists() {
            config_path = Some(p);
        }
    }

    // Python falls back to a path relative to the *module file*:
    //   os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")
    // __file__ is src/pi_micro_agents/pi_zero_trust_execution_domain.py, so
    // dirname is src/pi_micro_agents and the join resolves to the repo-root
    // .antigravitycli/config.json. We cannot read Python's __file__ at runtime
    // here; mirror the resolved location relative to the workspace root.
    if config_path.is_none() {
        let fallback = std::path::PathBuf::from(".antigravitycli/config.json");
        if fallback.exists() {
            config_path = Some(fallback);
        }
    }

    if let Some(path) = config_path {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&contents) {
                // bool(data.get("PI_ZERO_TRUST_EXEC_DOMAIN_STRICT_MODE", True))
                return match data.get("PI_ZERO_TRUST_EXEC_DOMAIN_STRICT_MODE") {
                    Some(v) => json_truthy(v),
                    None => true,
                };
            }
            // json.load raising -> Python `except: pass` -> falls through to True.
        }
    }
    true
}

/// Mirror of Python `bool(x)` for a JSON value (Python truthiness).
fn json_truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => {
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
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

/// Best-effort equivalent of `os.path.expanduser("~")` on Unix.
fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

pub fn audit_exec_domain(input: &Input) -> Output {
    let code = &input.domain_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Scans for tmux socket leaks or unconstrained execution environment exports.
    // re.search -> first match anywhere in the string.
    if let Some(caps) = UNCONSTRAINED_TMUX.captures(code) {
        // group(1) -- the single capturing group (the whole alternation).
        let g1 = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        vulnerable_elements.push(g1.to_string());
        flagged_findings.push(format!(
            "Execution domain configuration exposes unsafe shell/socket mappings: '{g1}'. \
This bypasses normal role-based namespace bounds and opens vectors for host privilege escalation."
        ));
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZERO_TRUST_DOMAIN".to_string();
        } else {
            status = "WARN_ZERO_TRUST_DOMAIN".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_elements,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_exec_domain(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_exec_domain(&Input {
            file_path: "f.conf".into(),
            domain_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        let o = run("set -g default-shell /bin/bash\nrun-shell 'echo hi'");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn tmux_socket_leak_flagged() {
        let o = run("tmux -S /var/run/tmux.sock new-session");
        assert!(!o.is_secure || o.status == "WARN_ZERO_TRUST_DOMAIN");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_elements, vec!["tmux -S /var/run/tmux"]);
    }

    #[test]
    fn chmod_777_flagged() {
        let o = run("chmod 777 /etc/passwd");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_elements, vec!["chmod 777"]);
    }

    #[test]
    fn permit_root_flagged() {
        let o = run("PermitRootLogin yes\npermit-root");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_elements, vec!["permit-root"]);
    }
}
