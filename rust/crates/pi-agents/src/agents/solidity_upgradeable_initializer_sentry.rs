//! Port of `pi_micro_agents/pi_solidity_upgradeable_initializer_sentry.py`.
//!
//! Audits Solidity upgradeable contracts for uninitialized or unguarded
//! implementation takeovers (missing `_disableInitializers()` in the
//! constructor and `initialize*` functions lacking the `initializer` /
//! `onlyInitializing` guards). Behaviour is a line-for-line mirror of the
//! Python original.

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

// Compiled regexes mirroring the Python patterns.
//
// `re.findall` with three groups -> `captures_iter`. Python's `.` does not match
// newlines by default (no `re.DOTALL`), so the bare `regex` crate `.` (also
// non-newline by default) matches exactly. `[\s\S]` matches any char including
// newlines in both engines.
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

static CONSTRUCTOR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"constructor\s*\((.*?)\)\s*\{([\s\S]*?)\}").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// 1. If `PI_UPGRADE_INIT_STRICT_MODE` is set, return whether it equals (case
///    insensitively) "true".
/// 2. Otherwise look for `~/.antigravitycli/config.json`, falling back to the
///    repo-relative `../../.antigravitycli/config.json` next to the module, and
///    if found return `bool(data.get("PI_UPGRADE_INIT_STRICT_MODE", True))`.
/// 3. Otherwise default to `true`.
fn is_strict_mode() -> bool {
    if let Ok(v) = std::env::var("PI_UPGRADE_INIT_STRICT_MODE") {
        return v.to_lowercase() == "true";
    }

    // Resolve the config path the same way the Python does.
    let home_path = std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".antigravitycli/config.json"));

    let config_path = match &home_path {
        Some(p) if p.exists() => Some(p.clone()),
        _ => {
            // ../../.antigravitycli/config.json relative to this module's dir.
            // The Python module lives in src/pi_micro_agents/, so `../../` is the
            // repo root. We cannot reconstruct __file__ at runtime, so fall back
            // to the current working directory's repo-root candidate.
            let candidate = std::path::PathBuf::from(".antigravitycli/config.json");
            if candidate.exists() {
                Some(candidate)
            } else {
                None
            }
        }
    };

    if let Some(path) = config_path {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&contents) {
                return match data.get("PI_UPGRADE_INIT_STRICT_MODE") {
                    Some(serde_json::Value::Bool(b)) => *b,
                    Some(serde_json::Value::Null) => false,
                    Some(serde_json::Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
                    Some(serde_json::Value::String(s)) => !s.is_empty(),
                    Some(serde_json::Value::Array(a)) => !a.is_empty(),
                    Some(serde_json::Value::Object(o)) => !o.is_empty(),
                    None => true,
                };
            }
        }
    }
    true
}

pub fn audit_upgradeable_initializer(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions: (name, args, body) tuples.
    let func_blocks: Vec<(String, String, String)> = FUNC_BLOCK_RE
        .captures_iter(code)
        .map(|c| {
            (
                c.get(1).map(|m| m.as_str()).unwrap_or("").to_string(),
                c.get(2).map(|m| m.as_str()).unwrap_or("").to_string(),
                c.get(3).map(|m| m.as_str()).unwrap_or("").to_string(),
            )
        })
        .collect();

    // Check if contract is upgradeable.
    let is_upgradeable = code.contains("Initializable")
        || code.contains("initializer")
        || code.contains("onlyInitializing");

    if is_upgradeable {
        // Check constructor block to ensure it disables initializers.
        if let Some(constructor_match) = CONSTRUCTOR_RE.captures(code) {
            let constructor_body = constructor_match.get(2).map(|m| m.as_str()).unwrap_or("");
            if !constructor_body.contains("_disableInitializers") {
                vulnerable_funcs.push("constructor".to_string());
                flagged_findings.push(
                    "Constructor is present in upgradeable contract but does not call '_disableInitializers()'. \
This allows third parties to initialize the logic contract and execute self-destruct instructions."
                        .to_string(),
                );
            }
        }

        // Check all functions named initialize or similar to ensure they are guarded.
        for (name, _args, _body) in &func_blocks {
            if name.to_lowercase().contains("initialize") && code.contains("function") {
                // Build per-function definition regex from the (regex-safe) name.
                let def_re = Regex::new(&format!(
                    r"function\s+{}\s*\((.*?)\)[^{{]*",
                    name
                ))
                .unwrap();
                if let Some(func_def_match) = def_re.find(code) {
                    let def_string = func_def_match.as_str();
                    if !def_string.contains("initializer")
                        && !def_string.contains("onlyInitializing")
                    {
                        vulnerable_funcs.push(name.clone());
                        flagged_findings.push(format!(
                            "Upgradeable initialization function '{name}' is missing 'initializer' or 'onlyInitializing' guards. \
This allows attackers to re-initialize and hijack implementation controls."
                        ));
                    }
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_INITIALIZER_RISK".to_string();
        } else {
            status = "WARN_INITIALIZER_RISK".to_string();
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
    let out = audit_upgradeable_initializer(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_upgradeable_initializer(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_upgradeable_passes() {
        std::env::set_var("PI_UPGRADE_INIT_STRICT_MODE", "true");
        let code = "import {Initializable} from 'x';\n\
contract Foo is Initializable {\n\
    constructor() {\n\
        _disableInitializers();\n\
    }\n\
    function initialize(uint x) public initializer {\n\
        a = x;\n\
    }\n\
}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        std::env::remove_var("PI_UPGRADE_INIT_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn missing_disable_initializers_flagged() {
        std::env::set_var("PI_UPGRADE_INIT_STRICT_MODE", "true");
        let code = "import {Initializable} from 'x';\n\
contract Foo is Initializable {\n\
    constructor() {\n\
        x = 1;\n\
    }\n\
    function initialize(uint y) public initializer {\n\
        a = y;\n\
    }\n\
}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_INITIALIZER_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["constructor".to_string()]);
        std::env::remove_var("PI_UPGRADE_INIT_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn unguarded_initializer_warn_in_non_strict() {
        std::env::set_var("PI_UPGRADE_INIT_STRICT_MODE", "false");
        let code = "import {Initializable} from 'x';\n\
contract Foo {\n\
    function initialize(uint y) public {\n\
        a = y;\n\
    }\n\
}";
        let o = run(code);
        // initialize is unguarded -> vulnerable, but non-strict coerces is_secure=true.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_INITIALIZER_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["initialize".to_string()]);
        std::env::remove_var("PI_UPGRADE_INIT_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn non_upgradeable_passes() {
        std::env::set_var("PI_UPGRADE_INIT_STRICT_MODE", "true");
        let code = "contract Plain {\n    function foo() public {\n        a = 1;\n    }\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        std::env::remove_var("PI_UPGRADE_INIT_STRICT_MODE");
    }
}
