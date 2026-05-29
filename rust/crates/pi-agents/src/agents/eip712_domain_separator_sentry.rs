//! Port of `pi_micro_agents/pi_eip712_domain_separator_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits upgradeable contracts for EIP-712
//! dynamic domain separator compliance. It flags upgradeable contracts that
//! declare or initialize `DOMAIN_SEPARATOR` as constant/immutable or inside the
//! constructor, which exposes them to cross-chain signature replay attacks.
//!
//! Behaviour is a line-for-line mirror of the Python original.

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

// --- Regexes (mirroring the Python `re.search` patterns exactly) ---
//
// None of these patterns use lookahead/lookbehind/backreferences, so they
// translate directly to the `regex` crate.
//
// Note on dotall semantics: Python's `.` (without `re.DOTALL`) does NOT match
// newlines, and the Rust `regex` crate's `.` likewise does not match `\n` by
// default. `[\s\S]` is used (as in Python) to match across newlines explicitly.

static IMMUTABLE_PUBLIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"bytes32\s+public\s+immutable\s+DOMAIN_SEPARATOR").unwrap());
static CONSTANT_PUBLIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"bytes32\s+public\s+constant\s+DOMAIN_SEPARATOR").unwrap());
static IMMUTABLE_BARE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"bytes32\s+immutable\s+DOMAIN_SEPARATOR").unwrap());
// `constructor\s*\((.*?)\)\s*\{([\s\S]*?)\}` -- group 2 is the constructor body.
static CONSTRUCTOR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"constructor\s*\((.*?)\)\s*\{([\s\S]*?)\}").unwrap());

/// Mirrors `is_strict_mode()`:
///   1. If the env var is set, return `env_val.lower() == "true"`.
///   2. Otherwise consult `~/.antigravitycli/config.json` (falling back to the
///      repo-local `<src>/../../.antigravitycli/config.json`), returning
///      `bool(data.get("PI_DOMAIN_SEPARATOR_STRICT_MODE", True))`.
///   3. Default to `true`.
fn is_strict_mode() -> bool {
    if let Ok(v) = std::env::var("PI_DOMAIN_SEPARATOR_STRICT_MODE") {
        return v.to_lowercase() == "true";
    }

    let mut config_path = home_config_path();
    if config_path
        .as_deref()
        .map(std::path::Path::new)
        .map_or(true, |p| !p.exists())
    {
        config_path = repo_config_path();
    }

    if let Some(path) = config_path {
        let p = std::path::Path::new(&path);
        if p.exists() {
            if let Ok(contents) = std::fs::read_to_string(p) {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&contents) {
                    return py_truthy(data.get("PI_DOMAIN_SEPARATOR_STRICT_MODE"));
                }
            }
        }
    }
    true
}

/// `os.path.expanduser("~/.antigravitycli/config.json")`.
fn home_config_path() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    Some(format!("{home}/.antigravitycli/config.json"))
}

/// Repo-local fallback: `<this crate file dir>/../../.antigravitycli/config.json`
/// in the Python layout maps to the repo root `.antigravitycli/config.json`.
/// `__file__` lives at `src/pi_micro_agents/`, so `../../` is the repo root.
/// We resolve it by walking up from CWD looking for a `.antigravitycli/config.json`.
fn repo_config_path() -> Option<String> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".antigravitycli").join("config.json");
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Mirrors Python `bool(data.get(key, True))` where the value (if present) is a
/// JSON scalar. Python truthiness: `True`/non-zero/non-empty -> true.
fn py_truthy(v: Option<&serde_json::Value>) -> bool {
    match v {
        None => true, // default True
        Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(serde_json::Value::Array(a)) => !a.is_empty(),
        Some(serde_json::Value::Object(o)) => !o.is_empty(),
    }
}

pub fn audit_domain_separator(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let is_upgradeable =
        code.contains("Initializable") || code.contains("UUPSUpgradeable") || code.contains("Upgradeable");

    if is_upgradeable {
        // Check if DOMAIN_SEPARATOR is declared immutable or constant.
        let has_immutable_separator = IMMUTABLE_PUBLIC.is_match(code)
            || CONSTANT_PUBLIC.is_match(code)
            || IMMUTABLE_BARE.is_match(code);

        // Check if DOMAIN_SEPARATOR is initialized inside the constructor instead
        // of an initializer function or dynamically.
        let mut has_constructor_init = false;
        if let Some(caps) = CONSTRUCTOR.captures(code) {
            // Python `constructor_match.group(2)` -> the constructor body.
            let constructor_body = caps.get(2).map_or("", |m| m.as_str());
            if constructor_body.contains("DOMAIN_SEPARATOR") {
                has_constructor_init = true;
            }
        }

        if has_immutable_separator || has_constructor_init {
            vulnerable_funcs.push("DOMAIN_SEPARATOR".to_string());
            flagged_findings.push(
                "The contract appears to be upgradeable but defines or initializes EIP-712 'DOMAIN_SEPARATOR' \
as constant, immutable, or inside the constructor. In upgradeable proxies, this leads to incorrect \
domain verification (using implementation address or outdated block.chainid), exposing the contract \
to cross-chain signature replay attacks."
                    .to_string(),
            );
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_DOMAIN_SEPARATOR".to_string();
        } else {
            status = "WARN_DOMAIN_SEPARATOR".to_string();
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
    let out = audit_domain_separator(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_domain_separator(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn non_upgradeable_passes() {
        // No upgradeable markers -> never flagged, regardless of DOMAIN_SEPARATOR.
        let code = "contract C { bytes32 public immutable DOMAIN_SEPARATOR; }";
        std::env::remove_var("PI_DOMAIN_SEPARATOR_STRICT_MODE");
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn upgradeable_immutable_rejected_strict() {
        let code = "contract C is Initializable { bytes32 public immutable DOMAIN_SEPARATOR; }";
        std::env::set_var("PI_DOMAIN_SEPARATOR_STRICT_MODE", "true");
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DOMAIN_SEPARATOR");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["DOMAIN_SEPARATOR"]);
        std::env::remove_var("PI_DOMAIN_SEPARATOR_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn upgradeable_constructor_init_warn_nonstrict() {
        let code = "contract C is UUPSUpgradeable { constructor() { DOMAIN_SEPARATOR = keccak256(abi.encode(0)); } }";
        std::env::set_var("PI_DOMAIN_SEPARATOR_STRICT_MODE", "false");
        let o = run(code);
        // Non-strict -> WARN path, is_secure coerced back to true.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_DOMAIN_SEPARATOR");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["DOMAIN_SEPARATOR"]);
        std::env::remove_var("PI_DOMAIN_SEPARATOR_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn upgradeable_dynamic_separator_passes() {
        // Upgradeable but DOMAIN_SEPARATOR is not immutable/constant and not in
        // the constructor -> secure.
        let code = "contract C is Initializable { function init() public { DOMAIN_SEPARATOR = compute(); } }";
        std::env::set_var("PI_DOMAIN_SEPARATOR_STRICT_MODE", "true");
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        std::env::remove_var("PI_DOMAIN_SEPARATOR_STRICT_MODE");
    }
}
