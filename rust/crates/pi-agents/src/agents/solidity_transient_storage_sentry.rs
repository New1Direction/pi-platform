//! Port of `pi_micro_agents/pi_solidity_transient_storage_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for Cancun
//! EIP-1153 transient storage (`tstore`/`tload`) misuse. Behaviour is a
//! line-for-line mirror of the Python original.
//!
//! Parity note on the function-block scan: the Python source uses
//! `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}` (three capture
//! groups, body terminated by the FIRST `}`). This pattern is fully
//! lookahead/lookbehind/backreference free, so the Rust `regex` crate matches it
//! directly via `captures_iter` (non-overlapping, leftmost, lazy quantifiers),
//! which has the same semantics as `re.findall`. `.` does not match `\n` (Python
//! had no `re.DOTALL`), and `[\s\S]` matches everything including newlines, in
//! both engines.

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

// `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`
// Groups: 1 = name, 2 = args, 3 = body. `.` does not match `\n` (no DOTALL);
// `[\s\S]` matches everything including newlines.
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// `re.search(r'tstore\s*\(\s*[a-zA-Z0-9_]+\s*,\s*0\s*\)', body)` (no groups).
static HAS_CLEAR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"tstore\s*\(\s*[a-zA-Z0-9_]+\s*,\s*0\s*\)").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Order, faithful to Python:
///   1. If env var `PI_TRANSIENT_STORAGE_STRICT_MODE` is set, return
///      `value.to_lowercase() == "true"`.
///   2. Else read `~/.antigravitycli/config.json`; if it does not exist, fall
///      back to the repo-relative `../../.antigravitycli/config.json` (relative
///      to the Python module's directory, i.e. the repo root).
///   3. If a config file exists, parse it and return
///      `bool(data.get("PI_TRANSIENT_STORAGE_STRICT_MODE", True))`. Any error
///      (missing file, bad JSON) falls through to `True`.
///   4. Default: `True`.
///
/// PARITY NOTE: in this repository the key `PI_TRANSIENT_STORAGE_STRICT_MODE` is
/// absent from the repo `.antigravitycli/config.json`, so the config path
/// resolves to `True`. The full file lookup is replicated here for faithfulness,
/// but the only way to observe a non-strict result is the env var (or a home
/// config file that explicitly sets the key to a falsey JSON value).
fn is_strict_mode() -> bool {
    if let Ok(env_val) = std::env::var("PI_TRANSIENT_STORAGE_STRICT_MODE") {
        return env_val.to_lowercase() == "true";
    }

    // os.path.expanduser("~/.antigravitycli/config.json")
    let home_path: Option<std::path::PathBuf> = std::env::var_os("HOME")
        .map(|h| std::path::Path::new(&h).join(".antigravitycli/config.json"));

    let mut config_path: Option<std::path::PathBuf> = None;
    if let Some(hp) = home_path {
        if hp.exists() {
            config_path = Some(hp);
        }
    }
    if config_path.is_none() {
        // os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")
        // The Python module lives in src/pi_micro_agents/, so dirname/../../ is the
        // repo root. We resolve the same repo-root config file.
        let repo_cfg =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../.antigravitycli/config.json");
        if repo_cfg.exists() {
            config_path = Some(repo_cfg);
        }
    }

    if let Some(path) = config_path {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&contents) {
                // bool(data.get("PI_TRANSIENT_STORAGE_STRICT_MODE", True))
                return match data.get("PI_TRANSIENT_STORAGE_STRICT_MODE") {
                    Some(v) => json_truthy(v),
                    None => true,
                };
            }
        }
    }
    true
}

/// Mirrors Python `bool(x)` truthiness for JSON-decoded values.
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

pub fn audit_transient_storage(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // group 2 (args) captured but unused, exactly like the Python loop.
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Look for assembly block containing tstore/tload.
        if body.contains("assembly") && (body.contains("tstore") || body.contains("tload")) {
            // Check if it has a tstore to clear the slot (tstore(slot, 0)).
            let has_clear = HAS_CLEAR_RE.is_match(body);
            if !has_clear {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' utilizes transient storage (tstore/tload) \
but does not explicitly clear the storage slot to zero before exit. \
This may lead to transient reentrancy and dirty state bugs across transaction calls."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_TRANSIENT_RISK".to_string();
        } else {
            status = "WARN_TRANSIENT_RISK".to_string();
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
    let out = audit_transient_storage(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_transient_storage(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_contract_passes() {
        // No assembly / no transient storage usage at all.
        let o = run("function foo(uint x) public { return x; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn transient_without_clear_flagged() {
        let code = "function lock() public { assembly { tstore(0, 1) } }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TRANSIENT_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["lock"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    fn transient_with_clear_is_safe() {
        // tload present, and tstore(slot, 0) clears the slot -> secure.
        let code = "function unlock() public { assembly { let v := tload(0) tstore(0, 0) } }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn empty_code_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }
}
