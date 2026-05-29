//! Port of `pi_micro_agents/pi_erc7702_delegation_guard.py`.
//!
//! Audits Solidity contracts for ERC-7702 EOA delegation signature &
//! authorization safety. Behaviour is a line-for-line mirror of the Python
//! original.

use serde::{Deserialize, Serialize};
use std::path::Path;

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

/// Mirrors `is_strict_mode()`:
///   1. If env var `PI_ERC7702_GUARD_STRICT_MODE` is set -> `lower() == "true"`.
///   2. Else look at `~/.antigravitycli/config.json`; if missing, fall back to
///      a repo-relative `../../.antigravitycli/config.json` (relative to the
///      Python source file).
///   3. If a config file exists, return `bool(data.get(key, True))`.
///   4. Otherwise default to `true`.
fn is_strict_mode() -> bool {
    // 1. Environment variable takes precedence.
    if let Ok(env_val) = std::env::var("PI_ERC7702_GUARD_STRICT_MODE") {
        return env_val.to_lowercase() == "true";
    }

    // 2. Resolve config path.
    //    Python: os.path.expanduser("~/.antigravitycli/config.json")
    let mut config_path: Option<String> = None;
    if let Some(home) = home_dir() {
        let p = format!("{}/.antigravitycli/config.json", home);
        if Path::new(&p).exists() {
            config_path = Some(p);
        }
    }
    //    Python fallback: os.path.join(os.path.dirname(__file__),
    //                                  "../../.antigravitycli/config.json")
    //    We cannot recover the Python source dir in Rust; the harness runs from
    //    the repo, so probe the repo-relative location best-effort. See
    //    deviations: when neither file carries the key, the default below (true)
    //    matches Python's `data.get(key, True)`.
    if config_path.is_none() {
        for candidate in [
            "../.antigravitycli/config.json",
            "../../.antigravitycli/config.json",
            ".antigravitycli/config.json",
        ] {
            if Path::new(candidate).exists() {
                config_path = Some(candidate.to_string());
                break;
            }
        }
    }

    // 3. Read the config file if present.
    if let Some(path) = config_path {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) {
                if let Some(obj) = value.as_object() {
                    match obj.get("PI_ERC7702_GUARD_STRICT_MODE") {
                        Some(v) => return python_bool(v),
                        None => return true, // data.get(key, True)
                    }
                }
            }
        }
    }

    // 4. Default.
    true
}

/// Best-effort `os.path.expanduser("~")` source: prefer `$HOME`.
fn home_dir() -> Option<String> {
    std::env::var("HOME").ok().filter(|h| !h.is_empty())
}

/// Mirrors Python `bool(x)` for a JSON value pulled from the config dict.
fn python_bool(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Null => false,
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i != 0
            } else if let Some(u) = n.as_u64() {
                u != 0
            } else {
                n.as_f64().map(|f| f != 0.0).unwrap_or(false)
            }
        }
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

/// Compiled equivalent of:
///   re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
///
/// Python uses default flags (no DOTALL), so `.` (inside the args group
/// `(.*?)`) does NOT match newlines. `[\s\S]` always matches everything,
/// including newlines. The Rust `regex` crate has the same default (`.` excludes
/// `\n`), so the pattern maps directly with no flags. No lookaround/backrefs.
fn func_regex() -> regex::Regex {
    regex::Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
}

pub fn audit_erc7702_delegation(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions. `captures_iter` mirrors `re.findall` with >1 group:
    // each item yields the (name, args, body) capture tuple.
    let re = func_regex();
    let code_lower = code.to_lowercase();
    for caps in re.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // args (group 2) is matched but never referenced in the Python logic.
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        let name_lower = name.to_lowercase();
        let body_lower = body.to_lowercase();

        // Check for delegation hooks, authorization setups, or signature checks.
        if name_lower.contains("delegate")
            || name_lower.contains("authorize")
            || body_lower.contains("signature")
        {
            // Signatures must include nonces to prevent replay.
            if !body_lower.contains("nonce")
                && !code_lower.contains("nonces")
                && body.contains("ecrecover")
            {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' processes dynamic account delegation/signatures but does not implement \
nonce tracking. This exposes the EIP-7702 smart account delegation to message replay attacks."
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
            status = "REJECTED_ERC7702_RISK".to_string();
        } else {
            status = "WARN_ERC7702_RISK".to_string();
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
    let out = audit_erc7702_delegation(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        // Force strict default regardless of ambient config for deterministic
        // unit assertions.
        std::env::set_var("PI_ERC7702_GUARD_STRICT_MODE", "true");
        audit_erc7702_delegation(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_contract_passes() {
        let code = "function transfer(address to, uint256 v) public { balances[to] += v; }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn delegate_without_nonce_flagged() {
        let code = "function delegateAuth(bytes sig) public { address s = ecrecover(h, v, r, ss); }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ERC7702_RISK");
        assert_eq!(o.vulnerable_functions, vec!["delegateAuth"]);
        assert_eq!(o.risk_score, 80.0);
    }

    #[test]
    #[serial]
    fn nonce_present_is_safe() {
        let code = "function delegateAuth(bytes sig) public { uint n = nonce; address s = ecrecover(h, v, r, ss); }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn warn_mode_when_not_strict() {
        std::env::set_var("PI_ERC7702_GUARD_STRICT_MODE", "false");
        let o = audit_erc7702_delegation(&Input {
            file_path: "C.sol".into(),
            solidity_code: "function delegateAuth(bytes sig) public { address s = ecrecover(h, v, r, ss); }".into(),
            check_level: "STRICT".into(),
        });
        // is_secure is coerced back to true in WARN mode, but the function is
        // still recorded as vulnerable.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ERC7702_RISK");
        assert_eq!(o.vulnerable_functions, vec!["delegateAuth"]);
        std::env::set_var("PI_ERC7702_GUARD_STRICT_MODE", "true");
    }
}
