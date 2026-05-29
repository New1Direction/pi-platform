//! Port of `pi_micro_agents/pi_read_only_oracle_manipulation_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for read-only
//! spot oracle price manipulation risks. Behaviour is a line-for-line mirror of
//! the Python original.

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

// Mirrors:
//   re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// Python `.` does not match newlines (no re.DOTALL), so `(.*?)` for args stays
// on a single logical region; `[\s\S]*?` for the body matches everything lazily.
// No lookahead/lookbehind/backreferences => translates directly to the regex
// crate. `re.findall` with 3 groups behaves like `captures_iter`.
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

/// Mirrors `is_strict_mode()` in the Python source.
///
/// 1. If env var `PI_READ_ONLY_ORACLE_STRICT_MODE` is set, return
///    `value.lower() == "true"`.
/// 2. Otherwise look for `~/.antigravitycli/config.json`, falling back to the
///    repo-relative `<module_dir>/../../.antigravitycli/config.json`, and read
///    the `PI_READ_ONLY_ORACLE_STRICT_MODE` key (default `True` if absent).
/// 3. Default to `true` when nothing is found / on any read or parse error.
fn is_strict_mode() -> bool {
    if let Ok(env_val) = std::env::var("PI_READ_ONLY_ORACLE_STRICT_MODE") {
        return env_val.to_lowercase() == "true";
    }

    // Resolve config path: prefer ~/.antigravitycli/config.json.
    let home_path = home_config_path();
    let config_path = match &home_path {
        Some(p) if p.exists() => Some(p.clone()),
        _ => {
            // Python falls back to <module_dir>/../../.antigravitycli/config.json.
            // The Rust port has no equivalent module dir; we attempt the
            // current-dir-relative location used by the repo layout.
            let fallback = std::path::PathBuf::from(".antigravitycli/config.json");
            if fallback.exists() {
                Some(fallback)
            } else {
                None
            }
        }
    };

    if let Some(path) = config_path {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&contents) {
                // bool(data.get("PI_READ_ONLY_ORACLE_STRICT_MODE", True))
                match data.get("PI_READ_ONLY_ORACLE_STRICT_MODE") {
                    Some(v) => return json_truthy(v),
                    None => return true,
                }
            }
            // json parse error -> Python catches and falls through to `return True`.
        }
        // read error -> Python catches and falls through to `return True`.
    }
    true
}

fn home_config_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(std::path::PathBuf::from(home).join(".antigravitycli/config.json"))
}

/// Mirrors Python `bool(x)` truthiness for a JSON value (as produced by
/// `json.load`): None/false/0/0.0/""/[]/{}  => false, everything else true.
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

pub fn audit_read_only_oracle(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions.
    for caps in FUNC_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // group 2 (args) is captured but unused, mirroring the Python loop var.
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        let name_lower = name.to_lowercase();
        let body_lower = body.to_lowercase();

        // Check if function queries spot pricing methods of Balancer, Curve,
        // Uniswap reserves, etc.
        if (body.contains("getReserves")
            || body.contains("queryBatchSwap")
            || body.contains("get_dy"))
            && (body.contains("balanceOf")
                || name_lower.contains("price")
                || name_lower.contains("oracle"))
        {
            // Check if it lacks TWAP or secondary oracle verifications
            // (Chainlink fallback).
            let has_fallback = body.contains("latestRoundData")
                || body.contains("consult")
                || body.contains("observe")
                || body_lower.contains("twap");
            if !has_fallback {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' queries spot balance/swap rates directly from an AMM pool \
without dynamic TWAP observations or Chainlink oracle verifications. This exposes \
the contract to instant oracle price manipulation via flash loans."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ORACLE_RISK".to_string();
        } else {
            status = "WARN_ORACLE_RISK".to_string();
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
    let out = audit_read_only_oracle(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_read_only_oracle(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_code_passes() {
        std::env::set_var("PI_READ_ONLY_ORACLE_STRICT_MODE", "true");
        let o = run(
            "function getPrice() public view returns (uint) { \
             uint p = oracle.latestRoundData(); return p; }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        std::env::remove_var("PI_READ_ONLY_ORACLE_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn spot_price_without_fallback_flagged_strict() {
        std::env::set_var("PI_READ_ONLY_ORACLE_STRICT_MODE", "true");
        let o = run(
            "function getPrice() public view returns (uint) { \
             (uint112 r0, uint112 r1,) = pair.getReserves(); uint bal = token.balanceOf(addr); return r0; }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ORACLE_RISK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["getPrice"]);
        std::env::remove_var("PI_READ_ONLY_ORACLE_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn non_strict_env_warns_and_coerces_secure() {
        std::env::set_var("PI_READ_ONLY_ORACLE_STRICT_MODE", "false");
        let o = run(
            "function spotOracle() public view returns (uint) { \
             uint dy = curve.get_dy(0, 1, 1e18); return dy; }",
        );
        // vulnerable (name contains "oracle", body has get_dy, no fallback),
        // but non-strict mode coerces is_secure back to true with a WARN status.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ORACLE_RISK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["spotOracle"]);
        std::env::remove_var("PI_READ_ONLY_ORACLE_STRICT_MODE");
    }
}
