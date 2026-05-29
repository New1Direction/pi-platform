//! Port of `pi_micro_agents/pi_solidity_eip712_typehash_mismatch_sentry.py`.
//!
//! Audits Solidity EIP-712 `TYPEHASH` constant declarations to ensure their
//! signature strings (e.g. `keccak256("Mail(address from,address to)")`) align
//! exactly with the layout of the corresponding `struct`. A mismatch breaks
//! structured signature verification. Behaviour is a line-for-line mirror of
//! the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

// --- Regexes (compiled once) -------------------------------------------------

// re.findall(r'struct\s+([a-zA-Z0-9_]+)\s*\{([\s\S]*?)\}', code) -- 2 groups.
// `[\s\S]` matches any char incl. newlines; `*?` is lazy.
static STRUCT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"struct\s+([a-zA-Z0-9_]+)\s*\{([\s\S]*?)\}").unwrap());

// re.findall(r'([a-zA-Z0-9_\[\]]+)\s+([a-zA-Z0-9_]+)\s*;', sbody) -- 2 groups.
static VAR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-zA-Z0-9_\[\]]+)\s+([a-zA-Z0-9_]+)\s*;").unwrap());

// re.findall(r'([a-zA-Z0-9_]+TYPEHASH[a-zA-Z0-9_]*)\s*=.*keccak256\s*\(\s*"([^"]+)"\s*\)', code)
// -- 2 groups. `.*` is greedy and (no DOTALL) does NOT span newlines, matching
// Rust's default `.` behaviour.
static TYPEHASH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"([a-zA-Z0-9_]+TYPEHASH[a-zA-Z0-9_]*)\s*=.*keccak256\s*\(\s*"([^"]+)"\s*\)"#)
        .unwrap()
});

// re.match(r'([a-zA-Z0-9_]+)\s*\(([^)]*)\)', signature) -- anchored at start.
static SIG_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^([a-zA-Z0-9_]+)\s*\(([^)]*)\)").unwrap());

/// Mirrors Python `" ".join(s.split())`: collapses any run of (ASCII) whitespace
/// to single spaces and strips leading/trailing whitespace.
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// Mirrors `is_strict_mode()`.
///
/// 1. If env var `PI_EIP712_TYPEHASH_STRICT_MODE` is set, return whether its
///    lowercased value equals "true".
/// 2. Otherwise look for `~/.antigravitycli/config.json`; if missing, fall back
///    to `<crate>/../../.antigravitycli/config.json` (the Python original
///    resolves this relative to its own module directory).
/// 3. If a config file exists, read key `PI_EIP712_TYPEHASH_STRICT_MODE`
///    (default `true`); any read/parse error yields `true`.
/// 4. Default `true`.
fn is_strict_mode() -> bool {
    if let Ok(env_val) = std::env::var("PI_EIP712_TYPEHASH_STRICT_MODE") {
        return env_val.to_lowercase() == "true";
    }

    // ~/.antigravitycli/config.json
    let mut config_path: Option<std::path::PathBuf> = None;
    if let Some(home) = home_dir() {
        let p = home.join(".antigravitycli").join("config.json");
        if p.exists() {
            config_path = Some(p);
        }
    }
    // Fallback relative to the source tree. Python uses os.path.dirname(__file__)
    // (src/pi_micro_agents) + "../../.antigravitycli/config.json" -> repo-root
    // config. We cannot know the original layout at runtime, so we mirror the
    // existence check only when the home config was absent.
    if config_path.is_none() {
        let fallback = repo_fallback_config();
        if let Some(p) = fallback {
            if p.exists() {
                config_path = Some(p);
            }
        }
    }

    if let Some(p) = config_path {
        match std::fs::read_to_string(&p) {
            Ok(contents) => match serde_json::from_str::<Value>(&contents) {
                Ok(v) => {
                    // bool(data.get("PI_EIP712_TYPEHASH_STRICT_MODE", True))
                    match v.get("PI_EIP712_TYPEHASH_STRICT_MODE") {
                        Some(val) => json_truthy(val),
                        None => true,
                    }
                }
                Err(_) => true,
            },
            Err(_) => true,
        }
    } else {
        true
    }
}

/// Python `bool(x)` truthiness for the JSON values that can appear in config.
fn json_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

/// Best-effort analogue of the Python module-relative fallback path. The Python
/// agent lives at `src/pi_micro_agents/...` and joins `../../.antigravitycli/
/// config.json`, i.e. the repository root. At runtime we approximate that via
/// the `CARGO_MANIFEST_DIR` of this crate walked up to the workspace root.
fn repo_fallback_config() -> Option<std::path::PathBuf> {
    // crate dir: <repo>/rust/crates/pi-agents
    let manifest = option_env!("CARGO_MANIFEST_DIR");
    let manifest = manifest?;
    let p = Path::new(manifest);
    // walk up to repo root: pi-agents -> crates -> rust -> <repo>
    let repo_root = p.parent()?.parent()?.parent()?;
    Some(repo_root.join(".antigravitycli").join("config.json"))
}

pub fn audit(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all structs defined in Solidity.
    // struct_map: name -> Vec<(vtype, vname)>
    let mut struct_map: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for caps in STRUCT_RE.captures_iter(code) {
        let sname = caps.get(1).unwrap().as_str().to_string();
        let sbody = caps.get(2).unwrap().as_str();
        let mut vars: Vec<(String, String)> = Vec::new();
        for vcaps in VAR_RE.captures_iter(sbody) {
            let vtype = vcaps.get(1).unwrap().as_str().trim().to_string();
            let vname = vcaps.get(2).unwrap().as_str().trim().to_string();
            vars.push((vtype, vname));
        }
        struct_map.push((sname, vars));
    }

    // Find all TYPEHASH constants/variables.
    for caps in TYPEHASH_RE.captures_iter(code) {
        let th_name = caps.get(1).unwrap().as_str();
        let signature = caps.get(2).unwrap().as_str();

        // re.match -> anchored prefix match.
        if let Some(sig_caps) = SIG_RE.captures(signature) {
            let sname = sig_caps.get(1).unwrap().as_str();
            let sig_params_raw = sig_caps.get(2).unwrap().as_str();
            // [p.strip() for p in sig_params_raw.split(",") if p.strip()]
            let sig_params: Vec<String> = sig_params_raw
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();

            // Look up the struct in the parsed mapping (first match, like dict
            // last-write-wins would differ — but Python builds a dict, so the
            // LAST struct with a given name wins). Mirror dict semantics.
            if let Some(expected_vars) = lookup_last(&struct_map, sname) {
                // Format expected vars as "type name".
                let expected_params: Vec<String> = expected_vars
                    .iter()
                    .map(|(vtype, vname)| format!("{vtype} {vname}"))
                    .collect();

                let mut mismatch = false;
                if sig_params.len() != expected_params.len() {
                    mismatch = true;
                } else {
                    for (sp, ep) in sig_params.iter().zip(expected_params.iter()) {
                        let sp_norm = collapse_ws(sp);
                        let ep_norm = collapse_ws(ep);
                        if sp_norm != ep_norm {
                            mismatch = true;
                            break;
                        }
                    }
                }

                if mismatch {
                    vulnerable_funcs.push(th_name.to_string());
                    flagged_findings.push(format!(
                        "EIP-712 TYPEHASH constant '{th_name}' signature definition '{signature}' does not match \
the actual Solidity struct '{sname}' variables: {}. \
This mismatch breaks structured signature verification.",
                        expected_params.join(", ")
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_TYPEHASH_MISMATCH".to_string();
        } else {
            status = "WARN_TYPEHASH_MISMATCH".to_string();
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

/// Mirrors Python dict semantics where `struct_map[sname] = ...` means the LAST
/// struct definition with a given name wins. Returns a reference to the vars of
/// the last entry whose name matches, or None.
fn lookup_last<'a>(
    struct_map: &'a [(String, Vec<(String, String)>)],
    name: &str,
) -> Option<&'a Vec<(String, String)>> {
    struct_map
        .iter()
        .rev()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
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
            file_path: "c.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_aligned_passes() {
        std::env::remove_var("PI_EIP712_TYPEHASH_STRICT_MODE");
        let code = "struct Mail {\n    address from;\n    address to;\n    string contents;\n}\nbytes32 constant MAIL_TYPEHASH = keccak256(\"Mail(address from,address to,string contents)\");\n";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn mismatch_count_flagged_strict() {
        std::env::set_var("PI_EIP712_TYPEHASH_STRICT_MODE", "true");
        let code = "struct Mail {\n    address from;\n    address to;\n    string contents;\n}\nbytes32 constant MAIL_TYPEHASH = keccak256(\"Mail(address from,address to)\");\n";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TYPEHASH_MISMATCH");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["MAIL_TYPEHASH"]);
        std::env::remove_var("PI_EIP712_TYPEHASH_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn mismatch_warn_when_non_strict() {
        std::env::set_var("PI_EIP712_TYPEHASH_STRICT_MODE", "false");
        let code = "struct Order {\n    uint256 amount;\n    address buyer;\n}\nbytes32 constant ORDER_TYPEHASH = keccak256(\"Order(uint256 qty,address buyer)\");\n";
        let o = run(code);
        // non-strict coerces is_secure back to true but still reports findings
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_TYPEHASH_MISMATCH");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["ORDER_TYPEHASH"]);
        std::env::remove_var("PI_EIP712_TYPEHASH_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn typehash_for_unknown_struct_is_ignored() {
        std::env::remove_var("PI_EIP712_TYPEHASH_STRICT_MODE");
        let code = "bytes32 constant FOO_TYPEHASH = keccak256(\"Ghost(address a)\");";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
