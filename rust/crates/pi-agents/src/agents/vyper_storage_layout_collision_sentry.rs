//! Port of `pi_micro_agents/pi_vyper_storage_layout_collision_sentry.py`.
//!
//! Audits Vyper upgradeable contracts for storage layout collisions caused by
//! declaring upgrade-marked state variables out-of-order (before older state
//! variable declarations). Behaviour is a line-for-line mirror of the Python
//! original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub vyper_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_variables: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors the Python state-variable declaration regex:
/// `r'^([a-zA-Z0-9_]+)\s*:\s*([^#\n]+)'` (used with `re.match`, i.e. anchored
/// at the start of the string). No lookaround / backreferences, so it ports
/// directly. `re.match` only anchors the start, so we do NOT add `$`.
static VAR_DECL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^([a-zA-Z0-9_]+)\s*:\s*([^#\n]+)").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python order: env var `PI_VYPER_STORAGE_COLLISION_STRICT_MODE` (case-insensitive
/// "true" => true); otherwise consult `~/.antigravitycli/config.json` (or the
/// repo-relative fallback), defaulting to True. When neither config file is
/// present/parseable, returns True.
///
/// Like the `jwt_none_sentry` reference port, we implement only the env-var
/// branch and default to `true` (the config-file branch resolves to `True` for
/// this key in this repo's config). See `deviations` in the parity report.
fn is_strict_mode() -> bool {
    match std::env::var("PI_VYPER_STORAGE_COLLISION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_vyper_storage_collision(input: &Input) -> Output {
    let code = &input.vyper_code;
    let mut vulnerable_vars: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Parse global state variables (defined outside of functions/def statements).
    // Each entry: (var_name, var_type, line_num).
    let mut state_vars: Vec<(String, String, usize)> = Vec::new();

    let lines = pyutil::splitlines(code);
    let mut in_fn = false;
    for (i, line) in lines.into_iter().enumerate() {
        let line_num = i + 1;
        let clean_line = pyutil::strip(line);
        if clean_line.is_empty() || clean_line.starts_with('#') {
            continue;
        }

        // Detect start of a function block in Vyper.
        if clean_line.starts_with("def ") || clean_line.starts_with('@') {
            in_fn = true;
            continue;
        }

        if in_fn {
            // If indentation is 0 and it starts a new block, we might have left
            // function scope.
            if line.starts_with("def ") || line.starts_with('@') {
                in_fn = true;
            } else if !line.starts_with(' ')
                && !line.starts_with('\t')
                && clean_line.contains(':')
            {
                // Variable declared outside functions.
                in_fn = false;
            }
        }

        if !in_fn {
            if let Some(caps) = VAR_DECL_RE.captures(clean_line) {
                let var_name = caps.get(1).unwrap().as_str().to_string();
                let var_type = pyutil::strip(caps.get(2).unwrap().as_str()).to_string();
                // Skip constant or immutable variable decorations.
                if !var_type.contains("constant") && !var_type.contains("immutable") {
                    state_vars.push((var_name, var_type, line_num));
                }
            }
        }
    }

    // Look for state variables defined with upgrade-like markers but not at the
    // end of the state variable declaration list, where older (unmarked)
    // variables follow them -> storage slot collision.
    let n = state_vars.len();
    for idx in 0..n {
        let (var_name, _var_type, line_num) = &state_vars[idx];
        if var_name.contains("_v2") || var_name.contains("_upgrade") || var_name.contains("new_") {
            // If this upgraded variable is NOT at the end of the list, it may
            // cause slot collisions.
            if idx < n - 1 {
                // Check if subsequent variables are older declarations.
                let mut older_found = false;
                for next in &state_vars[idx + 1..n] {
                    let next_name = &next.0;
                    if !next_name.contains("_v2")
                        && !next_name.contains("_upgrade")
                        && !next_name.contains("new_")
                    {
                        older_found = true;
                    }
                }

                if older_found {
                    vulnerable_vars.push(var_name.clone());
                    flagged_findings.push(format!(
                        "State variable '{var_name}' at line {line_num} contains upgrade-like markers but is defined \
prior to older state variable definitions in the layout list. In upgradeable Vyper contracts, \
declaring upgraded state variables out-of-order alters layout mapping, causing total \
storage corruption slots collision."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_vars.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_VYPER_STORAGE_COLLISION".to_string();
        } else {
            status = "WARN_VYPER_STORAGE_COLLISION".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_variables: vulnerable_vars,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_vyper_storage_collision(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_vyper_storage_collision(&Input {
            file_path: "c.vy".into(),
            vyper_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_layout_passes() {
        std::env::remove_var("PI_VYPER_STORAGE_COLLISION_STRICT_MODE");
        let o = run("owner: public(address)\nbalance: uint256\ntotal: uint256");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_variables.is_empty());
    }

    #[test]
    #[serial]
    fn out_of_order_upgrade_var_flagged() {
        std::env::remove_var("PI_VYPER_STORAGE_COLLISION_STRICT_MODE");
        // _v2 var appears before an older (unmarked) var -> collision.
        let o = run("owner: public(address)\nbalance_v2: uint256\ntotal: uint256");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_VYPER_STORAGE_COLLISION");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_variables, vec!["balance_v2"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    #[serial]
    fn non_strict_env_warns_and_coerces_secure() {
        std::env::set_var("PI_VYPER_STORAGE_COLLISION_STRICT_MODE", "false");
        let o = run("owner: public(address)\nnew_admin: address\nlegacy: uint256");
        std::env::remove_var("PI_VYPER_STORAGE_COLLISION_STRICT_MODE");
        assert!(o.is_secure); // coerced back to True in WARN path
        assert_eq!(o.status, "WARN_VYPER_STORAGE_COLLISION");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_variables, vec!["new_admin"]);
    }

    #[test]
    #[serial]
    fn upgrade_var_at_end_is_safe() {
        std::env::remove_var("PI_VYPER_STORAGE_COLLISION_STRICT_MODE");
        // _v2 var is last -> idx == n-1 -> not flagged.
        let o = run("owner: public(address)\ntotal: uint256\nbalance_v2: uint256");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_variables.is_empty());
    }
}
