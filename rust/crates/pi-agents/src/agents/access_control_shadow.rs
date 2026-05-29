//! Port of `pi_micro_agents/pi_access_control_shadow.py`.
//!
//! Audits Solidity contracts for administrative functions that are missing an
//! access-control modifier (e.g. `onlyOwner` / `onlyRole`). Behaviour is a
//! line-for-line mirror of the Python original.

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

// Python: re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// `[\s\S]` matches any char incl. newlines, so no DOTALL flag is needed. The
// `(.*?)` for args does NOT span newlines (Python `.` w/o DOTALL), so we leave
// the default (non-DOTALL) behaviour for `.` and rely on `[\s\S]` for the body.
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Admin-style keywords matched against `name.lower()`.
const ADMIN_KEYWORDS: [&str; 7] = [
    "admin", "setowner", "withdraw", "emergency", "pause", "mint", "burn",
];

// Access-control modifiers; for each we also build a `\bMOD\b` regex over the
// whole source, mirroring the Python `re.search(r'\b' + mod + r'\b', code)`.
const MODIFIERS: [&str; 4] = ["onlyOwner", "onlyRole", "restricted", "requireAdmin"];

static MODIFIER_RES: Lazy<Vec<Regex>> = Lazy::new(|| {
    MODIFIERS
        .iter()
        .map(|m| Regex::new(&format!(r"\b{m}\b")).unwrap())
        .collect()
});

/// Mirrors `is_strict_mode()`.
///
/// Faithful for the env-var branch (which all parity samples exercise). When the
/// env var is unset, Python additionally consults a JSON config file
/// (`~/.antigravitycli/config.json`, then `src/.antigravitycli/config.json`),
/// returning `bool(data.get("PI_AC_SHADOW_STRICT_MODE", True))` if found and
/// `True` otherwise. We replicate only the final default (`True`); see the
/// parity deviations note for the config-file fallback.
fn is_strict_mode() -> bool {
    match std::env::var("PI_AC_SHADOW_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_access_control(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions. captures: group(1)=name, group(2)=args, group(3)=body.
    for caps in FUNC_RE.captures_iter(code) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        let _args = caps.get(2).map_or("", |m| m.as_str());
        let body = caps.get(3).map_or("", |m| m.as_str());

        // Mode 1: Check for admin-style keywords.
        let name_lower = name.to_lowercase();
        let is_admin_action = ADMIN_KEYWORDS.iter().any(|kw| name_lower.contains(kw));

        if is_admin_action {
            // Mode 2: Verify it has an access modifier.
            // Python: any(mod in body or re.search(r'\b'+mod+r'\b', code) for mod in [...])
            let has_modifier = MODIFIERS.iter().enumerate().any(|(i, m)| {
                body.contains(m) || MODIFIER_RES[i].is_match(code)
            });

            if !has_modifier {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Administrative function '{name}' is missing an access control modifier \
(e.g., 'onlyOwner' or 'onlyRole'). This allows unauthorized users to trigger critical admin states."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_AC_SHADOW_RISK".to_string();
        } else {
            status = "WARN_AC_SHADOW_RISK".to_string();
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
    let out = audit_access_control(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        // Ensure deterministic strict mode for tests.
        std::env::set_var("PI_AC_SHADOW_STRICT_MODE", "true");
        audit_access_control(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_admin_with_modifier_passes() {
        let o = run("function withdraw() public onlyOwner { balance = 0; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn admin_without_modifier_flagged() {
        let o = run("function emergencyStop() public { paused = true; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_AC_SHADOW_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["emergencyStop"]);
    }

    #[test]
    #[serial]
    fn non_admin_function_ignored() {
        let o = run("function transfer(address to) public { x = to; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn warn_path_coerces_secure() {
        std::env::set_var("PI_AC_SHADOW_STRICT_MODE", "false");
        let o = audit_access_control(&Input {
            file_path: "C.sol".into(),
            solidity_code: "function mintTokens() public { supply += 1; }".into(),
            check_level: "MEDIUM".into(),
        });
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_AC_SHADOW_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["mintTokens"]);
        std::env::set_var("PI_AC_SHADOW_STRICT_MODE", "true");
    }
}
