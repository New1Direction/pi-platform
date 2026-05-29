//! Port of `pi_micro_agents/pi_centralization_sentry.py`.
//!
//! Audits Solidity contracts for centralization risks (admin functions lacking
//! timelocks / multisig) and timelock-delay compliance. Behaviour is a
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

// `\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(`
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// `re.sub(r'//.*', '', ...)` — single-line comment, `.` does not match `\n`.
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// `re.sub(r'/\*.*?\*/', '', ..., flags=re.DOTALL)` — block comment, DOTALL.
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// The Python helper first consults the env var `PI_CENTRALIZATION_STRICT_MODE`
/// (returning `lower() == "true"`), and only if it is unset falls back to a
/// `.antigravitycli/config.json` file, ultimately defaulting to `True`. We
/// mirror the env-var branch exactly and treat "env unset" as strict (`True`),
/// which equals the Python default when the config file is absent. See
/// `deviations` in the parity spec for the config-file fallback caveat.
fn is_strict_mode() -> bool {
    match std::env::var("PI_CENTRALIZATION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `extract_solidity_functions`: returns `(func_name, func_body, start_line)`.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let bytes = solidity_code.as_bytes();
    let code_len = solidity_code.len();
    let mut functions: Vec<(String, String, usize)> = Vec::new();

    for caps in FUNC_RE.captures_iter(solidity_code) {
        let keyword = caps.get(1).unwrap().as_str();
        let name = caps.get(2).unwrap().as_str();
        let func_name: String = match keyword {
            "function" => name.to_string(),
            "constructor" => "constructor".to_string(),
            "fallback" => "fallback".to_string(),
            _ => "receive".to_string(),
        };

        let start_idx = caps.get(0).unwrap().start();
        // `solidity_code[:start_idx].count('\n') + 1`
        let start_line = solidity_code[..start_idx].matches('\n').count() + 1;

        // `solidity_code.find(';', start_idx)` / `.find('{', start_idx)`,
        // returning -1 (here: None) when not found.
        let semicolon_idx = find_byte(bytes, start_idx, b';');
        let brace_idx = find_byte(bytes, start_idx, b'{');

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue
        let brace_idx = match brace_idx {
            None => continue,
            Some(b) => {
                if let Some(s) = semicolon_idx {
                    if s < b {
                        continue;
                    }
                }
                b
            }
        };

        let mut brace_count: i64 = 1;
        let mut curr_idx = brace_idx + 1;
        while curr_idx < code_len && brace_count > 0 {
            let ch = bytes[curr_idx];
            if ch == b'{' {
                brace_count += 1;
            } else if ch == b'}' {
                brace_count -= 1;
            }
            curr_idx += 1;
        }

        if brace_count == 0 {
            let func_body = solidity_code[start_idx..curr_idx].to_string();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

/// `str.find(ch, start)` over bytes, returning the byte index or `None`.
fn find_byte(bytes: &[u8], start: usize, target: u8) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|&b| b == target)
        .map(|p| start + p)
}

pub fn audit_centralization(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    for (func_name, func_body, start_line) in &functions {
        // cleaned_body = re.sub(r'//.*', '', func_body)
        let cleaned_body = LINE_COMMENT_RE.replace_all(func_body, "");
        // cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "").into_owned();

        let func_name_lower = func_name.to_lowercase();
        let cleaned_body_lower = cleaned_body.to_lowercase();

        // Mode 1: Centralization Risk Check
        if ["mint", "pause", "unpause", "fee", "withdraw"]
            .iter()
            .any(|action| func_name_lower.contains(action))
        {
            if ["onlyOwner", "onlyAdmin", "onlyRole"]
                .iter()
                .any(|m| func_body.contains(m))
            {
                if !["timelock", "delay", "propose", "execute", "multisig", "threshold"]
                    .iter()
                    .any(|safe| cleaned_body_lower.contains(safe))
                {
                    vulnerable_funcs.push(func_name.clone());
                    flagged_findings.push(format!(
                        "Centralization Risk: Admin function '{func_name}' on Line {start_line} allows instant execution \
of highly privileged action without explicit timelocks or multi-signature consensus steps."
                    ));
                }
            }
        }

        // Mode 2: Multi-Sig/Timelock Setup Verification
        if func_name_lower.contains("timelock") || func_name_lower.contains("delay") {
            if cleaned_body_lower.contains("delay") && cleaned_body.contains('<') {
                if !["172800", "2 days", "48 hours"]
                    .iter()
                    .any(|limit| cleaned_body.contains(limit))
                {
                    flagged_findings.push(format!(
                        "Timelock Compliance warning: Function '{func_name}' on Line {start_line} updates timelock delay parameters \
but does not enforce a secure minimum floor bounds (e.g. 2 days delay)."
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
            status = "REJECTED_CENTRALIZATION_RISK".to_string();
        } else {
            status = "WARN_CENTRALIZATION_RISK".to_string();
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
    let out = audit_centralization(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_centralization(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_contract_passes() {
        std::env::remove_var("PI_CENTRALIZATION_STRICT_MODE");
        let code = "function transfer(address to, uint amount) public { balances[to] += amount; }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn centralized_mint_flagged_strict() {
        std::env::set_var("PI_CENTRALIZATION_STRICT_MODE", "true");
        let code = "function mint(address to, uint amt) public onlyOwner { _mint(to, amt); }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_CENTRALIZATION_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["mint"]);
        std::env::remove_var("PI_CENTRALIZATION_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn centralized_mint_warns_non_strict() {
        std::env::set_var("PI_CENTRALIZATION_STRICT_MODE", "false");
        let code = "function pauseContract() public onlyAdmin { paused = true; }";
        let o = run(code);
        // non-strict -> WARN and is_secure coerced back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_CENTRALIZATION_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["pauseContract"]);
        std::env::remove_var("PI_CENTRALIZATION_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn timelock_with_safeguard_not_flagged() {
        std::env::remove_var("PI_CENTRALIZATION_STRICT_MODE");
        // contains "timelock" safe keyword in body -> Mode 1 not triggered
        let code =
            "function mintFee() public onlyOwner { require(block.timestamp > timelock); _do(); }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }
}
