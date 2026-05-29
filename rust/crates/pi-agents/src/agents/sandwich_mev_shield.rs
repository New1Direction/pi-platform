//! Port of `pi_micro_agents/pi_sandwich_mev_shield.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for AMM slippage
//! configurations prone to sandwich attacks (hardcoded zero minimum-output on
//! swap operations). Behaviour is a line-for-line mirror of the Python original.

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

// re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
//
// Python `.` does NOT match newline (no DOTALL flag); `[\s\S]` matches every
// character including newlines. The Rust `regex` crate has identical defaults
// (`.` excludes `\n` unless `(?s)`), so the pattern ports verbatim. No
// lookaround/backreferences are used.
static FUNC_BLOCK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

// re.search(r'\b(swap...|swap)\b', body)
static SWAP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(swapExactTokensForTokens|swapTokensForExactTokens|exactInput|exactOutput|swap)\b",
    )
    .unwrap()
});

// re.search(r'amountOutMin\s*=\s*0|minAmountOut\s*=\s*0|amountOutMinimum\s*=\s*0', body)
static ZERO_SLIPPAGE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"amountOutMin\s*=\s*0|minAmountOut\s*=\s*0|amountOutMinimum\s*=\s*0").unwrap()
});

// re.search(r'\bswapExactTokensForTokens\s*\(\s*[^,]+,\s*0\s*,', body)
static HARDCODED_SWAP_ZERO_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bswapExactTokensForTokens\s*\(\s*[^,]+,\s*0\s*,").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: The Python original additionally falls back to reading a JSON config
/// file (`~/.antigravitycli/config.json` or a repo-relative copy) whose default
/// for the key is `True`. This port mirrors only the env-var branch and treats
/// env-absence as strict=True, matching that config default. See the matching
/// reference port `jwt_none_sentry.rs`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_MEV_SHIELD_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_mev_shield(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // group 2 (args) is captured by Python but unused beyond unpacking.
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Mode 1: Check for swap operations
        let swap_match = SWAP_RE.is_match(body);

        if swap_match {
            // Mode 2: Verify if amountOutMin is hardcoded to 0
            let zero_slippage_match = ZERO_SLIPPAGE_RE.is_match(body);
            let hardcoded_swap_zero = HARDCODED_SWAP_ZERO_RE.is_match(body);

            if zero_slippage_match || hardcoded_swap_zero {
                vulnerable_funcs.push(name.to_string());
                flagged_findings.push(format!(
                    "Function '{name}' executes a token swap with a hardcoded minimum output of 0. \
This permits execution under infinite slippage, exposing the trade to complete \
frontrunning / sandwich MEV theft."
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
            status = "REJECTED_MEV_RISK".to_string();
        } else {
            status = "WARN_MEV_RISK".to_string();
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
    let out = audit_mev_shield(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_mev_shield(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_swap_passes() {
        std::env::remove_var("PI_MEV_SHIELD_STRICT_MODE");
        let o = run(
            "function trade() public { swapExactTokensForTokens(amountIn, minOut, path, to, deadline); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn zero_min_out_flagged_strict() {
        std::env::remove_var("PI_MEV_SHIELD_STRICT_MODE");
        let o = run("function trade() public { swap(); amountOutMin = 0; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_MEV_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["trade"]);
    }

    #[test]
    #[serial]
    fn zero_min_out_warn_when_not_strict() {
        std::env::set_var("PI_MEV_SHIELD_STRICT_MODE", "false");
        let o = run("function trade() public { exactInput(); minAmountOut = 0; }");
        // is_secure coerced back to true in non-strict mode
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_MEV_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["trade"]);
        std::env::remove_var("PI_MEV_SHIELD_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn hardcoded_swap_zero_arg_flagged() {
        std::env::remove_var("PI_MEV_SHIELD_STRICT_MODE");
        let o = run(
            "function go() external { swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp); }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["go"]);
    }
}
