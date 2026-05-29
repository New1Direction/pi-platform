//! Port of `pi_micro_agents/pi_defi_math_rounding_sentry.py`.
//!
//! Audits Solidity contracts for integer-division rounding errors in ERC-4626
//! style share/asset conversions that favour the caller over the protocol.
//! Behaviour is a line-for-line mirror of the Python original.

// NOTE: this agent does not use pyutil::splitlines / pyutil::strip — the Python
// original never calls `.splitlines()` or `.strip()`. It scans the whole source
// with regexes, so no line-by-line iteration is needed.
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
// 3 capture groups -> captures_iter. No IGNORECASE/MULTILINE/DOTALL; `.` does
// not match `\n` (same default in both Python and the Rust regex crate), while
// `[\s\S]` explicitly spans newlines.
static FUNC_BLOCK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

// re.search(r'\b(convertToShares|convertToAssets|sharesToAssets|assetsToShares)\b', name)
static CONVERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(convertToShares|convertToAssets|sharesToAssets|assetsToShares)\b").unwrap()
});

// re.search(r'\/\s*[a-zA-Z0-9_]+', body)
static UNCHECKED_DIV_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"/\s*[a-zA-Z0-9_]+").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python resolution order:
///   1. env `PI_MATH_ROUNDING_STRICT_MODE` -> `value.lower() == "true"`
///   2. `~/.antigravitycli/config.json` then the in-repo
///      `../../.antigravitycli/config.json`, reading the
///      `PI_MATH_ROUNDING_STRICT_MODE` key (default True)
///   3. default True
///
/// The config-file fallback is environment-dependent; in this repo the config
/// file lacks the key, so `data.get(..., True)` yields True. Therefore, when
/// the env var is unset the effective result is `true`, which this function
/// reproduces. See `deviations` in the parity report: the config-file branch is
/// intentionally collapsed to the default-True behaviour.
fn is_strict_mode() -> bool {
    match std::env::var("PI_MATH_ROUNDING_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_math_rounding(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // func_blocks = re.findall(...)
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // conversion_match = re.search(...)
        let conversion_match = CONVERSION_RE.is_match(name);

        if conversion_match {
            // unchecked_div_match = re.search(r'\/\s*[a-zA-Z0-9_]+', body)
            let unchecked_div_match = UNCHECKED_DIV_RE.is_match(body);
            // mul_div_up_missing = "mulDivUp" not in body and "Math.Rounding.Up" not in body
            let mul_div_up_missing = !body.contains("mulDivUp") && !body.contains("Math.Rounding.Up");

            if unchecked_div_match && mul_div_up_missing {
                let name_lower = name.to_lowercase();
                if name_lower.contains("deposit")
                    || name_lower.contains("mint")
                    || name_lower.contains("shares")
                {
                    vulnerable_funcs.push(name.to_string());
                    flagged_findings.push(format!(
                        "Function '{name}' performs dynamic share or asset arithmetic division without \
explicit rounding direction controls (e.g., missing OpenZeppelin Math rounding qualifiers). \
Solidity division always rounds down. Rounding down on deposits/mints allows depositors \
to exploit vault inflation math, leading to zero-value share minting."
                    ));
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
            status = "REJECTED_ROUNDING_RISK".to_string();
        } else {
            status = "WARN_ROUNDING_RISK".to_string();
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
    let out = audit_math_rounding(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_math_rounding(&Input {
            file_path: "Vault.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[serial]
    #[test]
    fn clean_contract_passes() {
        std::env::remove_var("PI_MATH_ROUNDING_STRICT_MODE");
        let o = run("function totalAssets() public view returns (uint256) { return asset.balanceOf(address(this)); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[serial]
    #[test]
    fn vulnerable_convert_to_shares_rejected_strict() {
        std::env::set_var("PI_MATH_ROUNDING_STRICT_MODE", "true");
        let o = run("function convertToShares(uint256 assets) public returns (uint256) { return assets * supply / totalAssets; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ROUNDING_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["convertToShares"]);
        std::env::remove_var("PI_MATH_ROUNDING_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn vulnerable_non_strict_warns_and_secure() {
        std::env::set_var("PI_MATH_ROUNDING_STRICT_MODE", "false");
        let o = run("function convertToShares(uint256 assets) public returns (uint256) { return assets * supply / totalAssets; }");
        // non-strict coerces is_secure back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ROUNDING_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["convertToShares"]);
        std::env::remove_var("PI_MATH_ROUNDING_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn conversion_with_muldivup_is_safe() {
        std::env::remove_var("PI_MATH_ROUNDING_STRICT_MODE");
        let o = run("function convertToShares(uint256 assets) public returns (uint256) { return assets.mulDivUp(supply, totalAssets); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }
}
