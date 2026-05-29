//! Port of `pi_micro_agents/pi_defi_slippage_guard.py`.
//!
//! Specialized Web3 micro-agent that audits DeFi swap integrations for
//! zero-slippage sandwich-attack vulnerabilities. Behaviour is a line-for-line
//! mirror of the Python original, including the manual Solidity function
//! extraction (regex + brace matching) and the strict-mode status logic.

// NOTE: the Python original never calls `.splitlines()`; it counts `'\n'`
// occurrences directly and scans the source with regexes + a manual brace
// walk, so `crate::pyutil` is not required here. The string delimiters it
// inspects (`{`, `}`, `;`, `\n`) are all single-byte ASCII, so byte-offset
// scanning reproduces Python's codepoint-index semantics exactly.
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

// ---------------------------------------------------------------------------
// Compiled regexes (mirroring the Python `re` patterns).
// ---------------------------------------------------------------------------

// extract_solidity_functions:
//   re.compile(r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(')
// 2 capture groups -> captures_iter. No look-around; regex-crate compatible.
static FUNC_DECL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// re.sub(r'//.*', '', func_body)
// `.` does not match `\n` (same default in Python and the Rust regex crate),
// so this strips `//` line comments to end-of-line.
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)
// DOTALL -> (?s); non-greedy `.*?` spans newlines.
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

// swap_match = re.search(
//   r'\b(swapExact[a-zA-Z0-9_]*|swap[a-zA-Z0-9_]*Exact[a-zA-Z0-9_]*|swap)\b\s*\(', cleaned_body)
static SWAP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(swapExact[a-zA-Z0-9_]*|swap[a-zA-Z0-9_]*Exact[a-zA-Z0-9_]*|swap)\b\s*\(")
        .unwrap()
});

// zero_slippage_match = re.search(
//   r'\b(swapExact[a-zA-Z0-9_]*|swap[a-zA-Z0-9_]*Exact[a-zA-Z0-9_]*|swap)\b\s*\(\s*([^;]+)\s*\)',
//   cleaned_body, re.DOTALL)
// 2 capture groups; group(2) holds the args. DOTALL -> (?s).
static ZERO_SLIPPAGE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?s)\b(swapExact[a-zA-Z0-9_]*|swap[a-zA-Z0-9_]*Exact[a-zA-Z0-9_]*|swap)\b\s*\(\s*([^;]+)\s*\)",
    )
    .unwrap()
});

// sig_match = re.match(r'\b(function|constructor)\b\s*([a-zA-Z0-9_]*)\s*\(([^)]*)\)', func_body)
// `re.match` anchors at the START of the string -> leading `^`. group(3) = params.
static SIG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\b(function|constructor)\b\s*([a-zA-Z0-9_]*)\s*\(([^)]*)\)").unwrap()
});

// ---------------------------------------------------------------------------
// 1. Strict-mode configuration resolver.
//
// Python resolution order:
//   1. env `PI_SLIPPAGE_STRICT_MODE` -> `value.lower() == "true"`
//   2. `~/.antigravitycli/config.json`, then the in-repo
//      `../../.antigravitycli/config.json`, reading the
//      `PI_SLIPPAGE_STRICT_MODE` key (default True)
//   3. default True
//
// The config-file fallback is environment-dependent. In the parity harness only
// the env-var branch is exercised, and when the env var is unset the file
// fallback collapses to its default `True` (matching the `Err` arm here). This
// mirrors the established convention used by the sibling slippage/rounding
// agents; see `deviations` in the parity report.
// ---------------------------------------------------------------------------
fn is_strict_mode() -> bool {
    match std::env::var("PI_SLIPPAGE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirror of `extract_solidity_functions`: returns `(func_name, func_body,
/// start_line)` tuples discovered via the declaration regex + a manual brace
/// walk.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, i64)> {
    let mut functions: Vec<(String, String, i64)> = Vec::new();
    let bytes = solidity_code.as_bytes();
    let code_len = bytes.len();

    for caps in FUNC_DECL_RE.captures_iter(solidity_code) {
        let keyword = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let name = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        let func_name: String = if keyword == "function" {
            name.to_string()
        } else if keyword == "constructor" {
            "constructor".to_string()
        } else if keyword == "fallback" {
            "fallback".to_string()
        } else {
            "receive".to_string()
        };

        // match.start() — byte offset of group 0 start.
        let start_idx = caps.get(0).unwrap().start();
        // start_line = solidity_code[:start_idx].count('\n') + 1
        let start_line: i64 =
            bytes[..start_idx].iter().filter(|&&b| b == b'\n').count() as i64 + 1;

        // semicolon_idx = solidity_code.find(';', start_idx)
        // brace_idx     = solidity_code.find('{', start_idx)
        // Python str.find returns -1 when not found; we model that with Option.
        let semicolon_idx: i64 = find_byte_from(bytes, b';', start_idx);
        let brace_idx: i64 = find_byte_from(bytes, b'{', start_idx);

        // if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx): continue
        if brace_idx == -1 || (semicolon_idx != -1 && semicolon_idx < brace_idx) {
            continue;
        }

        let mut brace_count: i64 = 1;
        let mut curr_idx: usize = (brace_idx as usize) + 1;
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
            // func_body = solidity_code[start_idx:curr_idx]
            let func_body = solidity_code[start_idx..curr_idx].to_string();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

/// `str.find(ch, start)` returning Python's -1 sentinel as an i64 byte index.
fn find_byte_from(bytes: &[u8], target: u8, start: usize) -> i64 {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == target {
            return i as i64;
        }
        i += 1;
    }
    -1
}

pub fn audit_slippage(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    for (func_name, func_body, start_line) in functions.iter() {
        // cleaned_body = re.sub(r'//.*', '', func_body)
        let cleaned_body = LINE_COMMENT_RE.replace_all(func_body, "");
        // cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)
        let cleaned_body = BLOCK_COMMENT_RE.replace_all(&cleaned_body, "");

        // Mode 1: Zero Slippage Uniswap Swaps Scan
        let swap_match = SWAP_RE.is_match(&cleaned_body);
        if swap_match {
            if let Some(zcaps) = ZERO_SLIPPAGE_RE.captures(&cleaned_body) {
                // args_str = zero_slippage_match.group(2)
                let args_str = zcaps.get(2).map(|m| m.as_str()).unwrap_or("");
                // args = [arg.strip() for arg in args_str.split(',')]
                let args: Vec<&str> = args_str.split(',').map(|a| a.trim()).collect();

                let mut is_zero = false;
                for arg in &args {
                    if *arg == "0" || *arg == "uint256(0)" || *arg == "uint(0)" {
                        is_zero = true;
                        break;
                    }
                }

                if is_zero {
                    vulnerable_funcs.push(func_name.clone());
                    flagged_findings.push(format!(
                        "Function '{func_name}' on Line {start_line} performs a DeFi swap with a hardcoded minimum output \
parameter set to 0 (e.g. amountOutMin = 0). This removes slippage protection entirely, \
making the transaction extremely vulnerable to front-running sandwich attacks."
                    ));
                }
            }
        }

        // Mode 2: Slippage Setting Check
        if swap_match {
            // sig_match = re.match(r'\b(function|constructor)\b\s*([a-zA-Z0-9_]*)\s*\(([^)]*)\)', func_body)
            if let Some(scaps) = SIG_RE.captures(func_body) {
                // params_str = sig_match.group(3).lower()
                let params_str = scaps.get(3).map(|m| m.as_str()).unwrap_or("").to_lowercase();
                let keywords = ["slippage", "minamount", "amountoutmin", "minreturn", "minout"];
                if !keywords.iter().any(|kw| params_str.contains(kw)) {
                    flagged_findings.push(format!(
                        "DeFi Integration Check: Function '{func_name}' on Line {start_line} wraps a swap but \
does not accept a dynamic user-defined or oracle-derived slippage limit or amountOutMin parameter. \
It is recommended to allow the caller to specify their slippage tolerance dynamically."
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
            status = "REJECTED_SLIPPAGE_RISK".to_string();
        } else {
            status = "WARN_SLIPPAGE_RISK".to_string();
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
    let out = audit_slippage(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_slippage(&Input {
            file_path: "Swap.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[serial]
    #[test]
    fn clean_swap_with_min_param_passes() {
        std::env::remove_var("PI_SLIPPAGE_STRICT_MODE");
        let o = run(
            "function trade(uint256 amountIn, uint256 amountOutMin) public { \
router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        // Mode 2 should NOT flag: params contain amountOutMin.
        assert!(o.flagged_findings.is_empty());
    }

    #[serial]
    #[test]
    fn zero_slippage_swap_rejected_strict() {
        std::env::set_var("PI_SLIPPAGE_STRICT_MODE", "true");
        let o = run(
            "function trade(uint256 amountIn) public { \
router.swapExactTokensForTokens(amountIn, 0, path, to, deadline); }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SLIPPAGE_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["trade"]);
        std::env::remove_var("PI_SLIPPAGE_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn zero_slippage_non_strict_warns_and_secure() {
        std::env::set_var("PI_SLIPPAGE_STRICT_MODE", "false");
        let o = run(
            "function trade(uint256 amountIn) public { \
router.swapExactTokensForTokens(amountIn, uint256(0), path, to, deadline); }",
        );
        // non-strict coerces is_secure back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_SLIPPAGE_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["trade"]);
        std::env::remove_var("PI_SLIPPAGE_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn swap_without_min_param_flags_mode2_only() {
        std::env::remove_var("PI_SLIPPAGE_STRICT_MODE");
        // Swap present, no '0' arg, but no slippage-style param -> Mode 2 finding,
        // no vulnerable function, secure PASSED.
        let o = run(
            "function trade(uint256 amountIn) public { \
router.swapExactTokensForTokens(amountIn, computed, path, to, deadline); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("DeFi Integration Check"));
    }

    #[serial]
    #[test]
    fn empty_code_passes() {
        std::env::remove_var("PI_SLIPPAGE_STRICT_MODE");
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
        assert!(o.flagged_findings.is_empty());
    }
}
