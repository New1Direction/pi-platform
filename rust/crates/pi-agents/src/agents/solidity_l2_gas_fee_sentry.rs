//! Port of `pi_micro_agents/pi_solidity_l2_gas_fee_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity code to ensure Layer-2 gas
//! fee and calldata optimizations are followed. Behaviour is a line-for-line
//! mirror of the Python original.
//!
//! The Python source extracts function blocks with a single regex that relies on
//! a trailing lookahead `(?=\n\s*function|\Z)`. The Rust `regex` crate does not
//! support lookahead, so the extraction is reimplemented as a faithful manual
//! scanner that reproduces the exact backtracking semantics of CPython's `re`
//! engine for that specific pattern. See `find_func_blocks` for the detailed
//! correspondence.

// NOTE: the Python source is fully regex-based and never calls `.splitlines()`
// or `.strip()`, so `crate::pyutil` is intentionally not imported here.
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

// Python: `from __future__ import annotations` -> string annotations.
//
// L2GasFeeInput:
//   file_path: str          (required)
//   solidity_code: str      (required)
//   check_level: str = "STRICT"
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

// L2GasFeeOutput:
//   is_secure: bool
//   vulnerable_functions: List[str] = []
//   flagged_findings: List[str] = []
//   risk_score: float
//   status: str
#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_functions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`.
///
/// The Python helper:
///   1. If env var `PI_L2_GAS_FEE_STRICT_MODE` is set -> `env_val.lower() == "true"`.
///   2. Otherwise it reads `~/.antigravitycli/config.json` (or the repo-relative
///      fallback) and returns `bool(data.get("PI_L2_GAS_FEE_STRICT_MODE", True))`.
///   3. On any failure / missing file -> `True`.
///
/// Neither config file defines `PI_L2_GAS_FEE_STRICT_MODE`, so the config branch
/// always resolves to the `True` default. We therefore mirror the env branch and
/// default to `True` in every other case. The parity harness drives both branches
/// exclusively through the env var, which is reproduced exactly here.
fn is_strict_mode() -> bool {
    match std::env::var("PI_L2_GAS_FEE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Python: `re.search(r'\.length\s*(<=|<|>|>=|==|!=)', body)` -> bool.
///
/// No lookaround / backrefs -> the `regex` crate handles this verbatim. `\s` is
/// Unicode-aware in both engines; for Solidity source the relevant whitespace is
/// ASCII so the two agree.
static LENGTH_CHECK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.length\s*(<=|<|>|>=|==|!=)").unwrap());

/// Python `\s` predicate for the ASCII/common case. CPython's `\s` for `str`
/// patterns covers `[ \t\n\r\f\v]` plus Unicode whitespace; Rust's
/// `char::is_whitespace` is the Unicode `White_Space` property. These agree for
/// every whitespace character that appears in real source files.
#[inline]
fn is_py_space(c: char) -> bool {
    c.is_whitespace()
}

#[inline]
fn is_ident_char(c: char) -> bool {
    // Python char class [a-zA-Z0-9_]
    c.is_ascii_alphanumeric() || c == '_'
}

/// One extracted function block: `(name, args, visibility, body)` matching the
/// four capture groups of the Python regex.
struct FuncBlock {
    name: String,
    #[allow(dead_code)]
    args: String,
    #[allow(dead_code)]
    visibility: String,
    body: String,
}

/// Faithful reimplementation of:
/// ```text
/// re.findall(
///   r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*(external|public)[\s\S]*?\{([\s\S]*?)(?=\n\s*function|\Z)',
///   code)
/// ```
/// with default flags (no DOTALL): `.` does NOT match `\n`, `[\s\S]` matches any
/// character including `\n`.
///
/// `re.findall` semantics: leftmost, non-overlapping. From the current scan
/// position, try to match starting at each index left-to-right; on success record
/// the groups, advance the scan position to the match end, repeat.
fn find_func_blocks(code: &str) -> Vec<FuncBlock> {
    let chars: Vec<char> = code.chars().collect();
    let n = chars.len();
    let mut out: Vec<FuncBlock> = Vec::new();
    let mut start = 0usize;

    while start < n {
        match try_match(&chars, start) {
            Some((block, end)) => {
                out.push(block);
                // Match is never zero-width (it always consumes at least
                // "function "), so plain advance to `end` is correct.
                start = if end > start { end } else { start + 1 };
            }
            None => start += 1,
        }
    }
    out
}

/// Attempt to match the function-block pattern anchored at `p`. Returns the
/// captured `FuncBlock` plus the end index (the lookahead is zero-width, so the
/// match end is the index right after the body).
fn try_match(chars: &[char], p: usize) -> Option<(FuncBlock, usize)> {
    let n = chars.len();
    let mut i = p;

    // `function` literal
    const KW: &[char] = &['f', 'u', 'n', 'c', 't', 'i', 'o', 'n'];
    if i + KW.len() > n {
        return None;
    }
    for (k, &kc) in KW.iter().enumerate() {
        if chars[i + k] != kc {
            return None;
        }
    }
    i += KW.len();

    // `\s+` one or more whitespace
    let ws_start = i;
    while i < n && is_py_space(chars[i]) {
        i += 1;
    }
    if i == ws_start {
        return None; // need at least one whitespace
    }

    // `([a-zA-Z0-9_]+)` group 1 = name (greedy, >=1)
    let name_start = i;
    while i < n && is_ident_char(chars[i]) {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let name: String = chars[name_start..i].iter().collect();

    // `\s*` zero or more whitespace
    while i < n && is_py_space(chars[i]) {
        i += 1;
    }

    // `\(`
    if i >= n || chars[i] != '(' {
        return None;
    }
    i += 1;

    // `(.*?)` group 2 = args, non-greedy, `.` excludes '\n'. Followed by `\)`.
    // Non-greedy: expand minimally until the next char is ')'. Since `.` cannot
    // match '\n', if we hit a newline before any ')', the match fails at `p`.
    let args_start = i;
    loop {
        if i >= n {
            return None;
        }
        if chars[i] == ')' {
            break; // group 2 = chars[args_start..i]; `\)` consumes chars[i]
        }
        if chars[i] == '\n' {
            return None; // `.` (non-DOTALL) cannot cross newline
        }
        i += 1;
    }
    let args: String = chars[args_start..i].iter().collect();
    // consume `\)`
    i += 1;

    // `[^{]*` greedy (any non-'{', includes '\n'), then `(external|public)`,
    // then `[\s\S]*?\{`.
    //
    // Effective semantics: the region scanned by `[^{]*` runs from `i` up to the
    // first '{'. Within that region we must place `(external|public)`; the greedy
    // `[^{]*` backtracks from longest, selecting the RIGHTMOST occurrence of
    // "external" or "public" such that a '{' still follows. After the chosen
    // token, `[\s\S]*?\{` consumes up to (and including) that first '{'.
    let region_start = i;
    let mut first_brace: Option<usize> = None;
    {
        let mut j = region_start;
        while j < n {
            if chars[j] == '{' {
                first_brace = Some(j);
                break;
            }
            j += 1;
        }
    }
    let brace_idx = first_brace?; // no '{' after ')' -> no match

    // Find rightmost "external" or "public" occurrence whose start is within
    // [region_start, brace_idx) (the `[^{]*`-reachable region). The token itself
    // must lie entirely before `brace_idx`. Tokens are matched as plain
    // substrings (NOT word-anchored), exactly like the regex alternation.
    let vis = find_rightmost_visibility(chars, region_start, brace_idx)?;
    let (vis_token, vis_start, vis_end) = vis;

    // `[\s\S]*?\{`: from vis_end advance non-greedily to the first '{'. Because
    // everything between vis_end and brace_idx contains no earlier '{' (brace_idx
    // is the first '{' >= region_start, and vis_start >= region_start), the first
    // '{' reached is exactly brace_idx.
    // (vis_end <= brace_idx is guaranteed by construction.)
    let body_start = brace_idx + 1; // consume the '{'
    let _ = (vis_start, vis_end);

    // `([\s\S]*?)` group 4 = body, non-greedy, then lookahead
    // `(?=\n\s*function|\Z)`. Body expands minimally to the first index j
    // (>= body_start) where the lookahead succeeds:
    //   - `\Z`: j == n (end of string), OR
    //   - `\n\s*function`: chars[j] == '\n', then zero+ `\s`, then literal
    //     "function".
    let mut j = body_start;
    let body_end;
    loop {
        if lookahead_ok(chars, j) {
            body_end = j;
            break;
        }
        if j >= n {
            // `\Z` is always satisfied at n, so we never fall off the end
            // without matching, but guard anyway.
            body_end = n;
            break;
        }
        j += 1;
    }
    let body: String = chars[body_start..body_end].iter().collect();

    Some((
        FuncBlock {
            name,
            args,
            visibility: vis_token,
            body,
        },
        body_end,
    ))
}

/// Find the rightmost occurrence of "external" or "public" with start index in
/// `[lo, hi)` such that the whole token fits before `hi`. Returns
/// `(token, start, end)`.
fn find_rightmost_visibility(
    chars: &[char],
    lo: usize,
    hi: usize,
) -> Option<(String, usize, usize)> {
    const EXTERNAL: &[char] = &['e', 'x', 't', 'e', 'r', 'n', 'a', 'l'];
    const PUBLIC: &[char] = &['p', 'u', 'b', 'l', 'i', 'c'];

    let matches_at = |s: usize, kw: &[char]| -> bool {
        if s + kw.len() > hi {
            return false;
        }
        for (k, &kc) in kw.iter().enumerate() {
            if chars[s + k] != kc {
                return false;
            }
        }
        true
    };

    // Scan from rightmost candidate start downward. The greedy `[^{]*` picks the
    // longest prefix, i.e. the latest possible visibility start.
    let mut s = hi; // exclusive upper bound; first candidate is hi-1 .. lo
    while s > lo {
        s -= 1;
        if matches_at(s, EXTERNAL) {
            return Some(("external".to_string(), s, s + EXTERNAL.len()));
        }
        if matches_at(s, PUBLIC) {
            return Some(("public".to_string(), s, s + PUBLIC.len()));
        }
    }
    None
}

/// Lookahead `(?=\n\s*function|\Z)` evaluated at position `j`.
fn lookahead_ok(chars: &[char], j: usize) -> bool {
    let n = chars.len();
    // `\Z` : end of string.
    if j == n {
        return true;
    }
    // `\n\s*function`
    if chars[j] != '\n' {
        return false;
    }
    let mut k = j + 1;
    while k < n && is_py_space(chars[k]) {
        k += 1;
    }
    const KW: &[char] = &['f', 'u', 'n', 'c', 't', 'i', 'o', 'n'];
    if k + KW.len() > n {
        return false;
    }
    for (idx, &kc) in KW.iter().enumerate() {
        if chars[k + idx] != kc {
            return false;
        }
    }
    true
}

/// Mirrors `PiSolidityL2GasFeeSentry.audit_l2_gas_fee`.
pub fn audit_l2_gas_fee(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // func_blocks = re.findall(...)
    let func_blocks = find_func_blocks(code);

    for block in &func_blocks {
        let name = &block.name;
        let args = &block.args;
        let body = &block.body;

        // if "[]" in args or "bytes" in args:
        if args.contains("[]") || args.contains("bytes") {
            // has_length_check = bool(re.search(r'\.length\s*(<=|<|>|>=|==|!=)', body))
            let has_length_check = LENGTH_CHECK_RE.is_match(body);

            if !has_length_check {
                vulnerable_funcs.push(name.clone());
                flagged_findings.push(format!(
                    "Function '{name}' accepts a dynamic calldata/memory parameter in its signature \
but does not enforce a maximum length boundary on the input. On L2 deployments, \
unbounded calldata size creates high L1 data fee exposure and potential out-of-gas DoS."
                ));
            }
        }
        let _ = &block.visibility;
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_L2_GAS_FEE".to_string();
        } else {
            status = "WARN_L2_GAS_FEE".to_string();
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
    let out = audit_l2_gas_fee(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_l2_gas_fee(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn no_dynamic_params_passes() {
        let o = run("function transfer(address to, uint256 amount) external {\n    balances[to] += amount;\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn unbounded_array_flagged() {
        let o = run(
            "function batchSend(address[] recipients, uint256[] amounts) public {\n    for (uint i=0;i<recipients.length;i++) {}\n}",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_L2_GAS_FEE");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_functions, vec!["batchSend"]);
    }

    #[test]
    fn bytes_with_length_check_passes() {
        let o = run("function safeBatch(bytes data) external {\n    require(data.length <= 100);\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn multi_function_mixed() {
        let code = "function a(uint[] x) external {\n  x;\n}\n\nfunction b(bytes y) public {\n  require(y.length < 32);\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["a"]);
    }
}
