//! Port of `pi_micro_agents/pi_solidity_price_feed_fallback_sentry.py`.
//!
//! Audits Solidity contracts for oracle price-feed fallback setups: every
//! function whose body reads from `latestRoundData` / `getPrice` must also
//! implement a secondary/fallback pricing source (TWAP, backup oracle, Pyth,
//! try/catch, ...). Behaviour is a line-for-line mirror of the Python original.
//!
//! The Python source extracts function blocks with this regex:
//!
//! ```text
//! function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)
//! ```
//!
//! That pattern uses a lookahead `(?=...)` and `\Z`, neither of which the Rust
//! `regex` crate supports, and its overall match depends on the engine's lazy
//! quantifier / backtracking behaviour (e.g. a header without a `{` lets
//! `[^{]*` swallow the following `function` keyword). Rather than approximate
//! it, `find_function_blocks` below is a faithful hand-written backtracking
//! matcher that reproduces CPython's `re.findall` output exactly (verified
//! against the original under the parity harness).

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

/// Mirrors `is_strict_mode()`.
///
/// Python first consults the env var `PI_ORACLE_FALLBACK_STRICT_MODE`; if set,
/// it returns `env_val.lower() == "true"`. Otherwise it tries to read a config
/// file (`~/.antigravitycli/config.json`, falling back to a repo-relative
/// path) and returns `bool(data.get("PI_ORACLE_FALLBACK_STRICT_MODE", True))`,
/// defaulting to `True` whenever the file is missing/unreadable or the key is
/// absent. We replicate the env-var branch exactly and default to `true` for
/// the file branch (the config files in this repo do not define the key, so the
/// Python default of `True` applies). See `deviations` in the parity report:
/// if a config file *did* set the key to `false`, this port would diverge.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ORACLE_FALLBACK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// --- Faithful re-implementation of the function-block regex --------------- //

/// `\s` in Python's `re` (Unicode mode): ASCII whitespace plus a few Unicode
/// whitespace code points. We use Rust's Unicode `char::is_whitespace`, which
/// matches CPython's set for all practical Solidity inputs.
fn is_re_space(c: char) -> bool {
    c.is_whitespace()
}

/// `[a-zA-Z0-9_]` (ASCII word char, no Unicode).
fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `(?=\n\s*function|\Z)` evaluated with the cursor at char index `pos`.
fn lookahead_ok(chars: &[char], pos: usize) -> bool {
    let n = chars.len();
    if pos == n {
        // \Z : end of string.
        return true;
    }
    // \n\s*function
    if chars[pos] == '\n' {
        let mut i = pos + 1;
        while i < n && is_re_space(chars[i]) {
            i += 1;
        }
        if starts_with(chars, i, "function") {
            return true;
        }
    }
    false
}

fn starts_with(chars: &[char], pos: usize, lit: &str) -> bool {
    let litc: Vec<char> = lit.chars().collect();
    if pos + litc.len() > chars.len() {
        return false;
    }
    for (k, &lc) in litc.iter().enumerate() {
        if chars[pos + k] != lc {
            return false;
        }
    }
    true
}

/// `([\s\S]*?)(?=\n\s*function|\Z)` starting at char index `b`.
/// Returns `(end_index, body_string)` or `None`.
fn try_body(chars: &[char], b: usize) -> Option<(usize, String)> {
    let n = chars.len();
    let mut t = b;
    loop {
        if lookahead_ok(chars, t) {
            let body: String = chars[b..t].iter().collect();
            return Some((t, body));
        }
        if t < n {
            t += 1;
        } else {
            return None;
        }
    }
}

/// Matches `\)[^{]*\{` then the body, with `[^{]*` greedy and backtracking.
/// `j` points at the char where `\)` is expected; `args` is already captured.
fn try_after_args(chars: &[char], j: usize, name: &str, args: &str) -> Option<MatchOut> {
    let n = chars.len();
    // \)
    if j >= n || chars[j] != ')' {
        return None;
    }
    let k = j + 1;
    // [^{]* greedy: advance to first '{' (or end).
    let brace_start = k;
    let mut g = k;
    while g < n && chars[g] != '{' {
        g += 1;
    }
    // Backtrack [^{]* from greedy `g` down to `brace_start`, looking for '{'.
    let mut m = g as isize;
    while m >= brace_start as isize {
        let mi = m as usize;
        if mi < n && chars[mi] == '{' {
            if let Some((end, body)) = try_body(chars, mi + 1) {
                return Some(MatchOut {
                    end,
                    name: name.to_string(),
                    args: args.to_string(),
                    body,
                });
            }
        }
        m -= 1;
    }
    None
}

struct MatchOut {
    end: usize,
    name: String,
    args: String,
    body: String,
}

/// Attempts the full pattern starting at char index `p`. Returns the match
/// (with its end index) or `None`.
fn match_at(chars: &[char], p: usize) -> Option<MatchOut> {
    let n = chars.len();
    // literal 'function'
    if !starts_with(chars, p, "function") {
        return None;
    }
    let mut i = p + "function".chars().count();
    // \s+
    let mut cnt = 0usize;
    while i < n && is_re_space(chars[i]) {
        i += 1;
        cnt += 1;
    }
    if cnt == 0 {
        return None;
    }
    // ([a-zA-Z0-9_]+) greedy, group 1
    let name_start = i;
    while i < n && is_word_char(chars[i]) {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let name: String = chars[name_start..i].iter().collect();
    // \s*
    while i < n && is_re_space(chars[i]) {
        i += 1;
    }
    // \(
    if i >= n || chars[i] != '(' {
        return None;
    }
    i += 1;
    // (.*?) group 2, lazy; '.' = any char except '\n' (no DOTALL).
    let arg_start = i;
    let mut j = i;
    loop {
        let args: String = chars[arg_start..j].iter().collect();
        if let Some(out) = try_after_args(chars, j, &name, &args) {
            return Some(out);
        }
        // Expand group 2 by one char if it's not a newline.
        if j < n && chars[j] != '\n' {
            j += 1;
        } else {
            return None;
        }
    }
}

/// Mirrors `re.findall(pattern, code)` for the function-block pattern: returns
/// `(name, args, body)` tuples for all non-overlapping matches, scanning left
/// to right and resuming at the end of each match.
fn find_function_blocks(code: &str) -> Vec<(String, String, String)> {
    let chars: Vec<char> = code.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut p = 0usize;
    while p <= n {
        if let Some(m) = match_at(&chars, p) {
            out.push((m.name, m.args, m.body));
            if m.end == p {
                p += 1; // avoid infinite loop on a zero-width match
            } else {
                p = m.end;
            }
        } else {
            p += 1;
        }
    }
    out
}

// ------------------------------------------------------------------------- //

pub fn audit_price_feed_fallback(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let func_blocks = find_function_blocks(code);

    for (name, _args, body) in &func_blocks {
        // Check if latestRoundData is called.
        if body.contains("latestRoundData") || body.contains("getPrice") {
            // Heuristic: any fallback / secondary / TWAP / backup / Pyth /
            // try-catch reference disqualifies the finding.
            let body_lower = body.to_lowercase();
            let mut has_fallback = false;
            if ["fallback", "twap", "secondary", "catch", "backup", "pyth"]
                .iter()
                .any(|x| body_lower.contains(x))
            {
                has_fallback = true;
            }

            if !has_fallback {
                vulnerable_funcs.push(name.clone());
                flagged_findings.push(format!(
                    "Function '{name}' reads from an external price feed oracle using 'latestRoundData' or 'getPrice' \
but does not implement a secondary/fallback pricing source (like TWAP or a backup oracle) in case \
the primary oracle suffers from an outage, lag, or zero-price freeze."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ORACLE_FALLBACK".to_string();
        } else {
            status = "WARN_ORACLE_FALLBACK".to_string();
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
    let out = audit_price_feed_fallback(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // Build an Input without touching process-global env (these tests rely on
    // the default strict=true that holds when the env var is unset and no
    // config file defines the key).
    fn mk(code: &str) -> Input {
        Input {
            file_path: "c.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        }
    }

    // Exercise the vulnerability *scan* independently of the strict-mode env so
    // the assertions are deterministic under parallel test execution.
    fn scan(code: &str) -> Vec<String> {
        audit_price_feed_fallback(&mk(code)).vulnerable_functions
    }

    #[test]
    #[serial]
    fn vulnerable_oracle_read_flagged() {
        let code = "function getQuote() public { return oracle.latestRoundData(); }";
        assert_eq!(scan(code), vec!["getQuote"]);
    }

    #[test]
    #[serial]
    fn fallback_present_passes() {
        let code =
            "function getQuote() public {\n    uint p = oracle.latestRoundData();\n    if (bad) p = getTwap();\n}";
        assert!(scan(code).is_empty());
    }

    #[test]
    #[serial]
    fn no_oracle_call_passes() {
        assert!(scan("function helper(uint a) public { return a + 1; }").is_empty());
    }

    #[test]
    #[serial]
    fn header_without_brace_swallows_next_function() {
        // Mirrors the regex backtracking: `noBody` has no `{`, so `[^{]*`
        // consumes the following `function last` and the brace of `last`.
        let code = "function noBody() external returns (uint)\n    function last() public { return getPrice(); }\n}";
        let blocks = find_function_blocks(code);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, "noBody");
        assert_eq!(blocks[0].2, " return getPrice(); }\n}");
    }

    // Serializes the env-mutating status tests; process env is global state.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    #[serial]
    fn strict_mode_rejects() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("PI_ORACLE_FALLBACK_STRICT_MODE", "true");
        let o = audit_price_feed_fallback(&mk("function g() public { getPrice(); }"));
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ORACLE_FALLBACK");
        assert_eq!(o.risk_score, 70.0);
        std::env::remove_var("PI_ORACLE_FALLBACK_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn warn_mode_coerces_secure() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("PI_ORACLE_FALLBACK_STRICT_MODE", "false");
        let o = audit_price_feed_fallback(&mk("function g() public { getPrice(); }"));
        assert!(o.is_secure); // coerced back to true
        assert_eq!(o.status, "WARN_ORACLE_FALLBACK");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_functions, vec!["g"]); // still listed
        std::env::remove_var("PI_ORACLE_FALLBACK_STRICT_MODE");
    }
}
