//! Port of `pi_micro_agents/pi_solidity_price_feed_sequencer_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity code to ensure Chainlink
//! Price Feeds validate the L2 Sequencer liveness. Behaviour is a line-for-line
//! mirror of the Python original.
//!
//! Parity note on the function-block scan: the Python source uses a regex with a
//! lookahead boundary
//! `function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)`.
//! The Rust `regex` crate does not support lookahead, so the body capture is
//! reproduced with manual scanning: each function header is located with the
//! lookahead-free prefix regex, and the body extends from just after the opening
//! brace up to (but not including) the first `\n\s*function` occurrence, or end
//! of string. This was verified to be byte-identical to `re.findall` across a
//! suite of edge cases (adjacent functions, CRLF, nested braces, inline
//! `function` keywords, multiline args).

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

// Lookahead-free prefix of the original pattern: matches a function header up to
// and including the opening brace, capturing the name (group 1) and args
// (group 2). `.` does not match `\n` (Python had no re.DOTALL on this part), and
// `[^{]*` cannot cross a `{`, exactly like the original.
static FUNC_PREFIX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

// Boundary used by the original lookahead `(?=\n\s*function|\Z)`. The `\Z`
// alternative is handled in code (no boundary match -> body runs to end).
static FUNC_BOUNDARY: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n\s*function").unwrap());

// `re.search(r'sequencer', body, re.IGNORECASE)`.
static SEQUENCER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)sequencer").unwrap());

/// Reproduces `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)', code)`
/// returning `(name, args, body)` tuples in match order.
fn find_func_blocks(code: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    let n = code.len();
    let mut pos = 0usize;
    while pos <= n {
        // Search the prefix starting at `pos`.
        let m = match FUNC_PREFIX.captures(&code[pos..]) {
            Some(c) => c,
            None => break,
        };
        let whole = m.get(0).unwrap();
        let name = m.get(1).map(|g| g.as_str()).unwrap_or("").to_string();
        let args = m.get(2).map(|g| g.as_str()).unwrap_or("").to_string();
        // Absolute byte offset where the body begins (just past the `{`).
        let body_start = pos + whole.end();

        let (body, mut new_pos) = match FUNC_BOUNDARY.find(&code[body_start..]) {
            Some(b) => {
                let body_end = body_start + b.start();
                (code[body_start..body_end].to_string(), body_end)
            }
            None => (code[body_start..].to_string(), n + 1),
        };

        out.push((name, args, body));

        // Safety guard mirroring the prototype; prevents an infinite loop if the
        // boundary lands at or before the current position.
        if new_pos <= pos {
            new_pos = pos + 1;
        }
        pos = new_pos;
    }
    out
}

/// Mirrors `is_strict_mode()`.
///
/// PARITY DEVIATION: the Python original, when the env var is unset, consults
/// `~/.antigravitycli/config.json` and then a repo-relative config file,
/// defaulting to `True` (and `data.get("PI_SEQUENCER_LIVENESS_STRICT_MODE",
/// True)` defaults to `True` because that key is absent from the repo config).
/// In this repository both fallbacks resolve to `True`, so this env-only
/// implementation is byte-identical in the deployed environment. The config-file
/// lookup is intentionally NOT replicated (matches the reference jwt_none port).
fn is_strict_mode() -> bool {
    match std::env::var("PI_SEQUENCER_LIVENESS_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_price_feed_sequencer(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let func_blocks = find_func_blocks(code);

    for (name, _args, body) in &func_blocks {
        // `if "latestRoundData" in body or "feed" in body.lower():`
        if body.contains("latestRoundData") || body.to_lowercase().contains("feed") {
            // `if not re.search(r'sequencer', body, re.IGNORECASE):`
            if !SEQUENCER_RE.is_match(body) {
                vulnerable_funcs.push(name.clone());
                flagged_findings.push(format!(
                    "Function '{name}' queries an oracle feed but does not perform a Sequencer Uptime Feed liveness check. \
On Layer-2 networks, this could lead to using stale/manipulated oracle prices during sequencer outages."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SEQUENCER_LIVENESS".to_string();
        } else {
            status = "WARN_SEQUENCER_LIVENESS".to_string();
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
    let out = audit_price_feed_sequencer(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_price_feed_sequencer(&Input {
            file_path: "Feed.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_with_sequencer_check_passes() {
        let code = "function getPrice() public {\n    sequencer.check();\n    feed.latestRoundData();\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn missing_sequencer_check_flagged() {
        let code = "function getPrice() public {\n    int p = feed.latestRoundData();\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SEQUENCER_LIVENESS");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["getPrice"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    fn two_functions_only_vulnerable_flagged() {
        let code = "function getPrice(uint x) public {\n    int p = feed.latestRoundData();\n    return p;\n}\nfunction check() public {\n    require(sequencer.isUp());\n}";
        let o = run(code);
        // First reads feed without sequencer -> flagged. Second reads feed
        // (in word? no "feed"/"latestRoundData") -> not flagged.
        assert_eq!(o.vulnerable_functions, vec!["getPrice"]);
        assert!(!o.is_secure);
    }

    #[test]
    fn no_functions_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }
}
