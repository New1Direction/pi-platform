//! Port of `pi_micro_agents/pi_token_tax_detector.py`.
//!
//! Specialized Web3 micro-agent that audits ERC-20 transfer mechanisms for
//! hidden taxes, burn fees, and standards compliance. Behaviour is a
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

// ---------------------------------------------------------------------------
// Regexes (compiled once). None of these use lookaround or backreferences, so
// they map cleanly onto the Rust `regex` crate.
// ---------------------------------------------------------------------------

// Python: r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\('
static FUNC_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(").unwrap()
});

// Python: re.sub(r'//.*', '', func_body)   (`.` excludes newline by default)
static LINE_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());

// Python: re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
static BLOCK_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

// Python: re.compile(r'\b(fee|tax|burn|basisPoints|rate|pct)\b')
static TAX_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(fee|tax|burn|basisPoints|rate|pct)\b").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// 1. If env `PI_TOKENTAX_STRICT_MODE` is set, return `value.to_lowercase() == "true"`.
/// 2. Otherwise the Python original consults a JSON config file; if found and
///    parseable, returns `bool(data.get("PI_TOKENTAX_STRICT_MODE", True))`.
/// 3. Otherwise default to `true`.
///
/// The config-file fallback is replicated for faithfulness, but note that the
/// `~`/`__file__` expansion semantics differ slightly across host environments
/// (see deviations in the parity report). The parity harness exercises the env
/// var path (branch 1) and the default (branch 3, no config present).
fn is_strict_mode() -> bool {
    if let Ok(v) = std::env::var("PI_TOKENTAX_STRICT_MODE") {
        return v.to_lowercase() == "true";
    }

    // Mirror Python's config-file lookup: first ~/.antigravitycli/config.json,
    // then a path relative to the module source. We only attempt the home path
    // here (the module-relative path has no stable analogue in the Rust build).
    if let Some(home) = std::env::var_os("HOME") {
        let mut path = std::path::PathBuf::from(home);
        path.push(".antigravitycli");
        path.push("config.json");
        if path.exists() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                    match val.get("PI_TOKENTAX_STRICT_MODE") {
                        Some(serde_json::Value::Bool(b)) => return *b,
                        Some(serde_json::Value::Null) => return false,
                        Some(other) => {
                            // Python bool() truthiness for non-bool JSON values.
                            return json_truthy(other);
                        }
                        None => return true,
                    }
                }
            }
        }
    }
    true
}

/// Approximates Python `bool(x)` truthiness for JSON scalar/containers.
fn json_truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

/// Mirror of `extract_solidity_functions`. Returns `(func_name, func_body, start_line)`.
///
/// All string indexing follows Python semantics: regex match offsets and
/// `str.find` are based on Unicode code-point (char) positions, and slicing is
/// by char index. We therefore convert to a `Vec<char>` and operate on char
/// indices to stay byte-identical with Python for non-ASCII input.
fn extract_solidity_functions(solidity_code: &str) -> Vec<(String, String, usize)> {
    let mut functions: Vec<(String, String, usize)> = Vec::new();
    let chars: Vec<char> = solidity_code.chars().collect();
    let code_len = chars.len();

    // Map byte offset (from regex, which works on the &str) -> char index.
    let byte_to_char: std::collections::HashMap<usize, usize> = solidity_code
        .char_indices()
        .enumerate()
        .map(|(ci, (bi, _))| (bi, ci))
        .collect();

    for m in FUNC_PATTERN.captures_iter(solidity_code) {
        let keyword = m.get(1).unwrap().as_str();
        let name = m.get(2).unwrap().as_str();
        let func_name = match keyword {
            "function" => name.to_string(),
            "constructor" => "constructor".to_string(),
            "fallback" => "fallback".to_string(),
            _ => "receive".to_string(),
        };

        // match.start() in char index.
        let start_byte = m.get(0).unwrap().start();
        let start_idx = *byte_to_char.get(&start_byte).unwrap();

        // start_line = solidity_code[:start_idx].count('\n') + 1
        let start_line = chars[..start_idx].iter().filter(|&&c| c == '\n').count() + 1;

        // semicolon_idx = solidity_code.find(';', start_idx)
        let semicolon_idx = find_char(&chars, ';', start_idx);
        // brace_idx = solidity_code.find('{', start_idx)
        let brace_idx = find_char(&chars, '{', start_idx);

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
            let ch = chars[curr_idx];
            if ch == '{' {
                brace_count += 1;
            } else if ch == '}' {
                brace_count -= 1;
            }
            curr_idx += 1;
        }

        if brace_count == 0 {
            let func_body: String = chars[start_idx..curr_idx].iter().collect();
            functions.push((func_name, func_body, start_line));
        }
    }

    functions
}

/// Python `str.find(ch, start)` over char indices; returns None for -1.
fn find_char(chars: &[char], target: char, start: usize) -> Option<usize> {
    chars
        .iter()
        .enumerate()
        .skip(start)
        .find(|&(_, &c)| c == target)
        .map(|(i, _)| i)
}

pub fn audit(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let functions = extract_solidity_functions(code);

    for (func_name, func_body, start_line) in &functions {
        // Clean comments.
        let cleaned_body = LINE_COMMENT.replace_all(func_body, "");
        let cleaned_body = BLOCK_COMMENT.replace_all(&cleaned_body, "").into_owned();

        if func_name == "transfer" || func_name == "transferFrom" {
            // Mode 1: Token Tax Audit.
            if TAX_PATTERN.is_match(&cleaned_body)
                && (cleaned_body.contains('-')
                    || cleaned_body.contains('*')
                    || cleaned_body.contains('/'))
            {
                vulnerable_funcs.push(func_name.clone());
                flagged_findings.push(format!(
                    "Function '{func_name}' on Line {start_line} contains operations using fee/tax variables \
which indicates a potential 'fee-on-transfer' or dynamic transfer tax mechanism."
                ));
            }

            // Check for blacklist/whitelist exclusion checks.
            let lower = cleaned_body.to_lowercase();
            if lower.contains("exclude") || lower.contains("blacklist") || lower.contains("whitelist")
            {
                if !vulnerable_funcs.contains(func_name) {
                    vulnerable_funcs.push(func_name.clone());
                }
                flagged_findings.push(format!(
                    "Function '{func_name}' on Line {start_line} contains exclusion or whitelist checks, \
which could act as backdoors to bypass taxes for privileged addresses."
                ));
            }

            // Mode 2: ERC-20 Interface Compliance.
            if func_body.contains("returns") && !func_body.contains("bool") {
                flagged_findings.push(format!(
                    "Compliance warning: Function '{func_name}' on Line {start_line} does not explicitly return a boolean value \
as required by the standard ERC-20 specification."
                ));
            }

            // Standard transfer functions must emit Transfer event.
            if !cleaned_body.contains("emit Transfer(") {
                flagged_findings.push(format!(
                    "Compliance warning: Function '{func_name}' on Line {start_line} does not emit the required 'Transfer' event."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_TOKENTAX_VULNERABILITY".to_string();
        } else {
            status = "WARN_TOKENTAX_VULNERABILITY".to_string();
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
    let out = audit(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit(&Input {
            file_path: "Token.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_transfer_passes() {
        std::env::remove_var("PI_TOKENTAX_STRICT_MODE");
        std::env::set_var("PI_TOKENTAX_STRICT_MODE", "true");
        let code = "function transfer(address to, uint256 amount) public returns (bool) {\n    balances[msg.sender] -= amount;\n    balances[to] += amount;\n    emit Transfer(msg.sender, to, amount);\n    return true;\n}";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        std::env::remove_var("PI_TOKENTAX_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn fee_transfer_flagged_strict() {
        std::env::set_var("PI_TOKENTAX_STRICT_MODE", "true");
        let code = "function transfer(address to, uint256 amount) public returns (bool) {\n    uint256 fee = amount / 100;\n    balances[to] += amount - fee;\n    emit Transfer(msg.sender, to, amount);\n    return true;\n}";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TOKENTAX_VULNERABILITY");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["transfer"]);
        std::env::remove_var("PI_TOKENTAX_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn vulnerable_warn_when_not_strict() {
        std::env::set_var("PI_TOKENTAX_STRICT_MODE", "false");
        let code = "function transferFrom(address f, address t, uint256 amount) returns (bool) {\n    uint256 tax = amount * 5 / 100;\n    emit Transfer(f, t, amount);\n}";
        let o = run(code);
        // WARN path coerces is_secure back to true.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_TOKENTAX_VULNERABILITY");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["transferFrom"]);
        std::env::remove_var("PI_TOKENTAX_STRICT_MODE");
    }
}
