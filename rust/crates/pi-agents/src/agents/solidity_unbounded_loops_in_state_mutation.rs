//! Port of `pi_micro_agents/pi_solidity_unbounded_loops_in_state_mutation.py`.
//!
//! Audits Solidity contracts for state-variable mutations occurring inside
//! unbounded `for`/`while` loops (gas-exhaustion / DoS). Behaviour is a
//! line-for-line mirror of the Python original.
//!
//! Parity note: the Python assignment-detection regex uses a negative
//! lookahead `(?!=)`, which the Rust `regex` crate does not support. That
//! single pattern is therefore reimplemented as a faithful backtracking
//! matcher (`find_assignment_idents`) that reproduces CPython's `re` semantics
//! exactly, including non-greedy backtracking that can *extend* a match when
//! the lookahead fails on a `==`. All other patterns use the `regex` crate.

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

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_UNBOUNDED_LOOPS_STATE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// --- Regexes (everything except the lookahead-bearing assignment regex). ---

// re.finditer(r'\bfunction\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{', code)
static FUNC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bfunction\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{").unwrap());

// re.findall(r'(for\s*\(.*?;(.*?);.*?\)|while\s*\(.*?\))', body)
static LOOP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(for\s*\(.*?;(.*?);.*?\)|while\s*\(.*?\))").unwrap());

// re.sub(r'\b(i|j|k|index|iter)\b', '', condition)
static LOOPVAR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(i|j|k|index|iter)\b").unwrap());

// re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', cond_clean)
static IDENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b").unwrap());

pub fn audit_unbounded_loops(input: &Input) -> Output {
    let code = &input.solidity_code;
    let code_chars: Vec<char> = code.chars().collect();
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions using balanced brace matching to support nested blocks.
    // func_blocks holds (name, _args, body). args is captured but only `name`
    // and `body` are used downstream, exactly like the Python.
    let mut func_blocks: Vec<(String, String)> = Vec::new();
    for caps in FUNC_RE.captures_iter(code) {
        let name = caps.get(1).unwrap().as_str().to_string();
        let _args = caps.get(2).unwrap().as_str().to_string();
        // match.end() is a byte offset into `code`; convert to a char index so
        // the brace-matching loop indexes `code_chars` like Python indexes the
        // str by character.
        let end_byte = caps.get(0).unwrap().end();
        let start_idx = byte_to_char_index(code, end_byte);
        let mut brace_count: i64 = 1;
        let mut idx = start_idx;
        while idx < code_chars.len() && brace_count > 0 {
            let ch = code_chars[idx];
            if ch == '{' {
                brace_count += 1;
            } else if ch == '}' {
                brace_count -= 1;
            }
            idx += 1;
        }
        if brace_count == 0 {
            // body = code[start_idx:idx-1]
            let body: String = code_chars[start_idx..idx - 1].iter().collect();
            func_blocks.push((name, body));
        }
    }

    for (name, body) in &func_blocks {
        // Find loops (for or while). 2 capture groups -> (loop_str, condition).
        for caps in LOOP_RE.captures_iter(body) {
            let loop_str = caps.get(1).unwrap().as_str();
            // group(2) corresponds to the inner `(.*?)`; for `while` it never
            // participates -> Python yields '' (empty string).
            let condition = caps.get(2).map(|m| m.as_str()).unwrap_or("");

            // cond_clean = re.sub(...) if condition else ''
            let cond_clean: String = if !condition.is_empty() {
                LOOPVAR_RE.replace_all(condition, "").into_owned()
            } else {
                String::new()
            };
            let vars_in_cond: Vec<String> = IDENT_RE
                .find_iter(&cond_clean)
                .map(|m| m.as_str().to_string())
                .collect();

            let mut is_unbounded = false;
            if condition.is_empty() {
                is_unbounded = true;
            } else if !vars_in_cond.is_empty() {
                for var in &vars_in_cond {
                    if var == "length" {
                        is_unbounded = true;
                        break;
                    }
                    // validation_pattern = r'\b(require|assert|if)\b[\s\S]*?\b' + re.escape(var) + r'\b'
                    let validation_pattern = format!(
                        r"\b(require|assert|if)\b[\s\S]*?\b{}\b",
                        regex::escape(var)
                    );
                    let val_re = Regex::new(&validation_pattern).unwrap();
                    if !val_re.is_match(body) {
                        is_unbounded = true;
                        break;
                    }
                }
            }

            if is_unbounded {
                let mut has_mutation = false;
                // loop_body_match = re.search(re.escape(loop_str) + r'\s*\{([\s\S]*?)\}', body)
                let loop_body_pattern = format!(r"{}\s*\{{([\s\S]*?)\}}", regex::escape(loop_str));
                let loop_body_re = Regex::new(&loop_body_pattern).unwrap();
                if let Some(lbcaps) = loop_body_re.captures(body) {
                    let loop_body = lbcaps.get(1).unwrap().as_str();
                    // assignments = re.findall(<lookahead regex>, loop_body)
                    let assignments = find_assignment_idents(loop_body);
                    let non_loop_assignments: Vec<&String> = assignments
                        .iter()
                        .filter(|asg| {
                            let s = asg.trim();
                            !matches!(s, "i" | "j" | "k" | "index" | "iter")
                        })
                        .collect();

                    if !non_loop_assignments.is_empty()
                        || loop_body.contains("sstore")
                        || loop_body.contains(".push")
                    {
                        has_mutation = true;
                    }
                }

                if has_mutation {
                    vulnerable_funcs.push(name.clone());
                    flagged_findings.push(format!(
                        "Function '{name}' modifies state variables or performs storage modifications inside an unbounded loop. \
If the loop boundary grows large, the transaction can exceed the block gas limit, causing a persistent Denial of Service (DoS)."
                    ));
                    break;
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_UNBOUNDED_LOOPS_STATE".to_string();
        } else {
            status = "WARN_UNBOUNDED_LOOPS_STATE".to_string();
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

/// Convert a byte offset into `s` to a character index.
fn byte_to_char_index(s: &str, byte_off: usize) -> usize {
    s[..byte_off].chars().count()
}

// --- Faithful port of the lookahead assignment regex via backtracking. ---
//
// Python pattern:
//   \b([a-zA-Z0-9_]+)(?:\s*\[.*?\]|\s*\.[a-zA-Z0-9_]+)*\s*[-+*\/]?=(?!=)
// re.findall returns group(1) for each leftmost, non-overlapping match.

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Python `re` `\s` for str patterns (exact set, CPython 3.11).
fn is_pyspace(c: char) -> bool {
    matches!(
        c,
        '\u{09}'
            | '\u{0a}'
            | '\u{0b}'
            | '\u{0c}'
            | '\u{0d}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{1f}'
            | '\u{20}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// Python `.` without DOTALL: any char except '\n' (0x0a).
fn is_dot(c: char) -> bool {
    c != '\n'
}

/// `\b` word-boundary test at char index `p` over slice `cs`.
fn at_word_boundary(cs: &[char], p: usize) -> bool {
    let before = if p == 0 { false } else { is_word(cs[p - 1]) };
    let after = if p < cs.len() { is_word(cs[p]) } else { false };
    before != after
}

/// Try to match the repeated group `(?:\s*\[.*?\]|\s*\.[a-zA-Z0-9_]+)*` then
/// `\s*[-+*\/]?=(?!=)` starting at char index `pos`. Greedy `*` with full
/// backtracking. Returns the end index (char index just past `=`) of the first
/// overall match found by Python's leftmost/greedy engine, or None.
fn match_tail(cs: &[char], pos: usize) -> Option<usize> {
    // Greedy `*`: try to take one more group iteration first, then fall back to
    // matching the trailing `\s*[-+*/]?=(?!=)` at the current position.
    // Each alternation iteration is itself tried greedily/with backtracking.

    // Try: one more iteration of the group (Alt A then Alt B), recursing.
    // Alt A: \s*\[.*?\]   (.*? is non-greedy)
    if let Some(after_a) = match_alt_a(cs, pos) {
        // after_a may be multiple possible end points because .*? is non-greedy;
        // match_alt_a yields the *shortest* first, but the surrounding `*` and
        // tail may require a longer one. We must try all expansions in order.
        // To keep ordering identical to Python, match_alt_a returns an iterator
        // of candidate ends in non-greedy (shortest-first) order.
        for end_a in after_a {
            if let Some(r) = match_tail(cs, end_a) {
                return Some(r);
            }
        }
    }
    // Alt B: \s*\.[a-zA-Z0-9_]+   (note: tried only if Alt A produced no full
    // match; Python's alternation prefers Alt A, but if the whole rest fails it
    // backtracks into Alt B for this iteration).
    if let Some(end_b) = match_alt_b(cs, pos) {
        if let Some(r) = match_tail(cs, end_b) {
            return Some(r);
        }
    }
    // Zero more iterations: match the trailing piece here.
    match_assign_tail(cs, pos)
}

/// Alt A: `\s*\[.*?\]`. `.*?` is non-greedy, so candidate end positions are
/// returned shortest-first. Returns the list of all valid end indices (after
/// the closing `]`) in non-greedy order, or None if it cannot match at all.
fn match_alt_a(cs: &[char], pos: usize) -> Option<Vec<usize>> {
    let mut p = pos;
    while p < cs.len() && is_pyspace(cs[p]) {
        p += 1;
    }
    if p >= cs.len() || cs[p] != '[' {
        return None;
    }
    p += 1; // consume '['
    // .*? then ] : non-greedy. Collect all positions where a ']' can close,
    // shortest first. `.` excludes '\n'.
    let mut ends = Vec::new();
    let mut q = p;
    loop {
        // try to close here (zero or more dot chars already consumed up to q)
        if q < cs.len() && cs[q] == ']' {
            ends.push(q + 1);
        }
        // extend .*? by one dot char (if possible)
        if q < cs.len() && is_dot(cs[q]) {
            q += 1;
        } else {
            break;
        }
    }
    if ends.is_empty() {
        None
    } else {
        Some(ends)
    }
}

/// Alt B: `\s*\.[a-zA-Z0-9_]+`. `+` is greedy. Returns single end index.
fn match_alt_b(cs: &[char], pos: usize) -> Option<usize> {
    let mut p = pos;
    while p < cs.len() && is_pyspace(cs[p]) {
        p += 1;
    }
    if p >= cs.len() || cs[p] != '.' {
        return None;
    }
    p += 1; // consume '.'
    let start_word = p;
    while p < cs.len() && is_word(cs[p]) {
        p += 1;
    }
    if p == start_word {
        // needs at least one word char
        None
    } else {
        Some(p)
    }
}

/// Match `\s*[-+*\/]?=(?!=)` starting at `pos`. Returns end index past `=`.
fn match_assign_tail(cs: &[char], pos: usize) -> Option<usize> {
    let mut p = pos;
    while p < cs.len() && is_pyspace(cs[p]) {
        p += 1;
    }
    // [-+*/]? optional single char
    if p < cs.len() && matches!(cs[p], '-' | '+' | '*' | '/') {
        p += 1;
    }
    // =
    if p >= cs.len() || cs[p] != '=' {
        return None;
    }
    p += 1; // consume '='
            // (?!=): next char must not be '='
    if p < cs.len() && cs[p] == '=' {
        return None;
    }
    Some(p)
}

/// Reproduce `re.findall(<assignment regex>, s)` -> Vec of group(1) strings.
fn find_assignment_idents(s: &str) -> Vec<String> {
    let cs: Vec<char> = s.chars().collect();
    let n = cs.len();
    let mut out = Vec::new();
    let mut start = 0usize;
    while start <= n {
        // Attempt a match anchored at `start`.
        let mut matched_end: Option<(usize, usize)> = None; // (group1_end, full_end)
        if at_word_boundary(&cs, start) && start < n && is_word(cs[start]) {
            // ([a-zA-Z0-9_]+) greedy: consume max word chars, then backtrack.
            let mut word_end = start;
            while word_end < n && is_word(cs[word_end]) {
                word_end += 1;
            }
            // group(1) is [start, g1_end); the `+` allows backtracking down to 1 char.
            let mut g1_end = word_end;
            while g1_end > start {
                if let Some(full_end) = match_tail(&cs, g1_end) {
                    matched_end = Some((g1_end, full_end));
                    break;
                }
                g1_end -= 1;
            }
        }
        match matched_end {
            Some((g1_end, full_end)) => {
                let captured: String = cs[start..g1_end].iter().collect();
                out.push(captured);
                // Non-overlapping: resume at full_end; if zero-width, advance 1.
                start = if full_end > start { full_end } else { start + 1 };
            }
            None => {
                start += 1;
            }
        }
    }
    out
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_unbounded_loops(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_unbounded_loops(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_contract_passes() {
        let code = "contract C { function noop() public { uint x = 1; } }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn unbounded_length_loop_with_mutation_flagged() {
        let code = "function withdrawAll(address[] memory users) public {\n\
            for (uint i = 0; i < users.length; i++) {\n\
                balances[users[i]] = 0;\n\
            }\n\
        }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_UNBOUNDED_LOOPS_STATE");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["withdrawAll"]);
    }

    #[test]
    #[serial]
    fn while_loop_no_condition_with_push_flagged() {
        let code = "function drain() public {\n\
            while (true) {\n\
                queue.push(1);\n\
            }\n\
        }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["drain"]);
    }

    #[test]
    #[serial]
    fn non_strict_env_warns_and_secures() {
        std::env::set_var("PI_UNBOUNDED_LOOPS_STATE_STRICT_MODE", "false");
        let code = "function drain() public {\n\
            while (true) {\n\
                total += 1;\n\
            }\n\
        }";
        let o = run(code);
        std::env::remove_var("PI_UNBOUNDED_LOOPS_STATE_STRICT_MODE");
        assert_eq!(o.status, "WARN_UNBOUNDED_LOOPS_STATE");
        assert!(o.is_secure); // coerced back to true
        assert_eq!(o.risk_score, 75.0);
    }
}
