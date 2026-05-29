//! Port of `pi_micro_agents/pi_dead_code_pruner.py`.
//!
//! Deterministic micro-agent that scans files for dead code: unused imports
//! and unreachable statements after `return`/`raise`. Behaviour is a
//! line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub code_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub unused_tokens: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_DEAD_CODE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// `import_pattern = r"^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+[a-zA-Z0-9_\.]+\s+import\s+([a-zA-Z0-9_]+))"`
// Used with `re.match` (anchored at start). Lines from splitlines() contain no
// newline, so the default (non-multiline) `^` anchor matches the line start
// exactly like Python's `re.match`.
static IMPORT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+[a-zA-Z0-9_\.]+\s+import\s+([a-zA-Z0-9_]+))")
        .unwrap()
});

/// Count of leading whitespace characters, mirroring Python
/// `len(line) - len(line.lstrip())` where `len` counts Unicode code points.
fn leading_ws_count(line: &str) -> usize {
    let total = line.chars().count();
    let stripped = line.trim_start();
    let stripped_len = stripped.chars().count();
    total - stripped_len
}

pub fn prune_dead_code(input: &Input) -> Output {
    let code = &input.code_content;
    let mut unused_tokens: Vec<String> = Vec::new();

    let lines = pyutil::splitlines(code);

    // 1. Check for unused imports
    for (i, line) in lines.iter().enumerate() {
        let idx = i + 1; // enumerate(lines, start=1)
        if let Some(caps) = IMPORT_PATTERN.captures(line) {
            // imported_name = match.group(1) or match.group(2)
            let imported_name: &str = match caps.get(1) {
                Some(m) if !m.as_str().is_empty() => m.as_str(),
                _ => match caps.get(2) {
                    Some(m) => m.as_str(),
                    None => "",
                },
            };
            if !imported_name.is_empty() {
                // Build word-boundary search regex: r"\b" + re.escape(name) + r"\b"
                let pat = format!(r"\b{}\b", regex::escape(imported_name));
                let name_re = Regex::new(&pat).unwrap();
                let mut occurrences = 0i64;
                for (l_i, l) in lines.iter().enumerate() {
                    let l_idx = l_i + 1; // enumerate(lines, start=1)
                    if l_idx == idx {
                        continue;
                    }
                    if name_re.is_match(l) {
                        occurrences += 1;
                    }
                }
                if occurrences == 0 {
                    unused_tokens.push(format!("Line {idx}: Unused import '{imported_name}'"));
                }
            }
        }
    }

    // 2. Check for unreachable code after return/raise
    let n_lines = lines.len();
    for (i, line) in lines.iter().enumerate() {
        let idx = i + 1; // enumerate(lines, start=1)
        let stripped = pyutil::strip(line);
        if stripped.starts_with("return") || stripped.starts_with("raise") {
            // if idx < len(lines):  next_line = lines[idx]  (0-based -> the line after idx)
            if idx < n_lines {
                let next_line = lines[idx];
                let next_stripped = pyutil::strip(next_line);
                if !next_stripped.is_empty()
                    && !next_stripped.starts_with('#')
                    && !next_stripped.starts_with("def ")
                    && !next_stripped.starts_with("class ")
                    && !next_stripped.starts_with("elif")
                    && !next_stripped.starts_with("else")
                    && !next_stripped.starts_with("except")
                    && !next_stripped.starts_with("finally")
                {
                    let current_indent = leading_ws_count(line);
                    let next_indent = leading_ws_count(next_line);
                    if next_indent >= current_indent {
                        unused_tokens
                            .push(format!("Line {}: Unreachable statement after return/raise", idx + 1));
                    }
                }
            }
        }
    }

    let mut is_secure = unused_tokens.is_empty();
    let risk_score = if !is_secure { 50.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_DEAD_CODE".to_string();
        } else {
            status = "WARN_DEAD_CODE".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        unused_tokens,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = prune_dead_code(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        prune_dead_code(&Input {
            file_path: "f.py".into(),
            code_content: code.into(),
        })
    }

    #[test]
    fn clean_code_passes() {
        let o = run("import os\nprint(os.getcwd())");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.unused_tokens.is_empty());
    }

    #[test]
    fn unused_import_flagged() {
        let o = run("import os\nprint('hello')");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DEAD_CODE");
        assert_eq!(o.risk_score, 50.0);
        assert_eq!(o.unused_tokens, vec!["Line 1: Unused import 'os'"]);
    }

    #[test]
    fn unreachable_after_return_flagged() {
        let o = run("def f():\n    return 1\n    x = 2");
        assert!(!o.is_secure);
        assert!(o
            .unused_tokens
            .iter()
            .any(|t| t == "Line 3: Unreachable statement after return/raise"));
    }
}
