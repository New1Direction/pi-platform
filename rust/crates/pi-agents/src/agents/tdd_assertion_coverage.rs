//! Port of `pi_micro_agents/pi_tdd_assertion_coverage.py`.
//!
//! Deterministic micro-agent that statically parses test source code and flags
//! `test_*` methods that contain no assertion. Behaviour is a line-for-line
//! mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

// `crate::pyutil` is intentionally not imported: the Python agent does not call
// `.splitlines()` or `.strip()`; it operates purely via regex over the raw code.

#[derive(Debug, Deserialize)]
pub struct Input {
    /// Test suite source code.
    pub test_code_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    /// True if assertions are present in all tests.
    pub is_secure: bool,
    /// Test methods missing asserts.
    pub empty_tests: Vec<String>,
    /// Status (PASSED, REJECTED_TDD_ASSERT, WARN_TDD_ASSERT).
    pub status: String,
}

// `re.findall(r"def\s+(test_[a-zA-Z0-9_]+)\s*\([^)]*\)\s*:", code)` — one capture
// group, so we iterate captures and pull group 1.
static METHOD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"def\s+(test_[a-zA-Z0-9_]+)\s*\([^)]*\)\s*:").unwrap());

// `re.split(r"def\s+test_[a-zA-Z0-9_]+\s*\([^)]*\)\s*:", code)` — no capture
// group, so the splitter text is discarded (matches `regex::Regex::split`).
static SPLIT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"def\s+test_[a-zA-Z0-9_]+\s*\([^)]*\)\s*:").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_TDD_ASSERT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn check_assertion_coverage(input: &Input) -> Output {
    let code = &input.test_code_content;
    let mut empty_tests: Vec<String> = Vec::new();

    // Simple static parser for test methods in Python.
    let methods: Vec<String> = METHOD_RE
        .captures_iter(code)
        .map(|c| c[1].to_string())
        .collect();

    // Split code by `def test_`.
    let blocks: Vec<&str> = SPLIT_RE.split(code).collect();

    // The first block is imports, subsequent blocks are the bodies of the test
    // methods.
    if blocks.len() > 1 && methods.len() == blocks.len() - 1 {
        for (idx, method_name) in methods.iter().enumerate() {
            let body = blocks[idx + 1];
            // Just checks if body has any assert keyword.
            if !body.contains("assert")
                && !body.contains("self.assert")
                && !body.contains("expect(")
            {
                empty_tests.push(method_name.clone());
            }
        }
    }

    let mut is_secure = empty_tests.is_empty();

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_TDD_ASSERT".to_string();
        } else {
            status = "WARN_TDD_ASSERT".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        empty_tests,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_assertion_coverage(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        check_assertion_coverage(&Input {
            test_code_content: code.into(),
        })
    }

    #[test]
    fn all_tests_have_assertions_passes() {
        let code = "import unittest\n\
def test_a(self):\n    assert 1 == 1\n\
def test_b(self):\n    self.assertEqual(1, 1)\n";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.empty_tests.is_empty());
    }

    #[test]
    fn missing_assertion_is_rejected_in_strict() {
        // Ensure strict mode regardless of ambient env.
        std::env::remove_var("PI_TDD_ASSERT_STRICT_MODE");
        let code = "def test_a(self):\n    assert 1 == 1\n\
def test_empty(self):\n    x = 1\n";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.empty_tests, vec!["test_empty"]);
        assert_eq!(o.status, "REJECTED_TDD_ASSERT");
    }

    #[test]
    fn no_test_methods_passes() {
        let o = run("x = 1\ny = 2\n");
        assert!(o.is_secure);
        assert!(o.empty_tests.is_empty());
        assert_eq!(o.status, "PASSED");
    }
}
