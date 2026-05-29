//! Port of `pi_micro_agents/pi_tdd_mocking_sanity_checker.py`.
//!
//! Flags excessively broad mock patches in test suites that lack `spec=` /
//! `autospec=` validation. Behaviour is a line-for-line mirror of the Python
//! original.

use crate::pyutil;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub test_code_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub over_mocked_lines: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict by default; if the env var is set, it is
/// strict only when its (case-insensitively) lowercased value equals "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_TDD_MOCK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn check_mocking_sanity(input: &Input) -> Output {
    let code = &input.test_code_content;
    let mut flagged: Vec<String> = Vec::new();

    for (i, raw_line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        let clean = pyutil::strip(raw_line);
        // Look for broad mocks, e.g. mock.patch.dict or mock.Mock() returning itself broadly
        if clean.contains("mock.patch")
            || clean.contains("MagicMock")
            || clean.contains("Mock(")
            || clean.contains("mock.Mock")
        {
            if !clean.contains("spec=") && !clean.contains("autospec=") {
                flagged.push(format!(
                    "Line {idx}: Broad mock statement lacking spec validation: '{clean}'"
                ));
            }
        }
    }

    // Allow up to 2 unspec'd mocks per file, reject beyond that
    let mut is_secure = flagged.len() < 3;
    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_TDD_MOCK".to_string();
        } else {
            status = "WARN_TDD_MOCK".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        over_mocked_lines: flagged,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_mocking_sanity(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        check_mocking_sanity(&Input {
            test_code_content: code.into(),
        })
    }

    #[test]
    fn clean_code_passes() {
        let o = run("def test_thing():\n    assert add(1, 2) == 3");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.over_mocked_lines.is_empty());
    }

    #[test]
    fn two_unspecd_mocks_still_pass() {
        let o = run("m1 = MagicMock()\nm2 = mock.patch('x')");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.over_mocked_lines.len(), 2);
        assert_eq!(o.risk_score, 0.0);
    }

    #[test]
    fn three_unspecd_mocks_rejected() {
        let o = run("a = MagicMock()\nb = mock.patch('x')\nc = Mock()");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TDD_MOCK");
        assert_eq!(o.over_mocked_lines.len(), 3);
        assert_eq!(o.risk_score, 70.0);
    }

    #[test]
    fn spec_kwarg_is_not_flagged() {
        let o = run("a = MagicMock(spec=Foo)\nb = mock.patch('x', autospec=True)\nc = Mock(spec=Bar)");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.over_mocked_lines.is_empty());
    }
}
