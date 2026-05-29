//! Port of `pi_micro_agents/pi_design_an_interface_validator.py`.
//!
//! Checks proposed class/interface definitions for missing type-safety
//! annotations and documentation blocks. Behaviour is a line-for-line mirror of
//! the Python original.

use crate::pyutil;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub interface_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub validation_warnings: Vec<String>,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_DESIGN_INTERFACE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn validate_interface(input: &Input) -> Output {
    let content = &input.interface_content;
    let mut warnings: Vec<String> = Vec::new();

    // Check if Python or TS functions lack return types or parameter types
    let lines = pyutil::splitlines(content);
    for (i, raw_line) in lines.iter().enumerate() {
        let idx = i + 1;
        let clean = pyutil::strip(raw_line);
        if clean.starts_with("def ") && !clean.contains("->") {
            warnings.push(format!(
                "Line {idx}: Python function definition is missing return type hint."
            ));
        }
        if clean.contains("interface ") || clean.contains("class ") {
            // Check for docstrings or JSDoc
            // Python: if idx > 1 and "*/" not in lines[idx-2] and '"""' not in lines[idx-2]
            if idx > 1 {
                let prev = lines[idx - 2];
                if !prev.contains("*/") && !prev.contains("\"\"\"") {
                    warnings.push(format!(
                        "Line {idx}: Interface or class lacks descriptive documentation block."
                    ));
                }
            }
        }
    }

    let mut is_secure = warnings.is_empty();

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_DESIGN_INTERFACE".to_string();
        } else {
            status = "WARN_DESIGN_INTERFACE".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        validation_warnings: warnings,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = validate_interface(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        validate_interface(&Input {
            interface_content: content.into(),
        })
    }

    #[test]
    fn clean_input_passes() {
        // A function with a return type and no class/interface lines.
        let o = run("def foo() -> int:\n    return 1");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.validation_warnings.is_empty());
    }

    #[test]
    fn missing_return_type_flagged() {
        let o = run("def foo():\n    return 1");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DESIGN_INTERFACE");
        assert_eq!(
            o.validation_warnings,
            vec!["Line 1: Python function definition is missing return type hint."]
        );
    }

    #[test]
    fn class_without_doc_flagged() {
        // class on line 2; previous line (line 1) has no docstring/JSDoc terminator.
        let o = run("x = 1\nclass Foo:");
        assert!(!o.is_secure);
        assert_eq!(
            o.validation_warnings,
            vec!["Line 2: Interface or class lacks descriptive documentation block."]
        );
    }

    #[test]
    fn class_with_docblock_passes() {
        // Previous line ends a JSDoc block, so the class is not flagged.
        let o = run("*/\nclass Foo:");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
