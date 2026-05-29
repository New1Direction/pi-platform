//! Port of `pi_micro_agents/pi_tdd_test_file_verifier.py`.
//!
//! Deterministic micro-agent that checks if changesets include both
//! implementation and test files. Behaviour is a line-for-line mirror of the
//! Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub modified_files: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_files: Vec<String>,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict (true) unless the env var
/// `PI_TDD_FILE_STRICT_MODE` is set to a value that is not (case-insensitively)
/// "true". If the env var is unset, the default is strict.
fn is_strict_mode() -> bool {
    match std::env::var("PI_TDD_FILE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `os.path.split(f)[1]` (posixpath): the tail is everything after the
/// last `/`. The Python loop only reaches this when `f` contains a `/`, but we
/// keep the general behaviour anyway (rfind + slice after the separator).
fn base_name(f: &str) -> &str {
    match f.rfind('/') {
        Some(i) => &f[i + 1..],
        None => f,
    }
}

/// Mirrors Python `str.replace(old, new)` (replaces ALL non-overlapping
/// occurrences). Used to faithfully reproduce the chained `.replace(...)` calls
/// including the `.ts` substring matching inside `.tsx`.
fn py_replace(s: &str, old: &str, new: &str) -> String {
    s.replace(old, new)
}

pub fn verify_test_files(input: &Input) -> Output {
    let files = &input.modified_files;
    let mut missing_tests: Vec<String> = Vec::new();

    // Identify production code files (e.g. .py or .ts files that are not tests themselves)
    for f in files {
        // Skip test files, config files, metadata, or documentation
        if f.to_lowercase().contains("test")
            || f.ends_with(".md")
            || f.ends_with(".json")
            || f.ends_with(".yml")
            || !f.contains('/')
        {
            continue;
        }

        // Formulate expected test file name
        let base = base_name(f);
        let expected_test_py = format!("test_{base}");
        // chained: .replace(".ts", ".test.ts").replace(".tsx", ".test.tsx")
        let expected_test_ts = py_replace(
            &py_replace(base, ".ts", ".test.ts"),
            ".tsx",
            ".test.tsx",
        );

        // base_name.split(".")[0] -> everything before the first '.'
        let base_stem = match base.find('.') {
            Some(i) => &base[..i],
            None => base,
        };

        let mut has_test = false;
        for tf in files {
            if tf.to_lowercase().contains("test")
                && (tf.contains(&expected_test_py)
                    || tf.contains(&expected_test_ts)
                    || tf.contains(base_stem))
            {
                has_test = true;
                break;
            }
        }

        if !has_test {
            missing_tests.push(f.clone());
        }
    }

    let mut is_secure = missing_tests.is_empty();

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_TDD_FILE".to_string();
        } else {
            status = "WARN_TDD_FILE".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_files: missing_tests,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = verify_test_files(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(files: &[&str]) -> Output {
        verify_test_files(&Input {
            modified_files: files.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[test]
    fn impl_with_matching_test_passes() {
        // base_name "foo.py" -> stem "foo" is contained in "src/test_foo.py"
        let o = run(&["src/foo.py", "tests/test_foo.py"]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_files.is_empty());
    }

    #[test]
    fn impl_without_test_rejected() {
        let o = run(&["src/foo.py"]);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TDD_FILE");
        assert_eq!(o.vulnerable_files, vec!["src/foo.py".to_string()]);
    }

    #[test]
    fn skips_non_code_and_pathless() {
        // README.md skipped (.md), config.json skipped (.json), bare "x" skipped (no '/'),
        // anything with "test" in path skipped.
        let o = run(&["README.md", "config.json", "x", "tests/util_test.py"]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_files.is_empty());
    }
}
