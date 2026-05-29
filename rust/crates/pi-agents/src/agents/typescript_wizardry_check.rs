//! Port of `pi_micro_agents/pi_typescript_wizardry_check.py`.
//!
//! Deterministic micro-agent that audits TypeScript source for unsafe shortcuts
//! such as `: any`, `as any`, `<any>`, and the `@ts-ignore` / `@ts-nocheck`
//! type-check suppression comments. Behaviour is a line-for-line mirror of the
//! Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub code_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub unsafe_occurrences: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set, in which case
/// strict iff its (case-insensitive) value equals "true". When unset, strict.
fn is_strict_mode() -> bool {
    match std::env::var("PI_TYPESCRIPT_WIZARDRY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// (pattern, message) pairs, mirroring `any_patterns` in the Python source.
// None of these patterns use lookahead/lookbehind/backreferences, so they are
// directly portable to the Rust `regex` crate.
static PAT_COLON_ANY: Lazy<Regex> = Lazy::new(|| Regex::new(r":\s*any\b").unwrap());
static PAT_AS_ANY: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bas\s+any\b").unwrap());
static PAT_GENERIC_ANY: Lazy<Regex> = Lazy::new(|| Regex::new(r"<\s*any\s*>").unwrap());
static PAT_TS_IGNORE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//\s*@ts-ignore").unwrap());
static PAT_TS_NOCHECK: Lazy<Regex> = Lazy::new(|| Regex::new(r"//\s*@ts-nocheck").unwrap());

fn any_patterns() -> [(&'static Regex, &'static str); 5] {
    [
        (&PAT_COLON_ANY, "Explicit 'any' type annotation found"),
        (&PAT_AS_ANY, "Type assertion 'as any' found"),
        (&PAT_GENERIC_ANY, "Generic/cast '<any>' found"),
        (
            &PAT_TS_IGNORE,
            "TypeScript disable comment '@ts-ignore' found",
        ),
        (
            &PAT_TS_NOCHECK,
            "TypeScript disable comment '@ts-nocheck' found",
        ),
    ]
}

pub fn check_typescript(input: &Input) -> Output {
    let code = &input.code_content;
    let mut unsafe_occurrences: Vec<String> = Vec::new();

    let patterns = any_patterns();

    for (i, line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1; // enumerate(lines, start=1)

        // Skip comments to avoid false positives (except the explicit disable comments).
        let stripped = pyutil::strip(line);
        if stripped.starts_with("//")
            && !(stripped.contains("@ts-ignore") || stripped.contains("@ts-nocheck"))
        {
            continue;
        }

        for (pat, msg) in patterns.iter() {
            if pat.is_match(line) {
                unsafe_occurrences.push(format!("Line {idx}: {msg}"));
            }
        }
    }

    let mut is_secure = unsafe_occurrences.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_TYPESCRIPT_WIZARDRY".to_string();
        } else {
            status = "WARN_TYPESCRIPT_WIZARDRY".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        unsafe_occurrences,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_typescript(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        check_typescript(&Input {
            code_content: code.into(),
        })
    }

    #[test]
    fn clean_code_passes() {
        let o = run("const x: number = 1;\nfunction f(a: string): void {}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.unsafe_occurrences.is_empty());
    }

    #[test]
    fn explicit_any_flagged() {
        let o = run("let v: any = getThing();");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TYPESCRIPT_WIZARDRY");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(
            o.unsafe_occurrences,
            vec!["Line 1: Explicit 'any' type annotation found"]
        );
    }

    #[test]
    fn plain_comment_with_any_skipped() {
        // A regular comment line is skipped, so the ": any" inside is ignored.
        let o = run("// this returns : any value");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn ts_ignore_comment_flagged() {
        // The disable comment is NOT skipped and matches its pattern.
        let o = run("// @ts-ignore");
        assert!(!o.is_secure);
        assert_eq!(
            o.unsafe_occurrences,
            vec!["Line 1: TypeScript disable comment '@ts-ignore' found"]
        );
    }
}
