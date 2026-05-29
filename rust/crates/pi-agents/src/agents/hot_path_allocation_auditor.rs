//! Port of `pi_micro_agents/pi_hot_path_allocation_auditor.py`.
//!
//! Specialized high-performance diagnostics micro-agent: scans C#/Python source
//! for allocation anti-patterns on performance-critical "hot path" lines.
//! Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub source_code: String,
    #[serde(default)]
    pub hot_path_lines: Vec<i64>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_hotspots: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_PERF_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Anti-pattern regexes, in the same insertion order as the Python dict so the
// per-line scan checks them in an identical sequence.
//
// Each tuple is (compiled-pattern, description).
static PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"\.ToLower\(\)").unwrap(),
            "ToLower() allocates a new string copy. Consider OrdinalIgnoreCase comparisons.",
        ),
        (
            Regex::new(r"\.Substring\(").unwrap(),
            "Substring() allocates a new string object. Use Span<T> or Memory<T> slices.",
        ),
        (
            Regex::new(r"new\s+Dictionary<").unwrap(),
            "Per-call instantiation of dictionary within path. Hoist or cache as FrozenDictionary.",
        ),
        (
            Regex::new(r"Regex\(").unwrap(),
            "Non-compiled Regex instantiation in path. Hoist to static or use [GeneratedRegex].",
        ),
    ]
});

pub fn audit_hot_path(input: &Input) -> Output {
    let code = &input.source_code;
    // hot_lines = set(input_envelope.hot_path_lines)
    let hot_lines: std::collections::HashSet<i64> = input.hot_path_lines.iter().copied().collect();
    let mut hotspots: Vec<String> = Vec::new();

    // for idx, line in enumerate(code.splitlines(), 1):
    for (i, line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = (i + 1) as i64;
        // Only check if lines list is empty (check all) or if this line is in
        // the hot lines list.
        if hot_lines.is_empty() || hot_lines.contains(&idx) {
            for (pattern, desc) in PATTERNS.iter() {
                if pattern.is_match(line) {
                    hotspots.push(format!(
                        "L{idx}: allocation-risk: {desc} -> '{}'",
                        pyutil::strip(line)
                    ));
                }
            }
        }
    }

    let mut is_secure = hotspots.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        let strict = is_strict_mode();
        if strict {
            status = "REJECTED_PERF_RISK".to_string();
        } else {
            status = "WARN_PERF_RISK".to_string();
        }
        if !strict {
            is_secure = true;
        }
    }

    Output {
        is_secure,
        flagged_hotspots: hotspots,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_hot_path(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str, hot: Vec<i64>) -> Output {
        audit_hot_path(&Input {
            file_path: "f.cs".into(),
            source_code: source.into(),
            hot_path_lines: hot,
        })
    }

    #[test]
    fn clean_code_passes() {
        let o = run("var x = ComputeSpan(input);", vec![]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_hotspots.is_empty());
    }

    #[test]
    fn tolower_flagged_strict() {
        let o = run("  var y = s.ToLower();  ", vec![]);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_PERF_RISK");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.flagged_hotspots.len(), 1);
        assert_eq!(
            o.flagged_hotspots[0],
            "L1: allocation-risk: ToLower() allocates a new string copy. Consider OrdinalIgnoreCase comparisons. -> 'var y = s.ToLower();'"
        );
    }

    #[test]
    fn hot_lines_filter() {
        // Anti-pattern is on line 2 but only line 1 is a hot line -> no flag.
        let o = run("clean = 1;\nvar z = a.Substring(0);", vec![1]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn multiple_patterns_order() {
        // A single line that matches ToLower then Substring -> both flagged in
        // dict insertion order, ToLower first.
        let o = run("var v = s.ToLower().Substring(0);", vec![]);
        assert_eq!(o.flagged_hotspots.len(), 2);
        assert!(o.flagged_hotspots[0].contains("ToLower()"));
        assert!(o.flagged_hotspots[1].contains("Substring()"));
    }
}
