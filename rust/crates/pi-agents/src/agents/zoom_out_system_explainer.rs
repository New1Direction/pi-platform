//! Port of `pi_micro_agents/pi_zoom_out_system_explainer.py`.
//!
//! Deterministic micro-agent that extracts file imports to explain
//! architectural dependencies. Flags files with too many external package
//! dependencies. Behaviour is a line-for-line mirror of the Python original.

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
    pub imports: Vec<String>,
    pub architecture_summary: String,
    pub status: String,
}

/// Mirrors `is_strict_mode()`:
///   - if the env var is set, strict iff its lowercase value == "true"
///   - if unset, strict (True)
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZOOM_OUT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Python: re.match(r"^\s*(?:import\s+([\w\.-]+)|from\s+([\w\.-]+)\s+import)", line)
// re.match anchors at the start of the string; the leading `^` is redundant but
// preserved for fidelity. Two capture groups, no lookaround/backrefs -> portable.
static IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:import\s+([\w\.-]+)|from\s+([\w\.-]+)\s+import)").unwrap()
});

pub fn explain_system(input: &Input) -> Output {
    let code = &input.code_content;
    let mut imports: Vec<String> = Vec::new();

    // Regex to find imports
    let lines = pyutil::splitlines(code);
    for line in lines {
        // re.match only matches at the beginning of the string. Find at most one
        // match starting at position 0.
        if let Some(caps) = IMPORT_RE.captures(line) {
            // Ensure the match begins at the start (re.match semantics). With the
            // `^` anchor this is always true, but guard explicitly for fidelity.
            if caps.get(0).map(|m| m.start()).unwrap_or(1) == 0 {
                // pkg = match.group(1) or match.group(2)
                // Python: group(1) is None if it didn't participate; `or` falls
                // through to group(2). An empty string is falsy in Python too,
                // but [\w\.-]+ requires at least one char so groups are never "".
                let g1 = caps.get(1).map(|m| m.as_str());
                let g2 = caps.get(2).map(|m| m.as_str());
                let pkg: Option<&str> = match g1 {
                    Some(s) if !s.is_empty() => Some(s),
                    _ => match g2 {
                        Some(s) if !s.is_empty() => Some(s),
                        _ => None,
                    },
                };
                if let Some(pkg) = pkg {
                    // if pkg and pkg not in imports
                    if !imports.iter().any(|p| p == pkg) {
                        imports.push(pkg.to_string());
                    }
                }
            }
        }
    }

    // is_secure = len(imports) < 15
    let mut is_secure = imports.len() < 15;

    // summary = f"File imports {len} packages. Key dependencies: {', '.join(imports[:5])}"
    let head: Vec<&str> = imports.iter().take(5).map(|s| s.as_str()).collect();
    let summary = format!(
        "File imports {} packages. Key dependencies: {}",
        imports.len(),
        head.join(", ")
    );

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_ZOOM_OUT".to_string();
        } else {
            status = "WARN_ZOOM_OUT".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        imports,
        architecture_summary: summary,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = explain_system(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        explain_system(&Input {
            file_path: "f.py".into(),
            code_content: code.into(),
        })
    }

    #[test]
    fn clean_imports_pass() {
        let o = run("import os\nimport re\nfrom typing import List");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.imports, vec!["os", "re", "typing"]);
        assert_eq!(
            o.architecture_summary,
            "File imports 3 packages. Key dependencies: os, re, typing"
        );
    }

    #[test]
    fn dedup_and_indent_preserved() {
        // Leading whitespace allowed by \s*; duplicates deduped in order.
        let o = run("    import os\nimport os\nfrom os import path");
        assert_eq!(o.imports, vec!["os"]);
        assert!(o.is_secure);
    }

    #[test]
    fn too_many_imports_rejected_in_strict() {
        let mut lines = String::new();
        for i in 0..15 {
            lines.push_str(&format!("import pkg{}\n", i));
        }
        let o = run(&lines);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZOOM_OUT");
        assert_eq!(o.imports.len(), 15);
    }

    #[test]
    fn empty_code_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.imports.len(), 0);
        assert_eq!(
            o.architecture_summary,
            "File imports 0 packages. Key dependencies: "
        );
    }
}
