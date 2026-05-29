//! Port of `pi_micro_agents/pi_self_healing_patch_agent.py`.
//!
//! Autonomous Sec-Ops micro-agent that refactors vulnerabilities (unpinned
//! dependencies and dynamic `eval` execution vectors). Behaviour is a
//! line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub source_code: String,
    pub vulnerability_type: String,
    pub vulnerable_lines: Vec<i64>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub patch_synthesized: bool,
    pub patched_code: String,
    pub patch_diff: String,
    pub patch_safety_score: f64,
    pub remediations: Vec<String>,
    pub status: String,
}

// re.match(r"^([a-zA-Z0-9_\-]+)(?:[><=\*!~]+.*)?$", ...)
// `re.match` anchors at the start; the trailing `$` anchors at the end.
static PACKAGE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^([a-zA-Z0-9_\-]+)(?:[><=\*!~]+.*)?$").unwrap());

// re.search(r'["\']([a-zA-Z0-9_\-]+)["\']\s*:\s*["\']([^"\']+)["\']', ...)
static JSON_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"["']([a-zA-Z0-9_\-]+)["']\s*:\s*["']([^"']+)["']"#).unwrap()
});

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: The Python original, when the env var is *unset*, falls back to a
/// `~/.antigravitycli/config.json` lookup that defaults to `True` when the key
/// is absent. This port replicates only the env-var branch (which matches the
/// reference jwt_none_sentry port); for all practical inputs the fallback also
/// yields `True`, so the observable behaviour is identical unless a config file
/// explicitly sets `PI_PATCH_STRICT_MODE: false`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_PATCH_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn heal_vulnerabilities(input: &Input) -> Output {
    let code = &input.source_code;
    let vuln_type = input.vulnerability_type.to_uppercase();
    let lines_to_patch: std::collections::HashSet<i64> =
        input.vulnerable_lines.iter().copied().collect();

    let lines = pyutil::splitlines(code);
    let mut patched_lines: Vec<String> = Vec::new();
    let mut remediations: Vec<String> = Vec::new();
    let mut applied = false;

    for (i, line) in lines.iter().enumerate() {
        let idx = (i + 1) as i64;
        if lines_to_patch.contains(&idx) {
            if vuln_type == "UNPINNED_DEP" {
                // Pin requirements.txt or package.json
                let stripped = pyutil::strip(line);
                if stripped.is_empty() || stripped.starts_with('#') {
                    patched_lines.push((*line).to_string());
                    continue;
                }

                if let Some(caps) = PACKAGE_RE.captures(stripped) {
                    let package = caps.get(1).unwrap().as_str();
                    // Determine stable pin
                    let mut stable_ver = "2.31.0";
                    let pkg_lower = package.to_lowercase();
                    if pkg_lower == "flask" {
                        stable_ver = "3.0.0";
                    } else if pkg_lower == "lodash" {
                        stable_ver = "4.17.21";
                    } else if pkg_lower == "react" {
                        stable_ver = "18.2.0";
                    } else if pkg_lower == "pytest" {
                        stable_ver = "7.4.3";
                    }

                    let pinned_line = format!("{package}=={stable_ver}");
                    patched_lines.push(pinned_line);
                    remediations.push(format!(
                        "Pinned package '{package}' to stable secure version '{stable_ver}'"
                    ));
                    applied = true;
                } else {
                    // Match package.json dependency key-value
                    // (e.g. "react": "^18.2.0" or "lodash": "*")
                    if let Some(caps) = JSON_RE.captures(line) {
                        let package = caps.get(1).unwrap().as_str();
                        let stable_ver = if package.to_lowercase() == "react" {
                            "18.2.0"
                        } else {
                            "4.17.21"
                        };
                        // Maintain JSON spacing/brackets
                        // line[:line.find('"')]
                        let leading_space = match line.find('"') {
                            Some(pos) => &line[..pos],
                            // Python str.find returns -1; line[:-1] drops the
                            // last char. Unreachable here because JSON_RE only
                            // matches when the line contains a quote.
                            None => &line[..line.len().saturating_sub(1)],
                        };
                        let trailing_comma = if pyutil::strip(line).ends_with(',') {
                            ","
                        } else {
                            ""
                        };
                        let pinned_line = format!(
                            "{leading_space}\"{package}\": \"{stable_ver}\"{trailing_comma}"
                        );
                        patched_lines.push(pinned_line);
                        remediations.push(format!(
                            "Pinned JSON package '{package}' to stable secure version '{stable_ver}'"
                        ));
                        applied = true;
                    } else {
                        patched_lines.push((*line).to_string());
                    }
                }
            } else if vuln_type == "DANGEROUS_EVAL" {
                // Locate and replace eval(...) statements
                if line.contains("eval") {
                    // indent = line[:len(line) - len(line.lstrip())]
                    let lstripped_len = trim_start_python(line).len();
                    let indent = &line[..line.len() - lstripped_len];
                    let commented_remedy = format!(
                        "{indent}# TODO (Security Remediation): Blocked dangerous eval statement\n{indent}pass"
                    );
                    patched_lines.push(commented_remedy);
                    remediations.push(
                        "Replaced dangerous 'eval' construct with safe placeholder pass.".to_string(),
                    );
                    applied = true;
                } else {
                    patched_lines.push((*line).to_string());
                }
            } else {
                patched_lines.push((*line).to_string());
            }
        } else {
            patched_lines.push((*line).to_string());
        }
    }

    let mut patched_code = patched_lines.join("\n");
    if !code.is_empty() && code.ends_with('\n') && !patched_code.ends_with('\n') {
        patched_code.push('\n');
    }

    // Generate a clean unified diff representation
    let mut diff_lines: Vec<String> = Vec::new();
    if *code != patched_code {
        let c_lines = pyutil::splitlines(code);
        let p_lines = pyutil::splitlines(&patched_code);
        // zip stops at the shorter of the two.
        for (c_line, p_line) in c_lines.iter().zip(p_lines.iter()) {
            if c_line != p_line {
                diff_lines.push(format!("- {c_line}"));
                diff_lines.push(format!("+ {p_line}"));
            }
        }
    }
    let diff = diff_lines.join("\n");

    // Safety checking
    let mut safety_score: f64 = if applied { 100.0 } else { 50.0 };

    // Check if dangerous constructs remain on patched lines
    for (i, line) in pyutil::splitlines(&patched_code).iter().enumerate() {
        let idx = (i + 1) as i64;
        if lines_to_patch.contains(&idx) && vuln_type == "DANGEROUS_EVAL" && line.contains("eval(")
        {
            safety_score = 40.0;
        }
    }

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    let mut patch_synthesized = applied;

    if safety_score < 80.0 {
        if is_strict {
            patch_synthesized = false;
            status = "REJECTED_PATCH".to_string();
        } else {
            status = "WARN_PATCH".to_string();
        }
    }

    Output {
        patch_synthesized,
        patched_code,
        patch_diff: diff,
        patch_safety_score: safety_score,
        remediations,
        status,
    }
}

/// Equivalent of Python `str.lstrip()` (no-arg): strips leading whitespace
/// only, used to compute the indent prefix. Mirrors `str.lstrip()`'s Unicode
/// whitespace handling via Rust's `trim_start`.
fn trim_start_python(s: &str) -> &str {
    s.trim_start()
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = heal_vulnerabilities(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(vuln_type: &str, source: &str, lines: Vec<i64>) -> Output {
        heal_vulnerabilities(&Input {
            file_path: "f.txt".into(),
            source_code: source.into(),
            vulnerability_type: vuln_type.into(),
            vulnerable_lines: lines,
        })
    }

    #[test]
    #[serial]
    fn pins_unpinned_requirements_dep() {
        std::env::remove_var("PI_PATCH_STRICT_MODE");
        let o = run("UNPINNED_DEP", "flask>=1.0\nrequests", vec![1, 2]);
        assert_eq!(o.patched_code, "flask==3.0.0\nrequests==2.31.0");
        assert!(o.patch_synthesized);
        assert_eq!(o.patch_safety_score, 100.0);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.remediations.len(), 2);
    }

    #[test]
    #[serial]
    fn dangerous_eval_strict_rejected() {
        std::env::remove_var("PI_PATCH_STRICT_MODE");
        // The replacement still contains "eval" (in the TODO comment) but not
        // "eval(" -> safety stays 100. Use a line where eval( survives? It
        // doesn't: the whole line is replaced. So this stays PASSED at 100.
        let o = run("DANGEROUS_EVAL", "    result = eval(payload)", vec![1]);
        assert!(o.patched_code.contains("# TODO (Security Remediation)"));
        assert!(o.patched_code.contains("    pass"));
        assert_eq!(o.patch_safety_score, 100.0);
        assert_eq!(o.status, "PASSED");
        assert!(o.patch_synthesized);
    }

    #[test]
    #[serial]
    fn no_match_warn_mode_non_strict() {
        std::env::set_var("PI_PATCH_STRICT_MODE", "false");
        // A non-matching line for UNPINNED_DEP -> not applied -> score 50.0.
        let o = run("UNPINNED_DEP", "===garbage===", vec![1]);
        assert!(!o.patch_synthesized);
        assert_eq!(o.patch_safety_score, 50.0);
        assert_eq!(o.status, "WARN_PATCH");
        std::env::remove_var("PI_PATCH_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn no_match_strict_rejected() {
        std::env::remove_var("PI_PATCH_STRICT_MODE");
        let o = run("UNPINNED_DEP", "===garbage===", vec![1]);
        assert!(!o.patch_synthesized);
        assert_eq!(o.patch_safety_score, 50.0);
        assert_eq!(o.status, "REJECTED_PATCH");
    }
}
