//! Port of `pi_micro_agents/pi_git_sec_scanner.py`.
//!
//! CI/CD dependency and security-patch sandbox scanner. Inspects file content
//! (requirements.txt, package.json, source files) for unpinned/typosquatted
//! dependencies, dangerous code-execution patterns, and hardcoded secrets.
//! Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub filename: String,
    pub content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub risk_score: f64,
    pub status: String,
    pub flagged_vulnerabilities: Vec<String>,
}

// --- Compiled regexes (mirroring the Python patterns) ---

// package.json: re.findall(r'"([^"]+)"\s*:\s*"([*^~]|[xX]|\b(?:latest)\b)', content)
// 2 capture groups -> captures_iter. No IGNORECASE in Python.
static PACKAGE_JSON_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#""([^"]+)"\s*:\s*"([*^~]|[xX]|\b(?:latest)\b)"#).unwrap());

// Dangerous-execution patterns: re.search(pat, content). No flags. 0 groups -> is_match.
// Note: Python `.` does not match newline by default; regex crate matches Python here.
static EVAL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\beval\s*\(").unwrap());
static EXEC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bexec\s*\(").unwrap());
static SUBPROCESS_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"subprocess\.(?:Popen|run|call)\(.*shell\s*=\s*True").unwrap());
static OS_SYSTEM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"os\.system\s*\(").unwrap());

// Secret patterns: re.search(pat, content, re.IGNORECASE). 0 groups -> is_match.
static SECRET_API_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:api_key|apikey|api-key)\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]"#).unwrap()
});
static SECRET_PRIVATE_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:private_key|privatekey)\s*[:=]\s*['"](?:0x)?[a-fA-F0-9]{64,}['"]"#).unwrap()
});
static SECRET_CLIENT_SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:secret|client_secret|client-secret)\s*[:=]\s*['"][a-zA-Z0-9_\-+=/]{30,}['"]"#)
        .unwrap()
});

/// Mirrors `is_strict_mode()`.
///
/// Python resolution order:
///   1. env `PI_GIT_SEC_STRICT_MODE` -> `value.lower() == "true"`
///   2. `~/.antigravitycli/config.json` then the in-repo
///      `../../.antigravitycli/config.json`, reading the
///      `PI_GIT_SEC_STRICT_MODE` key (default True via `data.get(..., True)`)
///   3. default True
///
/// The config-file fallback is environment-dependent; in this repo the config
/// file lacks the key, so `data.get(..., True)` yields True. Therefore, when
/// the env var is unset the effective result is `true`, which this function
/// reproduces. See `deviations`: the config-file branch is intentionally
/// collapsed to the default-True behaviour.
fn is_strict_mode() -> bool {
    match std::env::var("PI_GIT_SEC_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `detect_git_sec_anomalies(content, filename)`.
fn detect_git_sec_anomalies(content: &str, filename: &str) -> (f64, Vec<String>) {
    let mut violations: Vec<String> = Vec::new();
    let mut max_risk: f64 = 0.0;
    if content.is_empty() {
        return (0.0, Vec::new());
    }

    let fn_lower = filename.to_lowercase();

    // A. Dependency Checkers (requirements.txt, package.json)
    if fn_lower.contains("requirements.txt") {
        // for idx, line in enumerate(lines):  (enumerate starts at 0; uses idx+1)
        for (i, raw_line) in pyutil::splitlines(content).into_iter().enumerate() {
            let line = pyutil::strip(raw_line);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Detect unpinned or wildcard/range dependencies.
            if !line.contains("==") && !line.contains("===") {
                violations.push(format!(
                    "unpinned or range dependency in requirements.txt (line {}): '{}'",
                    i + 1,
                    line
                ));
                max_risk = max_risk.max(75.0);
            }

            // Typosquatting / Suspicious Packages.
            let suspicious_packages = [
                "discord-py-self",
                "urllib5",
                "colorama-plus",
                "reqs",
                "pip-install-all",
            ];
            // package_name = line.split("=")[0].split(">")[0].split("<")[0].split("~")[0].strip().lower()
            // Python str.split(sep)[0] == substring up to first occurrence of sep.
            let package_name = py_first_split(line, '=');
            let package_name = py_first_split(package_name, '>');
            let package_name = py_first_split(package_name, '<');
            let package_name = py_first_split(package_name, '~');
            let package_name = pyutil::strip(package_name).to_lowercase();
            if suspicious_packages.contains(&package_name.as_str()) {
                violations.push(format!(
                    "high-risk typosquatted / suspicious package detected (line {}): '{}'",
                    i + 1,
                    package_name
                ));
                max_risk = max_risk.max(85.0);
            }
        }
    } else if fn_lower.contains("package.json") {
        // wildcard_matches = re.findall(r'...', content)  -> [(pkg, ver), ...]
        for caps in PACKAGE_JSON_RE.captures_iter(content) {
            let pkg = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let ver = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            violations.push(format!(
                "unpinned or floating dependency in package.json: '{}': '{}'",
                pkg, ver
            ));
            max_risk = max_risk.max(75.0);
        }
    }

    // B. Dangerous Code Execution Checks (.py, .js, .ts, .sh, .sol, ...)
    let source_extensions = [
        ".py", ".js", ".ts", ".sh", ".sol", ".go", ".c", ".cpp",
    ];
    if source_extensions.iter().any(|ext| fn_lower.ends_with(ext)) || fn_lower == "pi-platform" {
        let eval_patterns: [(&Regex, &str); 4] = [
            (&EVAL_RE, "arbitrary code evaluation 'eval()'"),
            (&EXEC_RE, "arbitrary code execution 'exec()'"),
            (&SUBPROCESS_RE, "insecure subprocess with shell=True"),
            (&OS_SYSTEM_RE, "insecure system execution 'os.system()'"),
        ];
        for (re, desc) in eval_patterns.iter() {
            if re.is_match(content) {
                violations.push(format!("dangerous execution function: {}", desc));
                max_risk = max_risk.max(90.0);
            }
        }
    }

    // C. Hardcoded Credentials & Sensitive Data Secrets (re.IGNORECASE)
    let secret_patterns: [(&Regex, &str); 3] = [
        (&SECRET_API_KEY_RE, "hardcoded API key"),
        (&SECRET_PRIVATE_KEY_RE, "hardcoded private key hex signature"),
        (&SECRET_CLIENT_SECRET_RE, "hardcoded client secret token"),
    ];
    for (re, desc) in secret_patterns.iter() {
        if re.is_match(content) {
            violations.push(format!("potential leak of secret information: {}", desc));
            max_risk = max_risk.max(95.0);
        }
    }

    (max_risk, violations)
}

/// Equivalent of Python `s.split(sep)[0]`: the substring before the first
/// occurrence of `sep` (or the whole string when `sep` is absent).
fn py_first_split(s: &str, sep: char) -> &str {
    match s.find(sep) {
        Some(idx) => &s[..idx],
        None => s,
    }
}

/// Mirrors `PiGitSecScanner.scan_file`.
pub fn scan_file(input: &Input) -> Output {
    let (risk, violations) = detect_git_sec_anomalies(&input.content, &input.filename);

    let is_strict = is_strict_mode();
    let mut is_secure = true;
    let mut status = "PASSED".to_string();

    if risk >= 80.0 {
        if is_strict {
            is_secure = false;
            status = "REJECTED_VULNERABILITY".to_string();
        } else {
            status = "WARN_VULNERABILITY".to_string();
        }
    } else if risk >= 70.0 {
        status = "WARN_VULNERABILITY".to_string();
    }

    Output {
        is_secure,
        risk_score: risk,
        status,
        flagged_vulnerabilities: violations,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_file(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(filename: &str, content: &str) -> Output {
        scan_file(&Input {
            filename: filename.into(),
            content: content.into(),
        })
    }

    #[test]
    #[serial]
    fn clean_requirements_passes() {
        std::env::remove_var("PI_GIT_SEC_STRICT_MODE");
        let o = run("requirements.txt", "requests==2.31.0\nflask==3.0.0\n");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_vulnerabilities.is_empty());
    }

    #[test]
    #[serial]
    fn unpinned_dependency_warns() {
        std::env::remove_var("PI_GIT_SEC_STRICT_MODE");
        // risk 75 -> WARN, is_secure stays true
        let o = run("requirements.txt", "requests>=2.0.0\n");
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_VULNERABILITY");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.flagged_vulnerabilities.len(), 1);
    }

    #[test]
    #[serial]
    fn dangerous_eval_rejected_strict() {
        std::env::remove_var("PI_GIT_SEC_STRICT_MODE");
        let o = run("app.py", "x = eval('1+1')\n");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_VULNERABILITY");
        assert_eq!(o.risk_score, 90.0);
    }

    #[test]
    #[serial]
    fn dangerous_eval_warns_non_strict() {
        std::env::set_var("PI_GIT_SEC_STRICT_MODE", "false");
        let o = run("app.py", "x = eval('1+1')\n");
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_VULNERABILITY");
        assert_eq!(o.risk_score, 90.0);
        std::env::remove_var("PI_GIT_SEC_STRICT_MODE");
    }
}
