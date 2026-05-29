//! Port of `pi_micro_agents/pi_cloud_run_config_auditor.py`.
//!
//! Audits Cloud Run Service YAML configurations using safe regex-based parsing
//! to enforce VPC connection, secret management, non-root execution, probes, and
//! resource bounds. Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub service_yaml: String,
    #[serde(default)]
    pub allow_unauthenticated: bool,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Python: re.findall(r"(?s)-\s*name:\s*([^\n]+).*?value:\s*([^\n]+)", yaml_content)
// (?s) = DOTALL (affects `.`); `[^\n]` still excludes newline regardless.
// Two capture groups, non-greedy `.*?`. No lookaround/backrefs -> regex crate OK.
static ENV_BLOCK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)-\s*name:\s*([^\n]+).*?value:\s*([^\n]+)").unwrap());

const SENSITIVE_KEYWORDS: [&str; 6] =
    ["password", "secret", "token", "key", "credential", "auth"];

/// Mirrors Python `str.strip(" '\"")`: strips leading/trailing space, single
/// quote, and double quote characters (NOT the default whitespace strip).
fn strip_quotes_spaces(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\'' || c == '"')
}

pub fn audit(input: &Input) -> Output {
    let yaml_content = &input.service_yaml;
    let allow_unauthenticated = input.allow_unauthenticated;

    let mut issues: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    let lower = yaml_content.to_lowercase();

    // 1. Check for allowUnauthenticated / allUsers ingress setting
    if !allow_unauthenticated
        && (lower.contains("allusers") || lower.contains("allowunauthenticated: true"))
    {
        issues.push("VULNERABILITY: Public unauthenticated ingress is active (allUsers binding).".to_string());
        risk_score += 30.0;
    }

    // 2. Check for resource limits
    if !lower.contains("resources:") || !lower.contains("limits:") {
        issues.push(
            "WARNING: Service does not configure resource limits (CPU/Memory).".to_string(),
        );
        risk_score += 20.0;
    }

    // 3. Check for VPC connection
    if !lower.contains("vpc-access-connector") && !lower.contains("vpc-access") {
        issues.push(
            "WARNING: Service does not utilize a VPC connector; it might bypass secure network routing.".to_string(),
        );
        risk_score += 15.0;
    }

    // 4. Check for health probes
    if !lower.contains("livenessprobe") && !lower.contains("startupprobe") {
        issues.push(
            "WARNING: Service does not configure livenessProbe or startupProbe for health checks.".to_string(),
        );
        risk_score += 10.0;
    }

    // 5. Non-root context
    if !lower.contains("runasnonroot: true") && !lower.contains("securitycontext") {
        issues.push(
            "WARNING: Service does not enforce non-root container execution.".to_string(),
        );
        risk_score += 10.0;
    }

    // 6. Check for cleartext secrets in environment variables
    for caps in ENV_BLOCK_RE.captures_iter(yaml_content) {
        let env_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let env_val = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        // env_name.strip(" '\"").lower()
        let env_name_clean = strip_quotes_spaces(env_name).to_lowercase();
        // env_val.strip(" '\"")
        let env_val_clean = strip_quotes_spaces(env_val);

        if SENSITIVE_KEYWORDS.iter().any(|kw| env_name_clean.contains(kw)) {
            if !env_val_clean.is_empty()
                && !env_val_clean.starts_with('$')
                && !env_val_clean.to_lowercase().contains("valuefrom")
            {
                // f"...'{env_name.strip()}'..." -> default whitespace strip
                let env_name_stripped = pyutil::strip(env_name);
                issues.push(format!(
                    "WARNING: Sensitive environment variable '{env_name_stripped}' has cleartext value."
                ));
                risk_score += 25.0;
                break;
            }
        }
    }

    risk_score = risk_score.min(100.0);
    let is_secure = risk_score < 50.0;

    let status = if risk_score >= 60.0 {
        "FAIL".to_string()
    } else if risk_score >= 30.0 {
        "WARN".to_string()
    } else {
        "PASS".to_string()
    };

    Output {
        is_secure,
        issues,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(service_yaml: &str, allow_unauthenticated: bool) -> Output {
        audit(&Input {
            service_yaml: service_yaml.into(),
            allow_unauthenticated,
        })
    }

    #[test]
    fn fully_hardened_config_passes_with_residual_warnings() {
        // Hits resources/limits, vpc-access, probes, securityContext present.
        let yaml = "\
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/vpc-access-connector: my-connector
    spec:
      containers:
        - image: gcr.io/x
          resources:
            limits:
              cpu: '1'
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /
          securityContext:
            runAsNonRoot: true
";
        let o = run(yaml, false);
        // All five structural checks satisfied -> no risk, PASS, secure.
        assert!(o.is_secure);
        assert_eq!(o.status, "PASS");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.issues.is_empty());
    }

    #[test]
    fn public_ingress_flagged() {
        // allUsers present and not allowed -> +30, plus all structural warnings.
        let yaml = "bindings:\n  - role: roles/run.invoker\n    members:\n      - allUsers\n";
        let o = run(yaml, false);
        assert!(o
            .issues
            .iter()
            .any(|i| i.contains("Public unauthenticated ingress")));
        // 30 (public) + 20 (limits) + 15 (vpc) + 10 (probes) + 10 (nonroot) = 85
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.status, "FAIL");
        assert!(!o.is_secure);
    }

    #[test]
    fn public_ingress_allowed_suppresses_vuln() {
        let yaml = "members:\n  - allUsers\n";
        let o = run(yaml, true);
        assert!(!o
            .issues
            .iter()
            .any(|i| i.contains("Public unauthenticated ingress")));
    }

    #[test]
    fn cleartext_secret_flagged() {
        let yaml = "\
env:
  - name: DB_PASSWORD
    value: hunter2
";
        let o = run(yaml, false);
        assert!(o
            .issues
            .iter()
            .any(|i| i.contains("Sensitive environment variable 'DB_PASSWORD' has cleartext value")));
    }

    #[test]
    fn secret_via_valuefrom_not_flagged() {
        let yaml = "\
env:
  - name: API_TOKEN
    valueFrom:
      secretKeyRef:
        name: my-secret
    value: valueFrom-placeholder
";
        let o = run(yaml, false);
        assert!(!o
            .issues
            .iter()
            .any(|i| i.contains("cleartext value")));
    }
}
