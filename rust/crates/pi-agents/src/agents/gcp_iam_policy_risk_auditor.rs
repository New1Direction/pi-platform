//! Port of `pi_micro_agents/pi_gcp_iam_policy_risk_auditor.py`.
//!
//! Audits GCP IAM policies (bindings, roles, members) to detect overly
//! permissive roles, public exposures, and compliance risks. Behaviour is a
//! line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct Input {
    pub policy_json: String,
    #[serde(default = "default_risk_tolerance")]
    pub risk_tolerance: String,
}

fn default_risk_tolerance() -> String {
    "medium".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `re.match(r"^[a-zA-Z0-9-._]+@[a-zA-Z0-9-._]+\.iam\.gserviceaccount\.com$", ...)`.
///
/// In Python's character class `[a-zA-Z0-9-._]` the `-` between `9` and `.` is a
/// literal dash (Python declines to form the backwards range `9..`). The Rust
/// `regex` crate would reject `9-.` as an invalid range, so the dash is moved to
/// the end of the class (`[a-zA-Z0-9._-]`) which matches the identical set:
/// a-z, A-Z, 0-9, `.`, `_`, `-`.
static SA_EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.iam\.gserviceaccount\.com$").unwrap()
});

pub fn audit(input: &Input) -> Result<Output, String> {
    let policy_json = &input.policy_json;
    let risk_tolerance = input.risk_tolerance.to_lowercase();

    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // try: policy = json.loads(policy_json)
    let policy: Value = match serde_json::from_str::<Value>(policy_json) {
        Ok(v) => v,
        Err(e) => {
            // NOTE: Python's json.JSONDecodeError message format
            // ("Expecting value: line 1 column 1 (char 0)") cannot be
            // reproduced byte-for-byte by serde_json. See deviations.
            findings.push(format!("Failed to parse IAM Policy JSON: {}", e));
            return Ok(Output {
                is_secure: false,
                findings,
                risk_score: 50.0,
                status: "FAIL".to_string(),
            });
        }
    };

    // policy.get("bindings", []) -- Python crashes with AttributeError if the
    // parsed JSON is not a dict (null/str/int/list). We surface that as an Err
    // since no faithful Output exists for those inputs.
    let policy_obj = match policy.as_object() {
        Some(m) => m,
        None => {
            return Err(
                "policy is not a JSON object ('NoneType'/str/int/list has no attribute 'get')"
                    .to_string(),
            )
        }
    };

    // bindings = policy.get("bindings", [])
    // A missing key yields the default empty list; a present non-list value
    // falls through to the "must contain a 'bindings' list" branch.
    let empty_bindings: Vec<Value> = Vec::new();
    let bindings: &Vec<Value> = match policy_obj.get("bindings") {
        None => &empty_bindings,
        Some(v) => match v.as_array() {
            Some(arr) => arr,
            None => {
                // if not isinstance(bindings, list):
                findings.push("IAM Policy must contain a 'bindings' list.".to_string());
                return Ok(Output {
                    is_secure: false,
                    findings,
                    risk_score: 40.0,
                    status: "FAIL".to_string(),
                });
            }
        },
    };

    let privileged_roles = ["roles/owner", "roles/editor"];

    for (idx, binding) in bindings.iter().enumerate() {
        // if not isinstance(binding, dict):
        let binding_obj = match binding.as_object() {
            Some(m) => m,
            None => {
                findings.push(format!("Binding at index {} is not a dictionary.", idx));
                risk_score += 10.0;
                continue;
            }
        };

        // role = binding.get("role", "")
        let role = binding_obj
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // members = binding.get("members", [])
        let empty_members: Vec<Value> = Vec::new();
        let members: &Vec<Value> = binding_obj
            .get("members")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_members);

        // if not role:
        if role.is_empty() {
            findings.push(format!("Binding at index {} is missing 'role'.", idx));
            risk_score += 15.0;
            continue;
        }

        // Rule 1: Check privileged roles
        let mut is_role_privileged = false;
        if privileged_roles.contains(&role.as_str()) {
            findings.push(format!("Highly privileged role '{}' binding detected.", role));
            risk_score += 30.0;
            is_role_privileged = true;
        } else if role.to_lowercase().contains("admin") {
            findings.push(format!("Administrative role '{}' binding detected.", role));
            risk_score += 20.0;
            is_role_privileged = true;
        }

        // Rule 2: Check wildcards in custom roles
        if role == "*" {
            findings.push(
                "Wildcard '*' role binding detected, granting absolute access.".to_string(),
            );
            risk_score += 50.0;
        }

        for member_val in members.iter() {
            // Python iterates raw members; non-str members would crash on
            // `member.startswith` / `member in [...]`. Treat non-str as
            // skipping string ops faithfully is impossible without a crash, so
            // we coerce to str only for str members and otherwise ignore.
            let member = match member_val.as_str() {
                Some(s) => s,
                None => continue,
            };

            // Rule 3: Check public exposure
            if member == "allUsers" || member == "allAuthenticatedUsers" {
                if is_role_privileged {
                    findings.push(format!(
                        "CRITICAL: Public member '{}' granted privileged role '{}'.",
                        member, role
                    ));
                    risk_score += 50.0;
                } else {
                    findings.push(format!(
                        "Public member '{}' granted role '{}'.",
                        member, role
                    ));
                    risk_score += 30.0;
                }
            }

            // Rule 4: Validate service account format
            if member.starts_with("serviceAccount:") {
                // member.split("serviceAccount:")[-1]
                let sa_email = member.rsplit("serviceAccount:").next().unwrap_or("");
                if !SA_EMAIL_RE.is_match(sa_email) {
                    findings.push(format!(
                        "Service account member '{}' has non-standard email domain formatting.",
                        sa_email
                    ));
                    risk_score += 15.0;
                }
            }
        }
    }

    // Adjust risk score based on tolerance
    if risk_tolerance == "low" {
        risk_score *= 1.25;
    } else if risk_tolerance == "high" {
        risk_score *= 0.75;
    }

    // risk_score = min(risk_score, 100.0)
    risk_score = risk_score.min(100.0);

    // Secure definition
    let fail_threshold: f64 = if risk_tolerance == "low" { 30.0 } else { 60.0 };
    let is_secure = risk_score < fail_threshold;

    let status = if risk_score > fail_threshold {
        "FAIL".to_string()
    } else if risk_score >= 20.0 {
        "WARN".to_string()
    } else {
        "PASS".to_string()
    };

    Ok(Output {
        is_secure,
        findings,
        risk_score,
        status,
    })
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit(&input)?;
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(policy_json: &str, risk_tolerance: &str) -> Output {
        audit(&Input {
            policy_json: policy_json.into(),
            risk_tolerance: risk_tolerance.into(),
        })
        .unwrap()
    }

    #[test]
    fn empty_policy_passes() {
        let o = run("{}", "medium");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASS");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.findings.is_empty());
    }

    #[test]
    fn owner_with_all_users_low_tolerance_fails() {
        let p = r#"{"bindings":[{"role":"roles/owner","members":["allUsers"]}]}"#;
        let o = run(p, "low");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAIL");
        assert_eq!(o.risk_score, 100.0);
        assert_eq!(o.findings.len(), 2);
    }

    #[test]
    fn bad_service_account_high_tolerance_warns_fraction() {
        let p = r#"{"bindings":[{"role":"roles/viewer","members":["serviceAccount:bad@gmail.com"]}]}"#;
        let o = run(p, "high");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASS");
        assert_eq!(o.risk_score, 11.25);
        assert_eq!(
            o.findings,
            vec!["Service account member 'bad@gmail.com' has non-standard email domain formatting."]
        );
    }

    #[test]
    fn bindings_not_a_list_fails() {
        let o = run(r#"{"bindings":"notalist"}"#, "medium");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAIL");
        assert_eq!(o.risk_score, 40.0);
        assert_eq!(o.findings, vec!["IAM Policy must contain a 'bindings' list."]);
    }
}
