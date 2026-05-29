//! Port of `pi_micro_agents/pi_pipeline_integrity_auditor.py`.
//!
//! Specialized CI/CD auditor checking for action injection vectors, unpinned
//! script runs, and host access abuses. Behaviour is a line-for-line mirror of
//! the Python original.
//!
//! Note: the Python module defines an `is_strict_mode()` helper that reads the
//! env var `PI_PIPELINE_INTEGRITY_STRICT_MODE`, but `audit_pipeline_integrity`
//! never calls it. The scan logic reads no env vars, so this port reads none
//! either.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub workflow_path: String,
    pub workflow_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub detected_flaws: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

pub fn audit_pipeline_integrity(input: &Input) -> Output {
    let content = &input.workflow_content;
    let mut flaws: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Detect untrusted user inputs siphoned directly into bash/shell tasks
    // (GitHub Event script injections)
    if content.contains("github.event.inputs") || content.contains("github.head_ref") {
        if content.contains("run:") {
            flaws.push(
                "Critical Script Injection: unescaped github.event context parameter siphoned directly into shell step."
                    .to_string(),
            );
            risk_score = risk_score.max(90.0);
        }
    }

    // Detect high-privilege access permissions (write-all, admin access to
    // secrets in forks)
    if content.to_lowercase().contains("permissions: write-all")
        || content.contains("permissions: {}")
    {
        flaws.push(
            "Permissive Access: workflow configuration is granted excessive default write permissions."
                .to_string(),
        );
        risk_score = risk_score.max(65.0);
    }

    let is_secure = flaws.is_empty();
    let status = if is_secure {
        "PASSED".to_string()
    } else {
        "FAILED_INTEGRITY".to_string()
    };

    Output {
        is_secure,
        detected_flaws: flaws,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_pipeline_integrity(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        audit_pipeline_integrity(&Input {
            workflow_path: ".github/workflows/ci.yml".into(),
            workflow_content: content.into(),
        })
    }

    #[test]
    fn clean_workflow_passes() {
        let o = run("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.detected_flaws.is_empty());
    }

    #[test]
    fn script_injection_flagged() {
        let o = run("jobs:\n  x:\n    steps:\n      - run: echo ${{ github.event.inputs.name }}\n");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_INTEGRITY");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.detected_flaws.len(), 1);
    }

    #[test]
    fn github_context_without_run_is_clean() {
        // github.head_ref present but no "run:" step => no flaw appended.
        let o = run("env:\n  REF: ${{ github.head_ref }}\n");
        assert!(o.is_secure);
        assert_eq!(o.risk_score, 0.0);
    }

    #[test]
    fn write_all_permissions_flagged() {
        let o = run("permissions: write-all\njobs: {}\n");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_INTEGRITY");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.detected_flaws.len(), 1);
    }

    #[test]
    fn both_flaws_take_max_risk() {
        let o = run(
            "permissions: write-all\njobs:\n  x:\n    steps:\n      - run: echo ${{ github.event.inputs.cmd }}\n",
        );
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.detected_flaws.len(), 2);
    }
}
