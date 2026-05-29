//! Port of `pi_micro_agents/pi_web_vuln_scanner.py`.
//!
//! Specialized web application vulnerability scanner targeting XSS, CSRF, and
//! security-header misconfigurations. Behaviour is a line-for-line mirror of the
//! Python original.
//!
//! Note: the Python module defines `is_strict_mode()` (reading the env var
//! `PI_WEB_VULN_STRICT_MODE`), but `scan_web_vulnerabilities` never calls it, so
//! no environment variable affects this agent's output. We deliberately do not
//! consult any env var here, matching the Python scan logic exactly.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub code_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_vulnerabilities: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

pub fn scan_web_vulnerabilities(input: &Input) -> Output {
    let code = &input.code_content;
    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Check for XSS (dangerouslySetInnerHTML, unsafe innerHTML, raw script injections)
    if code.contains("dangerouslySetInnerHTML") || code.contains("innerHTML =") {
        findings.push(
            "Potential Cross-Site Scripting (XSS) vulnerability: unsafe raw HTML injection found."
                .to_string(),
        );
        risk_score = risk_score.max(85.0);
    }

    // Check for missing CSRF protection or disabled CSRF tokens in configs
    let code_lower = code.to_lowercase();
    if code_lower.contains("csrf: false")
        || code_lower.contains("enable_csrf = false")
        || code_lower.contains("csrf_protect = false")
    {
        findings.push(
            "Broken Access Control: Cross-Site Request Forgery (CSRF) protection is disabled."
                .to_string(),
        );
        risk_score = risk_score.max(80.0);
    }

    // Check for missing security headers or insecure content security policies
    if !code_lower.contains("content-security-policy") && !code_lower.contains("csp") {
        findings.push(
            "Missing Security Hardening: Content Security Policy (CSP) header is not defined."
                .to_string(),
        );
        risk_score = risk_score.max(50.0);
    }

    let is_secure = findings.is_empty();
    let status = if is_secure { "SECURE" } else { "VULNERABLE" }.to_string();

    Output {
        is_secure,
        flagged_vulnerabilities: findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_web_vulnerabilities(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        scan_web_vulnerabilities(&Input {
            file_path: "f.js".into(),
            code_content: code.into(),
        })
    }

    #[test]
    fn clean_code_with_csp_is_secure() {
        // Has a Content-Security-Policy header reference, no XSS/CSRF issues.
        let o = run("res.setHeader('Content-Security-Policy', \"default-src 'self'\")");
        assert!(o.is_secure);
        assert_eq!(o.status, "SECURE");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_vulnerabilities.is_empty());
    }

    #[test]
    fn xss_flagged_high_risk() {
        // dangerouslySetInnerHTML triggers XSS (85). No CSP present -> also CSP (50).
        let o = run("return <div dangerouslySetInnerHTML={{__html: data}} />");
        assert!(!o.is_secure);
        assert_eq!(o.status, "VULNERABLE");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.flagged_vulnerabilities.len(), 2);
    }

    #[test]
    fn csrf_disabled_flagged() {
        // CSRF disabled (80) and no CSP (50) -> max 80, two findings.
        let o = run("app.use(session({ csrf: false }))");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.flagged_vulnerabilities.len(), 2);
    }

    #[test]
    fn missing_csp_only() {
        // Mentions neither CSP nor any flagged construct -> only the CSP finding (50).
        let o = run("const x = 1;");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 50.0);
        assert_eq!(o.flagged_vulnerabilities.len(), 1);
    }
}
