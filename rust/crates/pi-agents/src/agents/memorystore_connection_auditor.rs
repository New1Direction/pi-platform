//! Port of `pi_micro_agents/pi_memorystore_connection_auditor.py`.
//!
//! Audits Memorystore (Redis) connection parameters to ensure secure
//! transmission (TLS), credential safety, and proper environment bindings.
//! Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub connection_string: String,
    #[serde(default = "default_require_tls")]
    pub require_tls: bool,
    #[serde(default = "default_deployment_env")]
    pub deployment_env: String,
}

fn default_require_tls() -> bool {
    true
}

fn default_deployment_env() -> String {
    "production".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_valid: bool,
    pub scheme: String,
    pub host: String,
    pub port: i128,
    pub uses_tls: bool,
    pub has_auth: bool,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Redis connection string pattern.
// e.g., redis://:password@127.0.0.1:6379/0 or rediss://host:6380
// No lookaround/backreferences -> directly supported by the `regex` crate.
static PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(redis|rediss)://(?:([^:@]+)?(?::([^@]+))?@)?([^:/]+)(?::(\d+))?(?:/(\d+))?$")
        .unwrap()
});

pub fn audit(input: &Input) -> Output {
    let connection_string = &input.connection_string;
    let require_tls = input.require_tls;
    let deployment_env = &input.deployment_env;

    let mut issues: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;
    let scheme;
    let host;
    let port: i128;
    let uses_tls;
    let has_auth;

    // Match Redis connection string pattern.
    let captures = PATTERN.captures(connection_string);

    let caps = match captures {
        None => {
            issues.push(
                "Connection string is in an invalid format. Must match redis:// or rediss:// patterns."
                    .to_string(),
            );
            return Output {
                is_valid: false,
                scheme: String::new(),
                host: String::new(),
                port: 0,
                uses_tls: false,
                has_auth: false,
                issues,
                risk_score: 50.0,
                status: "FAIL".to_string(),
            };
        }
        Some(c) => c,
    };

    // Python sets is_valid = True after a successful regex match and only ever
    // resets it inside a dead `except ValueError` (see port parse below), so for
    // any matched input is_valid is always true.
    let is_valid = true;
    let matched_scheme = caps.get(1).map(|m| m.as_str());
    let user = caps.get(2).map(|m| m.as_str());
    let password = caps.get(3).map(|m| m.as_str());
    let matched_host = caps.get(4).map(|m| m.as_str());
    let matched_port = caps.get(5).map(|m| m.as_str());
    // group 6 (db) is captured by Python but never used.

    scheme = matched_scheme.unwrap_or("").to_string();
    host = matched_host.unwrap_or("").to_string();
    uses_tls = scheme == "rediss";
    // Python: bool(user or password). Both capture groups require >=1 char when
    // they match, so `is_some()` is equivalent to non-empty truthiness.
    has_auth = user.is_some() || password.is_some();

    match matched_port {
        Some(p) => {
            // Python `int()` is arbitrary precision, so its `except ValueError`
            // is DEAD CODE for a `\d+` capture — it never raises, never sets
            // is_valid=False, never appends "Port must be an integer." We use
            // i128 (covers any realistic port and far beyond) and saturate
            // rather than invalidate. Only a port exceeding i128::MAX (39+
            // digits) would differ in the numeric `port` value — never in
            // is_valid / status / issues. A naive i64::parse here previously
            // diverged on 20+ digit ports (overflow -> spurious FAIL).
            port = p.parse::<i128>().unwrap_or(i128::MAX);
        }
        None => {
            port = if uses_tls { 6380 } else { 6379 };
        }
    }

    // Apply security rules
    // Rule 1: TLS check in production
    if require_tls && deployment_env.to_lowercase() == "production" && !uses_tls {
        issues.push(
            "TLS is required in production but plain 'redis://' scheme is used.".to_string(),
        );
        risk_score += 40.0;
    }

    // Rule 2: Host check in production (localhost is a risk)
    if deployment_env.to_lowercase() == "production"
        && (host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0")
    {
        issues.push(format!(
            "Localhost/loopback IP '{host}' specified in production environment."
        ));
        risk_score += 25.0;
    }

    // Rule 3: Embedded credentials warning
    if has_auth {
        issues.push(
            "Sensitive credentials (passwords) are embedded directly in the connection string."
                .to_string(),
        );
        risk_score += 30.0;
    }

    risk_score = risk_score.min(100.0);

    let status = if !is_valid || risk_score > 60.0 {
        "FAIL".to_string()
    } else if risk_score >= 30.0 {
        "WARN".to_string()
    } else {
        "PASS".to_string()
    };

    Output {
        is_valid,
        scheme,
        host,
        port,
        uses_tls,
        has_auth,
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

    fn run(connection_string: &str, require_tls: bool, deployment_env: &str) -> Output {
        audit(&Input {
            connection_string: connection_string.into(),
            require_tls,
            deployment_env: deployment_env.into(),
        })
    }

    #[test]
    fn clean_tls_production_passes() {
        let o = run("rediss://cache.internal:6380", true, "production");
        assert!(o.is_valid);
        assert_eq!(o.scheme, "rediss");
        assert_eq!(o.host, "cache.internal");
        assert_eq!(o.port, 6380);
        assert!(o.uses_tls);
        assert!(!o.has_auth);
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.status, "PASS");
        assert!(o.issues.is_empty());
    }

    #[test]
    fn plain_redis_with_creds_and_localhost_fails() {
        let o = run("redis://:secret@127.0.0.1:6379/0", true, "production");
        assert!(o.is_valid);
        assert_eq!(o.scheme, "redis");
        assert_eq!(o.host, "127.0.0.1");
        assert_eq!(o.port, 6379);
        assert!(!o.uses_tls);
        assert!(o.has_auth);
        // 40 (TLS) + 25 (localhost) + 30 (creds) = 95 -> FAIL
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.status, "FAIL");
        assert_eq!(o.issues.len(), 3);
    }

    #[test]
    fn invalid_format_fails() {
        let o = run("http://example.com", true, "production");
        assert!(!o.is_valid);
        assert_eq!(o.scheme, "");
        assert_eq!(o.host, "");
        assert_eq!(o.port, 0);
        assert_eq!(o.risk_score, 50.0);
        assert_eq!(o.status, "FAIL");
        assert_eq!(o.issues.len(), 1);
    }

    #[test]
    fn default_port_for_plain_redis_development_warns_on_creds() {
        // plain redis, default port 6379, dev env (no TLS/localhost rules fire),
        // credentials embedded -> +30 -> WARN.
        let o = run("redis://user:pass@db.example.com", true, "development");
        assert!(o.is_valid);
        assert_eq!(o.port, 6379);
        assert!(!o.uses_tls);
        assert!(o.has_auth);
        assert_eq!(o.risk_score, 30.0);
        assert_eq!(o.status, "WARN");
    }
}
