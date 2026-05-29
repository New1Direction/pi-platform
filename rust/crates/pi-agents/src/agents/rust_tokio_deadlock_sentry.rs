//! Port of `pi_micro_agents/pi_rust_tokio_deadlock_sentry.py`.
//!
//! Specialized concurrency micro-agent auditing Rust code for Tokio async
//! deadlocks and nested lock-hold patterns. Behaviour is a line-for-line
//! mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub rust_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_elements: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Python: re.search(r'\.lock\(\)[\s\S]*?\.await', code)
// `[\s\S]*?` matches any character (incl. newlines) lazily; the `regex`
// crate supports this directly without `(?s)`.
static RE_LOCK_AWAIT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.lock\(\)[\s\S]*?\.await").unwrap());

// Python: re.search(r'async[\s\S]*?block_on\(', code)
static RE_ASYNC_BLOCK_ON: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"async[\s\S]*?block_on\(").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: the Python original, when the env var is unset, falls back to reading
/// `~/.antigravitycli/config.json` (defaulting to strict=True). This port
/// mirrors the env var (which the parity harness sets explicitly) and defaults
/// to strict=True otherwise, matching the reference jwt_none_sentry port.
fn is_strict_mode() -> bool {
    match std::env::var("PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_tokio_deadlock(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // has_std_mutex = ("std::sync" in code or "parking_lot" in code) and
    //                 ("Mutex" in code or "RwLock" in code)
    let has_std_mutex = (code.contains("std::sync") || code.contains("parking_lot"))
        && (code.contains("Mutex") || code.contains("RwLock"));
    let has_await = code.contains(".await");

    if has_std_mutex && has_await {
        if RE_LOCK_AWAIT.is_match(code) {
            vulnerable_elements.push("sync_lock_held_across_await".to_string());
            flagged_findings.push(
                "Rust async block holds a synchronous std::sync::Mutex guard across an '.await' point. \
This can lead to runtime thread deadlocks or block the Tokio executor pool completely."
                    .to_string(),
            );
        }

        if RE_ASYNC_BLOCK_ON.is_match(code) {
            vulnerable_elements.push("block_on_inside_async".to_string());
            flagged_findings.push(
                "Rust async function or block uses a synchronous 'block_on' executor call. \
Calling block_on nested inside an existing async task runtime can cause executor stack overflow or immediate deadlocks."
                    .to_string(),
            );
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_RUST_TOKIO_DEADLOCK".to_string();
        } else {
            status = "WARN_RUST_TOKIO_DEADLOCK".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_elements,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_tokio_deadlock(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_tokio_deadlock(&Input {
            file_path: "f.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_code_passes() {
        std::env::remove_var("PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE");
        let o = run("use tokio::sync::Mutex;\nasync fn f() { let g = m.lock().await; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    #[serial]
    fn sync_lock_across_await_flagged() {
        std::env::set_var("PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE", "true");
        let o = run("use std::sync::Mutex;\nasync fn f() { let g = m.lock(); other().await; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_RUST_TOKIO_DEADLOCK");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_elements, vec!["sync_lock_held_across_await"]);
        std::env::remove_var("PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn block_on_warn_when_not_strict() {
        std::env::set_var("PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE", "false");
        let o = run("use parking_lot::RwLock;\nasync fn g() { rt.block_on(fut); other().await; }");
        // both patterns: lock_await? no `.lock()` here, but block_on yes.
        assert!(o.is_secure); // coerced back to true under WARN
        assert_eq!(o.status, "WARN_RUST_TOKIO_DEADLOCK");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_elements, vec!["block_on_inside_async"]);
        std::env::remove_var("PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE");
    }
}
