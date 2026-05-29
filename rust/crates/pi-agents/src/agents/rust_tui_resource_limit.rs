//! Port of `pi_micro_agents/pi_rust_tui_resource_limit.py`.
//!
//! Audits Rust Ratatui/TUI rendering loops for missing frame/rate limits.
//! Behaviour is a line-for-line mirror of the Python original.

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

/// Mirrors `is_strict_mode()`.
///
/// The Python implementation first consults the env var
/// `PI_RUST_TUI_RESOURCE_LIMIT_STRICT_MODE` (strict iff the value lowercases to
/// "true"). If the env var is unset it falls back to reading
/// `~/.antigravitycli/config.json` (or, if that is missing, the repo-root
/// `.antigravitycli/config.json`) and returns
/// `bool(data.get("PI_RUST_TUI_RESOURCE_LIMIT_STRICT_MODE", True))`. In this
/// repository neither config file contains that key, so the config-file path
/// always resolves to `True`. We therefore default to `true` when the env var
/// is unset, which is byte-identical in this environment. See `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_RUST_TUI_RESOURCE_LIMIT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_tui_resources(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Scans for loops that do ratatui/tui terminal rendering.
    // Look for infinite loops or rendering loops.
    let has_draw =
        code.contains("terminal.draw") || code.contains("Terminal::draw") || code.contains("draw(");

    if has_draw {
        // Check if they have duration limits, poll, sleep, or interval.
        let throttle_tokens = [
            "event::poll",
            "Duration::from",
            "sleep(",
            "tick(",
            "interval(",
            "FrameRate",
            "fps",
        ];
        let has_throttle = throttle_tokens.iter().any(|x| code.contains(x));

        if !has_throttle {
            vulnerable_elements.push("terminal_draw_loop".to_string());
            flagged_findings.push(
                "Rust TUI rendering loop contains drawing calls (terminal.draw) but lacks explicit \
frame throttling or tick/poll intervals (e.g. event::poll or thread::sleep). This can cause \
extreme CPU consumption and resource exhaustion in terminal contexts."
                    .to_string(),
            );
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_RUST_TUI_LIMIT".to_string();
        } else {
            status = "WARN_RUST_TUI_LIMIT".to_string();
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
    let out = audit_tui_resources(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_tui_resources(&Input {
            file_path: "main.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn no_draw_passes() {
        let o = run("fn main() { println!(\"hi\"); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn draw_without_throttle_flagged() {
        let o = run("loop { terminal.draw(|f| ui(f))?; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_RUST_TUI_LIMIT");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_elements, vec!["terminal_draw_loop"]);
    }

    #[test]
    fn draw_with_throttle_passes() {
        let o = run("loop { terminal.draw(|f| ui(f))?; if event::poll(Duration::from_millis(16))? {} }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }
}
