//! Port of `pi_micro_agents/pi_gcp_vpc_connector_validator.py`.
//!
//! Validator agent for GCP Serverless VPC Access Connectors, checking name
//! structures, /28 sizing, and RFC 1918 private range allocations. Behaviour is
//! a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub connector_name: String,
    pub ip_cidr_range: String,
    #[serde(default = "default_network")]
    pub network: String,
}

fn default_network() -> String {
    "default".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_valid: bool,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Rule 1 name pattern: `re.match(r"^[a-z][a-z0-9-]{0,62}$", connector_name)`.
// `re.match` anchors at the start; the trailing `$` lets Python also accept a
// single trailing `\n`. We mirror that below by tolerating one trailing `\n`.
static NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z][a-z0-9-]{0,62}$").unwrap());

// Rule 2 CIDR pattern: 5 capture groups.
static CIDR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$").unwrap()
});

/// Python's `re.match` with a `^...$` pattern: `$` matches end-of-string OR just
/// before a single trailing `\n`; the Rust `regex` crate's `$` (text mode)
/// matches only at the very end. To stay byte-faithful we retry against the
/// string with a single trailing `\n` stripped.
fn py_name_matches(s: &str) -> bool {
    if NAME_RE.is_match(s) {
        return true;
    }
    // Account for the trailing-newline allowance of Python's `$`.
    if let Some(stripped) = s.strip_suffix('\n') {
        if NAME_RE.is_match(stripped) {
            return true;
        }
    }
    false
}

fn py_cidr_captures(s: &str) -> Option<[i64; 5]> {
    let cap = CIDR_RE.captures(s).or_else(|| {
        s.strip_suffix('\n').and_then(|stripped| CIDR_RE.captures(stripped))
    })?;
    let mut out = [0i64; 5];
    for i in 0..5 {
        // Group ranges are bounded to {1,3}/{1,2} digits, so they parse safely.
        out[i] = cap.get(i + 1).unwrap().as_str().parse::<i64>().unwrap();
    }
    Some(out)
}

pub fn validate(input: &Input) -> Output {
    let connector_name = &input.connector_name;
    let ip_cidr_range = &input.ip_cidr_range;
    let _network = &input.network;

    let mut issues: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;
    let mut is_name_valid = true;
    let mut is_cidr_valid = true;

    // Rule 1: Validate Connector Name
    if !py_name_matches(connector_name) {
        is_name_valid = false;
        issues.push(
            "Connector name must start with a lowercase letter, be 1-63 characters, and contain only lowercase letters, numbers, or hyphens.".to_string(),
        );
        risk_score += 35.0;
    }

    // Rule 2: Validate CIDR Range format and prefix size /28
    match py_cidr_captures(ip_cidr_range) {
        None => {
            is_cidr_valid = false;
            issues.push(
                "IP CIDR range must be in valid IPv4 CIDR format (e.g. 10.0.0.0/28).".to_string(),
            );
            risk_score += 45.0;
        }
        Some([o1, o2, o3, o4, prefix]) => {
            // Check IP octets validity
            if !((0..=255).contains(&o1)
                && (0..=255).contains(&o2)
                && (0..=255).contains(&o3)
                && (0..=255).contains(&o4))
            {
                is_cidr_valid = false;
                issues.push("IP address contains octets outside the 0-255 range.".to_string());
                risk_score += 45.0;
            }

            // Check prefix size (GCP VPC Access connector strictly requires /28)
            if prefix != 28 {
                is_cidr_valid = false;
                issues.push(format!(
                    "GCP Serverless VPC Access connector CIDR range must have a /28 prefix size (got /{prefix})."
                ));
                risk_score += 45.0;
            }

            // Check RFC 1918 private range allocation
            let mut is_rfc1918 = false;
            if o1 == 10 {
                is_rfc1918 = true;
            } else if o1 == 172 && (16..=31).contains(&o2) {
                is_rfc1918 = true;
            } else if o1 == 192 && o2 == 168 {
                is_rfc1918 = true;
            }

            if !is_rfc1918 {
                issues.push(format!(
                    "IP CIDR range '{ip_cidr_range}' is not in the private RFC 1918 address space."
                ));
                risk_score += 25.0;
            }
        }
    }

    risk_score = risk_score.min(100.0);
    let is_valid = is_name_valid && is_cidr_valid;

    let status = if !is_valid || risk_score > 60.0 {
        "FAIL".to_string()
    } else if risk_score >= 30.0 {
        "WARN".to_string()
    } else {
        "PASS".to_string()
    };

    Output {
        is_valid,
        issues,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = validate(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(name: &str, cidr: &str) -> Output {
        validate(&Input {
            connector_name: name.into(),
            ip_cidr_range: cidr.into(),
            network: "default".into(),
        })
    }

    #[test]
    fn clean_input_passes() {
        let o = run("my-connector", "10.8.0.0/28");
        assert!(o.is_valid);
        assert_eq!(o.status, "PASS");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.issues.is_empty());
    }

    #[test]
    fn bad_name_fails() {
        let o = run("Bad_Name", "10.8.0.0/28");
        assert!(!o.is_valid);
        assert_eq!(o.status, "FAIL");
        assert_eq!(o.risk_score, 35.0);
    }

    #[test]
    fn wrong_prefix_and_public_range() {
        // /24 prefix (+45), not RFC1918 (+25) => 70.0 => FAIL (cidr invalid)
        let o = run("conn", "8.8.8.8/24");
        assert!(!o.is_valid);
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.status, "FAIL");
    }

    #[test]
    fn private_but_wrong_prefix_only() {
        // RFC1918 ok, prefix /24 wrong (+45) => is_cidr_valid false => FAIL
        let o = run("conn", "192.168.1.0/24");
        assert!(!o.is_valid);
        assert_eq!(o.risk_score, 45.0);
        assert_eq!(o.status, "FAIL");
    }

    #[test]
    fn valid_name_public_28_warns() {
        // valid name, valid cidr /28 but public (+25) => is_valid true, 25 < 30 => PASS
        let o = run("conn", "8.8.8.0/28");
        assert!(o.is_valid);
        assert_eq!(o.risk_score, 25.0);
        assert_eq!(o.status, "PASS");
    }
}
