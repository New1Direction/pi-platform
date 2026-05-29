//! Port of `pi_micro_agents/pi_data_flow_privacy_mapper.py`.
//!
//! Specialized Data Flow Integrity Auditor: maps compliance across secured
//! database and untrusted boundaries. Behaviour is a line-for-line mirror of
//! the Python original. No env vars and no regex are involved.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub data_sources: Vec<String>,
    pub data_destinations: Vec<String>,
    /// Python: `List[Dict[str, str]]`. We mirror as a list of string maps so
    /// `.get("from", "")` / `.get("to", "")` semantics carry over.
    pub flow_connections: Vec<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub unsecured_flows: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `PiDataFlowPrivacyMapper.map_data_privacy_flows`.
pub fn map_data_privacy_flows(input: &Input) -> Output {
    let connections = &input.flow_connections;
    let mut unsecured: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    for conn in connections {
        // conn.get("from", "") / conn.get("to", "")
        let frm: &str = conn.get("from").map(|s| s.as_str()).unwrap_or("");
        let to: &str = conn.get("to").map(|s| s.as_str()).unwrap_or("");

        // If sensitive data source flows to an untrusted external endpoint
        let frm_lower = frm.to_lowercase();
        let to_lower = to.to_lowercase();
        if (frm_lower.contains("db") || frm_lower.contains("user"))
            && (to_lower.contains("untrusted") || to_lower.contains("external"))
        {
            unsecured.push(format!("{frm} -> {to}"));
            risk_score += 40.0;
        }
    }

    // risk_score = min(risk_score, 100.0)
    risk_score = risk_score.min(100.0);
    let is_secure = risk_score < 40.0;
    let status = if is_secure { "PASSED" } else { "COMPROMISED" }.to_string();

    Output {
        is_secure,
        unsecured_flows: unsecured,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = map_data_privacy_flows(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn conn(from: &str, to: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("from".to_string(), from.to_string());
        m.insert("to".to_string(), to.to_string());
        m
    }

    fn run(conns: Vec<HashMap<String, String>>) -> Output {
        map_data_privacy_flows(&Input {
            data_sources: vec![],
            data_destinations: vec![],
            flow_connections: conns,
        })
    }

    #[test]
    fn clean_flow_passes() {
        let o = run(vec![conn("user_db", "analytics_warehouse")]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.unsecured_flows.is_empty());
    }

    #[test]
    fn single_unsecured_flow_compromised() {
        let o = run(vec![conn("user_db", "untrusted_partner")]);
        assert!(!o.is_secure);
        assert_eq!(o.status, "COMPROMISED");
        assert_eq!(o.risk_score, 40.0);
        assert_eq!(o.unsecured_flows, vec!["user_db -> untrusted_partner"]);
    }

    #[test]
    fn risk_score_caps_at_100() {
        let o = run(vec![
            conn("db1", "external1"),
            conn("db2", "external2"),
            conn("user3", "untrusted3"),
            conn("db4", "external4"),
        ]);
        // 4 * 40 = 160, capped to 100
        assert_eq!(o.risk_score, 100.0);
        assert!(!o.is_secure);
        assert_eq!(o.unsecured_flows.len(), 4);
    }

    #[test]
    fn empty_connections_pass() {
        let o = run(vec![]);
        assert!(o.is_secure);
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.status, "PASSED");
    }
}
