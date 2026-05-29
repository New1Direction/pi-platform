//! Port of `pi_micro_agents/pi_automated_rotation_engine.py`.
//!
//! Automates lifecycle rotations for security credentials. The engine performs a
//! deterministic mock "secure rotation" and returns execution metadata. Behaviour
//! is a line-for-line mirror of the Python original (`PiAutomatedRotationEngine`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub credential_type: String,
    pub target_identifier: String,
}

#[derive(Debug, Serialize)]
pub struct Output {
    pub is_secure: bool,
    pub rotation_completed: bool,
    pub rotation_details: serde_json::Value,
    pub status: String,
}

/// Mirrors `PiAutomatedRotationEngine.rotate_credential`.
pub fn rotate_credential(input: &Input) -> Output {
    let cred_type = &input.credential_type;
    let target = &input.target_identifier;

    // Execute mock secure rotation.
    //
    // Python builds an insertion-ordered dict:
    //   {"target", "credential_type", "action", "version", "status"}
    // then sets details[target] = "rotated". We replicate that by inserting the
    // dynamic `target` key LAST so it overwrites any clashing fixed key exactly
    // as Python's dict assignment would.
    let mut details = serde_json::Map::new();
    details.insert(
        "target".to_string(),
        serde_json::Value::String(target.clone()),
    );
    details.insert(
        "credential_type".to_string(),
        serde_json::Value::String(cred_type.clone()),
    );
    details.insert(
        "action".to_string(),
        serde_json::Value::String("generated_new_secret".to_string()),
    );
    details.insert(
        "version".to_string(),
        serde_json::Value::String("v2".to_string()),
    );
    details.insert(
        "status".to_string(),
        serde_json::Value::String("active".to_string()),
    );

    // Make sure that target gets populated into details for consensus assertion
    // in the tests. NOTE: if `target` equals one of the fixed keys above, this
    // assignment overwrites that key's value with "rotated" (matching Python).
    details.insert(
        target.clone(),
        serde_json::Value::String("rotated".to_string()),
    );

    Output {
        is_secure: true,
        rotation_completed: true,
        rotation_details: serde_json::Value::Object(details),
        status: "COMPLETED".to_string(),
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = rotate_credential(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cred_type: &str, target: &str) -> Output {
        rotate_credential(&Input {
            credential_type: cred_type.into(),
            target_identifier: target.into(),
        })
    }

    #[test]
    fn basic_rotation_is_secure() {
        let o = run("AWS_KEY", "prod-key-1");
        assert!(o.is_secure);
        assert!(o.rotation_completed);
        assert_eq!(o.status, "COMPLETED");
        let d = o.rotation_details.as_object().unwrap();
        assert_eq!(d.get("target").unwrap(), "prod-key-1");
        assert_eq!(d.get("credential_type").unwrap(), "AWS_KEY");
        assert_eq!(d.get("action").unwrap(), "generated_new_secret");
        assert_eq!(d.get("version").unwrap(), "v2");
        assert_eq!(d.get("status").unwrap(), "active");
        // dynamic key populated
        assert_eq!(d.get("prod-key-1").unwrap(), "rotated");
        assert_eq!(d.len(), 6);
    }

    #[test]
    fn dynamic_target_key_overwrites_fixed_key() {
        // target collides with the fixed "status" key -> Python overwrites it.
        let o = run("DB_PASS", "status");
        let d = o.rotation_details.as_object().unwrap();
        // "status" now holds "rotated", not "active".
        assert_eq!(d.get("status").unwrap(), "rotated");
        // no extra key created since it collided.
        assert_eq!(d.len(), 5);
    }

    #[test]
    fn empty_strings_round_trip() {
        let o = run("", "");
        let d = o.rotation_details.as_object().unwrap();
        assert_eq!(d.get("credential_type").unwrap(), "");
        // empty-string target collides with nothing fixed, adds key "".
        assert_eq!(d.get("").unwrap(), "rotated");
        assert_eq!(o.status, "COMPLETED");
    }
}
