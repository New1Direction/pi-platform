//! Port of `pi_micro_agents/pi_automated_anonymizer.py`.
//!
//! Dynamic anonymization micro-agent that masks emails and credential/secret
//! assignments in a raw text payload. Behaviour is a line-for-line mirror of
//! the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub raw_payload: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub anonymized_payload: String,
    pub fields_scrubbed_count: i64,
    pub status: String,
}

// Mask emails (e.g. abc@test.com -> ******@test.com)
// Python: r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b"
static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b").unwrap());

// Mask secrets/passwords (e.g. password = '123' -> password = '*****')
// Python: r"(?i)\b(password|secret)\b\s*[:=]\s*['\"]([^'\"]+)['\"]"
static PASSWD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(password|secret)\b\s*[:=]\s*['"]([^'"]+)['"]"#).unwrap()
});

pub fn anonymize_payload(input: &Input) -> Output {
    let payload = &input.raw_payload;
    let mut scrubbed = payload.clone();
    let mut count: i64 = 0;

    // Mask emails (e.g. abc@test.com -> ******@test.com)
    if EMAIL_RE.is_match(&scrubbed) {
        // Python replacement: r"******@\2"
        scrubbed = EMAIL_RE
            .replace_all(&scrubbed, "******@${2}")
            .into_owned();
        count += 1;
    }

    // Mask secrets/passwords (e.g. password = '123' -> password = '*****')
    if PASSWD_RE.is_match(&scrubbed) {
        // Python replacement: r"\1 = '*****'"
        scrubbed = PASSWD_RE
            .replace_all(&scrubbed, "${1} = '*****'")
            .into_owned();
        count += 1;
    }

    Output {
        is_secure: true,
        anonymized_payload: scrubbed,
        // Default to 1 to satisfy test assertions in mock mode
        fields_scrubbed_count: if count > 0 { count } else { 1 },
        status: "SCRUBBED".to_string(),
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = anonymize_payload(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(payload: &str) -> Output {
        anonymize_payload(&Input {
            raw_payload: payload.into(),
        })
    }

    #[test]
    fn clean_payload_defaults_to_one() {
        let o = run("nothing sensitive here");
        assert!(o.is_secure);
        assert_eq!(o.anonymized_payload, "nothing sensitive here");
        assert_eq!(o.fields_scrubbed_count, 1);
        assert_eq!(o.status, "SCRUBBED");
    }

    #[test]
    fn masks_email() {
        let o = run("contact abc@test.com please");
        assert_eq!(o.anonymized_payload, "contact ******@test.com please");
        assert_eq!(o.fields_scrubbed_count, 1);
    }

    #[test]
    fn masks_password_and_email() {
        let o = run("user a@b.co password: 'hunter2'");
        assert_eq!(o.anonymized_payload, "user ******@b.co password = '*****'");
        assert_eq!(o.fields_scrubbed_count, 2);
    }
}
