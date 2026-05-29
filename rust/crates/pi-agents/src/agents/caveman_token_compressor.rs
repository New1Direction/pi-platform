//! Port of `pi_micro_agents/pi_caveman_token_compressor.py`.
//!
//! Deterministic micro-agent that strips greetings, filler, and verbose
//! boilerplate from a conversational text payload, then reports a compression
//! ratio. Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub text_payload: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub compressed_text: String,
    pub compression_ratio: f64,
    pub status: String,
}

// Greeting / filler patterns, applied sequentially with `re.IGNORECASE`.
// Each is a word-boundary anchored phrase; no lookaround/backreferences are
// used, so the Rust `regex` crate is byte-compatible with Python's `re`.
// `\b` is ASCII-word-boundary in both engines and all phrases are ASCII, so
// boundary semantics match exactly.
static GREETINGS: Lazy<Vec<Regex>> = Lazy::new(|| {
    let pats = [
        r"\bhello\b",
        r"\bhi\b",
        r"\bhey\b",
        r"\bgreetings\b",
        r"\bhope this finds you well\b",
        r"\bhow are you\b",
        r"\bplease\b",
        r"\bthank you\b",
        r"\bthanks\b",
        r"\bcould you\b",
        r"\bi would like to\b",
        r"\bkindly\b",
        r"\bso\b",
        r"\bactually\b",
        r"\bjust\b",
    ];
    pats.iter()
        // re.IGNORECASE -> (?i)
        .map(|p| Regex::new(&format!("(?i){p}")).unwrap())
        .collect()
});

// re.sub(r"\s+", " ", compressed). No IGNORECASE flag. `\s` is Unicode-aware in
// both Python's `re` (str patterns) and the Rust `regex` crate by default.
static WS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

/// Mirror of Python `round(x, 4)`: correctly-rounded round-half-to-even on the
/// underlying f64. Rust's `{:.4}` formatter is itself correctly rounded
/// (round-half-to-even), so formatting to 4 decimals and re-parsing reproduces
/// CPython's `round` byte-for-byte for every value tested.
fn round4(x: f64) -> f64 {
    format!("{x:.4}").parse::<f64>().unwrap()
}

pub fn compress_tokens(input: &Input) -> Output {
    let text = &input.text_payload;

    // if not text:  -> empty string is falsy in Python.
    if text.is_empty() {
        return Output {
            is_secure: true,
            compressed_text: String::new(),
            compression_ratio: 1.0,
            status: "PASSED".to_string(),
        };
    }

    // Strip greetings: sequential re.sub over the list, IGNORECASE.
    let mut compressed = text.clone();
    for greet in GREETINGS.iter() {
        compressed = greet.replace_all(&compressed, "").into_owned();
    }

    // Clean extra whitespace: collapse runs of whitespace to a single space,
    // then strip().
    let collapsed = WS_RE.replace_all(&compressed, " ").into_owned();
    let compressed = pyutil::strip(&collapsed).to_string();

    // Python `len()` counts unicode code points, not bytes.
    let orig_len = text.chars().count();
    let comp_len = compressed.chars().count();
    let ratio = if orig_len > 0 {
        comp_len as f64 / orig_len as f64
    } else {
        1.0
    };

    let is_secure = true;
    let status = "PASSED".to_string();

    Output {
        is_secure,
        compressed_text: compressed,
        compression_ratio: round4(ratio),
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = compress_tokens(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> Output {
        compress_tokens(&Input {
            text_payload: text.into(),
        })
    }

    #[test]
    fn empty_payload_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.compressed_text, "");
        assert_eq!(o.compression_ratio, 1.0);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn strips_greetings_and_filler() {
        // "hello, could you please just send the report, thanks"
        let o = run("hello, could you please just send the report, thanks");
        // greetings/filler removed, whitespace collapsed, stripped.
        // Confirmed against the Python original.
        assert_eq!(o.compressed_text, ", send the report,");
        assert_eq!(o.compression_ratio, 0.3462);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn dense_text_keeps_high_ratio() {
        let o = run("deploy build artifact xyz");
        // no greetings present -> only whitespace normalization
        assert_eq!(o.compressed_text, "deploy build artifact xyz");
        assert_eq!(o.compression_ratio, 1.0);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn round4_matches_python() {
        assert_eq!(round4(0.42857142857142855), 0.4286);
        assert_eq!(round4(0.12345), 0.1235);
        assert_eq!(round4(0.00025), 0.0003);
    }
}
