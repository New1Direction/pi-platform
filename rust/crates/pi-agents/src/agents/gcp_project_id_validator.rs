//! Port of `pi_micro_agents/pi_gcp_project_id_validator.py`.
//!
//! Validates a GCP project ID against Google Cloud naming rules and naming
//! conventions. Behaviour is a line-for-line mirror of the Python original.
//!
//! NOTE: the Python module defines `is_strict_mode()` (reading the env var
//! `PI_GCPPROJECTIDVALIDATOR_STRICT_MODE`) but `execute` NEVER calls it, so the
//! env var has no effect on output. We therefore do not read any env var here.
//! See `deviations` in the parity report.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
pub struct Input {
    pub project_id: String,
    #[serde(default = "default_strict_naming")]
    pub strict_naming: bool,
}

fn default_strict_naming() -> bool {
    true
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_valid: bool,
    pub length: i64,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// `^[a-z]` — must START with a lowercase letter (re.match anchors at start).
static RE_STARTS_LOWER: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z]").unwrap());
// `[^a-z0-9\-]` — any char that is NOT a lowercase letter, digit, or hyphen.
static RE_INVALID_CHAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^a-z0-9\-]").unwrap());
// `^[0-9]+$` — entirely digits (re.match anchors at start, `$` at end).
static RE_ALL_DIGITS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9]+$").unwrap());

/// GCP project IDs that look like reserved/generic environment names.
/// Stored sorted for the message (`sorted(_GENERIC_NAMES)`); membership tests
/// below use the set semantics directly.
const GENERIC_NAMES: [&str; 5] = ["demo", "dev", "prod", "staging", "test"];

fn is_generic_name(s: &str) -> bool {
    GENERIC_NAMES.contains(&s)
}

/// Reproduce Python's `repr()` of a SINGLE character exactly.
///
/// Rules (CPython unicode repr):
///  - normally wrapped in single quotes: `'a'`
///  - if the char is a single quote `'` and there is no double quote, the repr
///    uses double quotes: `"'"`
///  - backslash is doubled: `'\\'`
///  - `\t`, `\n`, `\r` use their short escapes
///  - non-printable chars use `\xNN` (<=0xff), `\uNNNN` (<=0xffff), `\UNNNNNNNN`
///  - printable chars (per Python `str.isprintable`) pass through verbatim
fn py_repr_char(c: char) -> String {
    // Choose quote char: Python uses single quotes unless the string contains a
    // single quote but no double quote. For a single-char string that is `'`,
    // the quote becomes `"`.
    let quote = if c == '\'' { '"' } else { '\'' };

    let body = match c {
        '\\' => "\\\\".to_string(),
        '\t' => "\\t".to_string(),
        '\n' => "\\n".to_string(),
        '\r' => "\\r".to_string(),
        c if c == quote => format!("\\{c}"),
        c if is_py_printable(c) => c.to_string(),
        c => {
            let cp = c as u32;
            if cp <= 0xff {
                format!("\\x{cp:02x}")
            } else if cp <= 0xffff {
                format!("\\u{cp:04x}")
            } else {
                format!("\\U{cp:08x}")
            }
        }
    };
    format!("{quote}{body}{quote}")
}

/// Best-effort replication of Python `str.isprintable()` for a single char.
///
/// Python: a char is printable iff it is NOT in Unicode general categories
/// "Other" (Cc, Cf, Cs, Co, Cn) or "Separator" (Zl, Zp, Zs), EXCEPT that ASCII
/// space (0x20) is considered printable.
///
/// We implement the ASCII range exactly. For non-ASCII we approximate: ASCII
/// space is printable, the common C/Z control & separator codepoints we know of
/// are treated as non-printable, and everything else is treated as printable.
/// This matches CPython for all ASCII inputs and for the listed codepoints.
fn is_py_printable(c: char) -> bool {
    let cp = c as u32;
    if cp == 0x20 {
        return true; // ASCII space is printable
    }
    if cp < 0x20 || cp == 0x7f {
        return false; // ASCII control chars
    }
    if cp < 0x7f {
        return true; // remaining printable ASCII
    }
    // Non-ASCII: known control/format/separator codepoints are non-printable.
    !matches!(
        cp,
        0x80..=0x9f      // C1 controls
            | 0xa0       // no-break space (Zs)
            | 0xad       // soft hyphen (Cf)
            | 0x1680     // ogham space mark (Zs)
            | 0x2000..=0x200a // various spaces (Zs)
            | 0x2028     // line separator (Zl)
            | 0x2029     // paragraph separator (Zp)
            | 0x202f     // narrow no-break space (Zs)
            | 0x205f     // medium mathematical space (Zs)
            | 0x3000     // ideographic space (Zs)
            | 0x200b..=0x200f // zero-width / directional format chars (Cf)
            | 0x2060..=0x2064 // word joiner / invisible operators (Cf)
            | 0xfeff     // BOM / zero-width no-break space (Cf)
            | 0xfff9..=0xfffb // interlinear annotation (Cf)
    )
}

pub fn execute(input: &Input) -> Output {
    let project_id = &input.project_id;
    let strict_naming = input.strict_naming;

    let mut issues: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;
    // Python len() counts Unicode code points, not bytes.
    let length: i64 = project_id.chars().count() as i64;

    // --- Length check: 6-30 chars ---
    if length < 6 {
        issues.push(format!(
            "Project ID is too short ({length} chars). Minimum length is 6 characters."
        ));
        risk_score += 25.0;
    } else if length > 30 {
        issues.push(format!(
            "Project ID is too long ({length} chars). Maximum length is 30 characters."
        ));
        risk_score += 25.0;
    }

    // --- Must start with a lowercase letter ---
    // `if project_id and not re.match(r"^[a-z]", project_id):`
    if !project_id.is_empty() && !RE_STARTS_LOWER.is_match(project_id) {
        let first = project_id.chars().next().unwrap();
        issues.push(format!(
            "Project ID must start with a lowercase letter [a-z]. Got: '{first}'."
        ));
        risk_score += 25.0;
    }

    // --- Only [a-z0-9-] allowed ---
    // `set(re.findall(r"[^a-z0-9\-]", project_id))`
    let mut invalid_chars: BTreeSet<char> = BTreeSet::new();
    for m in RE_INVALID_CHAR.find_iter(project_id) {
        // each match is a single character
        if let Some(ch) = m.as_str().chars().next() {
            invalid_chars.insert(ch);
        }
    }
    if !invalid_chars.is_empty() {
        // `', '.join(sorted(repr(c) for c in invalid_chars))`
        let mut reprs: Vec<String> = invalid_chars.iter().map(|&c| py_repr_char(c)).collect();
        reprs.sort();
        let joined = reprs.join(", ");
        issues.push(format!(
            "Project ID contains invalid character(s): {joined}. \
Only lowercase letters, digits, and hyphens are allowed."
        ));
        risk_score += 25.0;
    }

    // --- No consecutive hyphens ---
    if project_id.contains("--") {
        issues.push("Project ID must not contain consecutive hyphens ('--').".to_string());
        risk_score += 25.0;
    }

    // --- No leading hyphens ---
    if project_id.starts_with('-') {
        issues.push("Project ID must not start with a hyphen.".to_string());
        risk_score += 25.0;
    }

    // --- No trailing hyphens ---
    if project_id.ends_with('-') {
        issues.push("Project ID must not end with a hyphen.".to_string());
        risk_score += 25.0;
    }

    // --- Must not be all numbers ---
    // `if project_id and re.match(r"^[0-9]+$", project_id):`
    if !project_id.is_empty() && RE_ALL_DIGITS.is_match(project_id) {
        issues.push(
            "Project ID must not consist entirely of digits; \
it must contain at least one letter."
                .to_string(),
        );
        risk_score += 25.0;
    }

    // --- Convention warnings (optional, strict_naming) ---
    // `if strict_naming and project_id.lower() in _GENERIC_NAMES:`
    if strict_naming && is_generic_name(&project_id.to_lowercase()) {
        // `', '.join(sorted(_GENERIC_NAMES))` -> GENERIC_NAMES already sorted.
        let generic_joined = GENERIC_NAMES.join(", ");
        issues.push(format!(
            "Project ID '{project_id}' matches a reserved/generic environment name \
({generic_joined}). Use a more descriptive, unique project ID."
        ));
        risk_score += 10.0;
    }

    // --- Determine is_valid (no structural violations) ---
    let structural_issues_count = issues
        .iter()
        .filter(|iss| !iss.contains("generic environment name"))
        .count();
    let is_valid = structural_issues_count == 0;

    // --- Cap risk score ---
    risk_score = risk_score.min(100.0);

    // --- Determine status ---
    let status = if !is_valid || risk_score > 60.0 {
        "FAIL".to_string()
    } else if risk_score >= 10.0 {
        "WARN".to_string()
    } else {
        "PASS".to_string()
    };

    Output {
        is_valid,
        length,
        issues,
        risk_score: py_round2(risk_score),
        status,
    }
}

/// Python `round(x, 2)` — banker's rounding (round-half-to-even).
fn py_round2(x: f64) -> f64 {
    let scaled = x * 100.0;
    let floor = scaled.floor();
    let diff = scaled - floor;
    let rounded = if diff > 0.5 {
        floor + 1.0
    } else if diff < 0.5 {
        floor
    } else {
        // exactly halfway -> round to even
        if (floor as i64) % 2 == 0 {
            floor
        } else {
            floor + 1.0
        }
    };
    rounded / 100.0
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = execute(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(project_id: &str, strict_naming: bool) -> Output {
        execute(&Input {
            project_id: project_id.into(),
            strict_naming,
        })
    }

    #[test]
    fn clean_id_passes() {
        let o = run("my-valid-project-1", true);
        assert!(o.is_valid);
        assert_eq!(o.status, "PASS");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.issues.is_empty());
        assert_eq!(o.length, 18);
    }

    #[test]
    fn too_short_and_invalid_chars_fails() {
        // "Ab!" -> too short (3), not starting lowercase (A), invalid chars 'A','b'? no:
        // invalid chars are those NOT in [a-z0-9-]: 'A' and '!'
        let o = run("Ab!", true);
        assert!(!o.is_valid);
        assert_eq!(o.length, 3);
        assert_eq!(o.status, "FAIL");
        // too short (25) + not lowercase start (25) + invalid chars (25) = 75
        assert_eq!(o.risk_score, 75.0);
        // invalid chars repr sorted: '!' (0x21) then 'A' (0x41)
        let invalid_issue = o
            .issues
            .iter()
            .find(|i| i.contains("invalid character"))
            .unwrap();
        assert!(invalid_issue.contains("'!', 'A'"));
    }

    #[test]
    fn generic_name_warns() {
        let o = run("test", true);
        // "test" is 4 chars -> too short (structural) => is_valid false, FAIL
        assert!(!o.is_valid);
        assert_eq!(o.status, "FAIL");
        // contains the generic warning
        assert!(o.issues.iter().any(|i| i.contains("generic environment name")));
    }

    #[test]
    fn staging_generic_only_warns() {
        // "staging" is 7 chars, all valid, lowercase start -> only generic warn
        let o = run("staging", true);
        assert!(o.is_valid); // generic warning is not a structural issue
        assert_eq!(o.risk_score, 10.0);
        assert_eq!(o.status, "WARN");
    }

    #[test]
    fn all_digits_fails() {
        let o = run("123456", true);
        assert!(!o.is_valid);
        assert!(o.issues.iter().any(|i| i.contains("entirely of digits")));
    }

    #[test]
    fn py_repr_char_basics() {
        assert_eq!(py_repr_char('A'), "'A'");
        assert_eq!(py_repr_char('\''), "\"'\"");
        assert_eq!(py_repr_char('\\'), "'\\\\'");
        assert_eq!(py_repr_char(' '), "' '");
        assert_eq!(py_repr_char('.'), "'.'");
        assert_eq!(py_repr_char('\t'), "'\\t'");
        assert_eq!(py_repr_char('\u{0}'), "'\\x00'");
        assert_eq!(py_repr_char('\u{2028}'), "'\\u2028'");
    }

    #[test]
    fn py_round2_bankers() {
        assert_eq!(py_round2(10.0), 10.0);
        assert_eq!(py_round2(100.0), 100.0);
        assert_eq!(py_round2(0.0), 0.0);
    }
}
