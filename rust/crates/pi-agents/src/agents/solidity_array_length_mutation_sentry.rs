//! Port of `pi_micro_agents/pi_solidity_array_length_mutation_sentry.py`.
//!
//! Audits Solidity contracts for unsafe inline-assembly or direct manual
//! mutations of array lengths. Behaviour is a line-for-line mirror of the
//! Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub solidity_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_functions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Python: re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// No DOTALL on the whole pattern -> `.` does not match newline (matches Rust default).
// `[\s\S]` explicitly matches any char incl. newline.
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Python: re.search(r'\.[a-zA-Z0-9_]+\.length\s*[-+=\/]?=', body)
static DIRECT_LENGTH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.[a-zA-Z0-9_]+\.length\s*[-+=/]?=").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ARRAY_LENGTH_MUTATION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_array_length_mutation(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions: captures_iter mirrors re.findall with 3 groups.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // args (group 2) is captured by Python but never used in the loop body.
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Look for assembly block modifying array length, or direct .length mutation.
        let has_assembly_mutation = body.contains("assembly")
            && body.contains("sstore")
            && (body.contains("length") || body.contains("len"));
        let has_direct_length_assignment = DIRECT_LENGTH_RE.is_match(body);

        if has_assembly_mutation || has_direct_length_assignment {
            vulnerable_funcs.push(name.to_string());
            flagged_findings.push(format!(
                "Function '{name}' modifies the length of an array directly or inside assembly. \
Manually mutating array lengths can bypass array boundary checks, leading to out-of-bounds storage corruption or memory overflow exploits."
            ));
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ARRAY_LENGTH_MUTATION".to_string();
        } else {
            status = "WARN_ARRAY_LENGTH_MUTATION".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_functions: vulnerable_funcs,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_array_length_mutation(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_array_length_mutation(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("function safe(uint x) public { uint y = x + 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn direct_length_assignment_flagged() {
        let o = run("function shrink() public { state.arr.length = 0; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ARRAY_LENGTH_MUTATION");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["shrink"]);
    }

    #[test]
    fn assembly_mutation_flagged() {
        let o = run(
            "function grow() public {\n  assembly {\n    sstore(arr.slot, length)\n  }\n}",
        );
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["grow"]);
    }
}
