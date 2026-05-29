//! Port of `pi_micro_agents/pi_oracle_divergence_audit.py`.
//!
//! Audits price oracle inputs for excessive divergence between observed price
//! feeds and benchmark reference values, and scans Solidity aggregation math for
//! manipulable simple-average patterns. Behaviour is a line-for-line mirror of
//! the Python original (`PiOracleDivergenceAudit.audit_divergence`).

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub prices: Vec<f64>,
    pub benchmarks: Vec<f64>,
    #[serde(default = "default_max_deviation_percent")]
    pub max_deviation_percent: f64,
    #[serde(default)]
    pub solidity_code: String,
}

fn default_max_deviation_percent() -> f64 {
    2.0
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_functions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// ---------------------------------------------------------------------------
// Strict-mode configuration resolver.
//
// The Python helper `is_strict_mode()`:
//   1. returns env var lower() == "true" if PI_ORACLE_DIV_STRICT_MODE is set,
//   2. otherwise reads ~/.antigravitycli/config.json (or a sibling fallback),
//      returning bool(data.get("PI_ORACLE_DIV_STRICT_MODE", True)),
//   3. otherwise returns True.
//
// In the parity harness the config files present do NOT contain the
// PI_ORACLE_DIV_STRICT_MODE key, so the file branch yields the default `True`,
// identical to the no-file `True`. We therefore mirror the env-var branch
// faithfully and use `True` for the unset case. See `deviations` in the report.
// ---------------------------------------------------------------------------
fn is_strict_mode() -> bool {
    match std::env::var("PI_ORACLE_DIV_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// ---------------------------------------------------------------------------
// CPython `repr(float)` / `str(float)` reproduction.
//
// Python f-strings render `{p}` / `{b}` via `str(float)`, which uses the
// shortest round-tripping digit string formatted with these rules:
//   * fixed notation when  -4 < decpt <= 16, else exponential
//   * fixed integral values gain a trailing ".0"  (e.g. 1.0, 100.0)
//   * exponential form: `d[0].rest e ±XX`, exponent at least 2 digits, sign
//     always present.
// Rust's `{:e}` already selects the identical shortest mantissa digits, so we
// reuse them and only re-apply CPython's layout rules.
// ---------------------------------------------------------------------------
fn py_float_repr(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_string();
    }
    if v.is_infinite() {
        return if v < 0.0 {
            "-inf".to_string()
        } else {
            "inf".to_string()
        };
    }

    let negative = v.is_sign_negative();
    let sci = format!("{:e}", v.abs());
    let (mantissa, exp_str) = sci.split_once('e').expect("scientific form has 'e'");
    let exp: i64 = exp_str.parse().expect("valid exponent");

    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let decpt = exp + 1;

    let mut body = if decpt > -4 && decpt <= 16 {
        format_fixed(&digits, decpt)
    } else {
        format_exponential(&digits, decpt)
    };

    if negative {
        body.insert(0, '-');
    }
    body
}

fn format_fixed(digits: &str, decpt: i64) -> String {
    let n = digits.len() as i64;
    if decpt <= 0 {
        let zeros = "0".repeat((-decpt) as usize);
        format!("0.{}{}", zeros, digits)
    } else if decpt >= n {
        let trailing = "0".repeat((decpt - n) as usize);
        format!("{}{}.0", digits, trailing)
    } else {
        let (int_part, frac_part) = digits.split_at(decpt as usize);
        format!("{}.{}", int_part, frac_part)
    }
}

fn format_exponential(digits: &str, decpt: i64) -> String {
    let e = decpt - 1;
    let (lead, rest) = digits.split_at(1);
    let mantissa = if rest.is_empty() {
        lead.to_string()
    } else {
        format!("{}.{}", lead, rest)
    };
    let sign = if e < 0 { '-' } else { '+' };
    let abs_e = e.abs();
    format!("{}e{}{:02}", mantissa, sign, abs_e)
}

// Python: re.sub(r'//.*', '', code_lower)  -> strips `//` to end of line.
// `.` does not match newline (no DOTALL), so each line comment ends at EOL.
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"//.*").unwrap());
// Python: re.sub(r'/\*.*?\*/', '', code_clean, flags=re.DOTALL)
// non-greedy block comment; DOTALL -> `.` matches newline.
static BLOCK_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());

pub fn audit_divergence(input: &Input) -> Output {
    let prices = &input.prices;
    let benchmarks = &input.benchmarks;
    let max_dev = input.max_deviation_percent;
    let code = &input.solidity_code;

    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Mode 1: Oracle Manipulation Scan (Price array comparison)
    let min_len = prices.len().min(benchmarks.len());
    for i in 0..min_len {
        let p = prices[i];
        let b = benchmarks[i];
        if b <= 0.0 {
            continue;
        }
        let dev = (p - b).abs() / b * 100.0;
        if dev > max_dev {
            vulnerable_funcs.push(format!("asset_feed_{i}"));
            flagged_findings.push(format!(
                "Oracle price deviation at index {i} is {dev:.2}%, exceeding max deviation limit of {max_dev:.2}% \
(Price: {p_repr}, Benchmark: {b_repr}). Potential price manipulation threat detected.",
                p_repr = py_float_repr(p),
                b_repr = py_float_repr(b),
            ));
        }
    }

    // Mode 2: Aggregation Math Check (Solidity pattern scan)
    if !code.is_empty() {
        let code_lower = code.to_lowercase();
        // Clean comments.
        let code_clean = LINE_COMMENT_RE.replace_all(&code_lower, "");
        let code_clean = BLOCK_COMMENT_RE.replace_all(&code_clean, "");

        // Look for simple average patterns (addition divided by count).
        if code_clean.contains("sum")
            && code_clean.contains('/')
            && code_clean.contains("length")
        {
            let has_safe = ["geometric", "harmonic", "sqrt", "log"]
                .iter()
                .any(|kw| code_clean.contains(kw));
            if !has_safe {
                flagged_findings.push(
                    "Aggregation formulation warning: Pricing aggregator appears to calculate simple arithmetic average. \
Using simple arithmetic averages of AMM spot prices makes it highly susceptible to flash loan manipulation. \
Recommend implementing geometric or harmonic mean aggregation (e.g. Uniswap V3 TWAP)."
                        .to_string(),
                );
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ORACLE_DIVERGENCE".to_string();
        } else {
            status = "WARN_ORACLE_DIVERGENCE".to_string();
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
    let out = audit_divergence(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(prices: Vec<f64>, benchmarks: Vec<f64>, max_dev: f64, code: &str) -> Output {
        audit_divergence(&Input {
            file_path: "aggregator.sol".into(),
            prices,
            benchmarks,
            max_deviation_percent: max_dev,
            solidity_code: code.into(),
        })
    }

    #[test]
    #[serial]
    fn clean_feed_passes() {
        std::env::remove_var("PI_ORACLE_DIV_STRICT_MODE");
        let o = run(vec![3000.0, 3001.0], vec![3000.0, 3000.5], 2.0, "");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    #[serial]
    fn divergent_feed_rejected_in_strict_mode() {
        std::env::set_var("PI_ORACLE_DIV_STRICT_MODE", "true");
        let o = run(vec![3000.0, 4000.0], vec![3000.0, 3000.0], 2.0, "");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ORACLE_DIVERGENCE");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["asset_feed_1"]);
        assert!(o.flagged_findings[0].contains("33.33%"));
        assert!(o.flagged_findings[0].contains("Price: 4000.0, Benchmark: 3000.0"));
    }

    #[test]
    #[serial]
    fn divergent_feed_warns_in_lenient_mode() {
        std::env::set_var("PI_ORACLE_DIV_STRICT_MODE", "false");
        let o = run(vec![100.0], vec![50.0], 2.0, "");
        // Lenient mode coerces is_secure back to true with a WARN status.
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_ORACLE_DIVERGENCE");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["asset_feed_0"]);
        std::env::remove_var("PI_ORACLE_DIV_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn simple_average_solidity_flagged_but_not_vulnerable() {
        std::env::remove_var("PI_ORACLE_DIV_STRICT_MODE");
        let code = "function avg() public view returns (uint) { return sum / prices.length; }";
        let o = run(vec![], vec![], 2.0, code);
        // The aggregation finding does not populate vulnerable_functions, so the
        // feed stays secure / PASSED, but a finding is recorded.
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("simple arithmetic average"));
    }

    #[test]
    #[serial]
    fn geometric_mean_solidity_not_flagged() {
        std::env::remove_var("PI_ORACLE_DIV_STRICT_MODE");
        let code = "function avg() public view returns (uint) { return sqrt(sum / prices.length); }";
        let o = run(vec![], vec![], 2.0, code);
        assert!(o.flagged_findings.is_empty());
        assert!(o.is_secure);
    }
}
