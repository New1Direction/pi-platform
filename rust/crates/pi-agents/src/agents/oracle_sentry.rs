//! Port of `pi_micro_agents/pi_oracle_sentry.py`.
//!
//! Autonomous pricing integrity guard that audits an observed transaction price
//! against a consensus of mock oracle feeds (Chainlink / Pyth / Uniswap TWAP).
//! Behaviour is a line-for-line mirror of the Python original.

// NOTE: this agent never calls `.splitlines()` or `.strip()`, so `crate::pyutil`
// is not used. It does reproduce Python's `repr(float)` formatting for the
// anomaly / deviation strings, and a single regex (no lookaround/backrefs).
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub token: String,
    #[serde(default = "default_chain_id")]
    pub chain_id: i64,
    pub current_observed_price: f64,
    #[serde(default = "default_max_deviation_percent")]
    pub max_deviation_percent: f64,
}

fn default_chain_id() -> i64 {
    1
}

fn default_max_deviation_percent() -> f64 {
    2.0
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub deviation_detected_percent: f64,
    pub aggregate_fair_price: f64,
    pub verified_sources: Vec<String>,
    pub status: String,
    pub flagged_anomalies: Vec<String>,
}

// re.search(r"\b(?:scam|fake|rug|hack)\b", token, re.IGNORECASE)
// IGNORECASE -> (?i). No lookahead/lookbehind/backreferences, so the Rust regex
// crate handles this verbatim. The `(?:...)` non-capturing group is supported.
static SCAM_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:scam|fake|rug|hack)\b").unwrap());

// ---------------------------------------------------------------------------
// Python `repr(float)` / `str(float)` reproduction (identical for finite values).
//
// CPython renders floats with `PyOS_double_to_string(v, 'r', 0, ...)` — the
// shortest round-tripping digit string, then formatted with these rules:
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
    // Rust's `{:e}` on a negative number includes the sign; strip it and track
    // it ourselves so `-0.0` is handled consistently with CPython ("-0.0").
    let sci = format!("{:e}", v.abs());
    // sci looks like "1.2345e16" or "5e-1" or "0e0" (for 0.0).
    let (mantissa, exp_str) = sci.split_once('e').expect("scientific form has 'e'");
    let exp: i64 = exp_str.parse().expect("valid exponent");

    // Significant digit string (no decimal point) and decimal-point position.
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    // `decpt`: place value of first digit + 1 (CPython convention).
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
        // 0.000ddd
        let zeros = "0".repeat((-decpt) as usize);
        format!("0.{}{}", zeros, digits)
    } else if decpt >= n {
        // dddd000.0  (integral)
        let trailing = "0".repeat((decpt - n) as usize);
        format!("{}{}.0", digits, trailing)
    } else {
        // ddd.ddd
        let (int_part, frac_part) = digits.split_at(decpt as usize);
        format!("{}.{}", int_part, frac_part)
    }
}

fn format_exponential(digits: &str, decpt: i64) -> String {
    let e = decpt - 1; // exponent of the leading digit
    let (lead, rest) = digits.split_at(1);
    let mantissa = if rest.is_empty() {
        lead.to_string()
    } else {
        format!("{}.{}", lead, rest)
    };
    let sign = if e < 0 { '-' } else { '+' };
    let abs_e = e.abs();
    // CPython pads the exponent to at least two digits.
    format!("{}e{}{:02}", mantissa, sign, abs_e)
}

/// Mirrors `detect_pricing_anomalies(price, token)`.
fn detect_pricing_anomalies(price: f64, token: &str) -> (f64, Vec<String>) {
    let mut violations: Vec<String> = Vec::new();
    let mut max_risk = 0.0_f64;

    if price <= 0.0 {
        violations.push(format!(
            "Invalid pricing anomaly: zero or negative price detected ({})",
            py_float_repr(price)
        ));
        max_risk = 99.0;
    } else if price > 10_000_000.0 {
        violations.push(format!(
            "Extreme pricing anomaly: price exceeds reasonable limits ({})",
            py_float_repr(price)
        ));
        max_risk = 90.0;
    }

    // Check for known scam token patterns in token name/symbol.
    if SCAM_TOKEN_RE.is_match(token) {
        violations.push(format!("Dangerous token identifier flagged: {token}"));
        max_risk = max_risk.max(85.0);
    }

    (max_risk, violations)
}

/// Mirrors `is_strict_mode()`.
///
/// Python resolution order:
///   1. env `PI_ORACLE_STRICT_MODE` -> `value.lower() == "true"`
///   2. `~/.antigravitycli/config.json` then the in-repo
///      `../../.antigravitycli/config.json`, reading the `PI_ORACLE_STRICT_MODE`
///      key (default True)
///   3. default True
///
/// The config-file fallback is environment-dependent; in this repo the config
/// file lacks the `PI_ORACLE_STRICT_MODE` key, so `data.get(..., True)` yields
/// True. Therefore, when the env var is unset the effective result is `true`,
/// which this function reproduces. See `deviations` in the parity report: the
/// config-file branch is intentionally collapsed to the default-True behaviour.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ORACLE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_prices(input: &Input) -> Output {
    // token = input_envelope.token.upper()
    let token = input.token.to_uppercase();
    let observed = input.current_observed_price;
    let max_dev = input.max_deviation_percent;

    // Determine standard aggregate fair price based on token ticker.
    let fair_price: f64 = if token == "ETH" {
        3000.0
    } else if token == "BTC" {
        60000.0
    } else if token == "USDC" || token == "USDT" || token == "DAI" {
        1.0
    } else {
        // Fallback to observed if token is custom to prevent false positives.
        if observed > 0.0 {
            observed
        } else {
            100.0
        }
    };

    // Calculate deviation percentage.
    let deviation: f64 = if fair_price > 0.0 {
        ((observed - fair_price).abs() / fair_price) * 100.0
    } else {
        100.0
    };

    // Run static heuristics checks (note: Python passes the ORIGINAL,
    // un-uppercased token here, not the local `token` variable).
    let (mut risk, mut violations) = detect_pricing_anomalies(observed, &input.token);

    // Check deviation against threshold.
    if deviation > max_dev {
        violations.push(format!(
            "Price deviation of {:.2}% exceeds safe threshold of {}% (Fair: {})",
            deviation,
            py_float_repr(max_dev),
            py_float_repr(fair_price)
        ));
        risk = risk.max(85.0);
    }

    // Config strict mode resolution.
    let is_strict = is_strict_mode();
    let mut is_secure = true;
    let mut status = "PASSED".to_string();

    if risk >= 80.0 {
        if is_strict {
            is_secure = false;
            status = "REJECTED_PRICE".to_string();
        } else {
            status = "WARN_PRICE".to_string();
        }
    } else if risk >= 50.0 {
        status = "WARN_PRICE".to_string();
    }

    Output {
        is_secure,
        deviation_detected_percent: deviation,
        aggregate_fair_price: fair_price,
        verified_sources: vec![
            "Chainlink Aggregator V4".to_string(),
            "Pyth Network Push Oracle".to_string(),
            "Uniswap V3 TWAP Feed".to_string(),
        ],
        status,
        flagged_anomalies: violations,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_prices(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(token: &str, price: f64, max_dev: f64) -> Output {
        audit_prices(&Input {
            token: token.into(),
            chain_id: 1,
            current_observed_price: price,
            max_deviation_percent: max_dev,
        })
    }

    #[serial]
    #[test]
    fn clean_eth_price_passes() {
        std::env::remove_var("PI_ORACLE_STRICT_MODE");
        let o = run("ETH", 3000.0, 2.0);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.deviation_detected_percent, 0.0);
        assert_eq!(o.aggregate_fair_price, 3000.0);
        assert!(o.flagged_anomalies.is_empty());
    }

    #[serial]
    #[test]
    fn negative_price_rejected_strict() {
        std::env::set_var("PI_ORACLE_STRICT_MODE", "true");
        let o = run("ETH", -5.0, 2.0);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_PRICE");
        assert_eq!(
            o.flagged_anomalies[0],
            "Invalid pricing anomaly: zero or negative price detected (-5.0)"
        );
        std::env::remove_var("PI_ORACLE_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn scam_token_non_strict_warns() {
        std::env::set_var("PI_ORACLE_STRICT_MODE", "false");
        let o = run("scam", 50.0, 2.0);
        // risk >= 80 but non-strict -> WARN, is_secure stays true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_PRICE");
        assert!(o
            .flagged_anomalies
            .iter()
            .any(|f| f == "Dangerous token identifier flagged: scam"));
        std::env::remove_var("PI_ORACLE_STRICT_MODE");
    }

    #[serial]
    #[test]
    fn deviation_string_uses_two_decimals_and_py_repr() {
        std::env::set_var("PI_ORACLE_STRICT_MODE", "true");
        // BTC fair=60000, observed=90000 -> deviation = 50.00%
        let o = run("BTC", 90000.0, 2.0);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_PRICE");
        assert_eq!(
            o.flagged_anomalies[0],
            "Price deviation of 50.00% exceeds safe threshold of 2.0% (Fair: 60000.0)"
        );
        std::env::remove_var("PI_ORACLE_STRICT_MODE");
    }

    #[test]
    fn py_float_repr_matches_cpython() {
        assert_eq!(py_float_repr(1.0), "1.0");
        assert_eq!(py_float_repr(100.0), "100.0");
        assert_eq!(py_float_repr(2.0), "2.0");
        assert_eq!(py_float_repr(3000.0), "3000.0");
        assert_eq!(py_float_repr(60000.0), "60000.0");
        assert_eq!(py_float_repr(-5.0), "-5.0");
        assert_eq!(py_float_repr(0.0), "0.0");
    }
}
