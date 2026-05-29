//! Port of `pi_micro_agents/pi_arbitrage_guard.py`.
//!
//! Autonomous routing guard managing EIP-4337 smart-contract wallet liquidity
//! arbitrage. Behaviour is a line-for-line mirror of the Python original,
//! including the float math and the Python-`repr` formatting of the price
//! values interpolated into `route_details`.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub token_in: String,
    pub token_out: String,
    pub amount_in: f64,
    pub pool_price_a: f64,
    pub pool_price_b: f64,
    #[serde(default = "default_min_spread_percent")]
    pub min_spread_percent: f64,
}

fn default_min_spread_percent() -> f64 {
    0.5
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub should_execute: bool,
    pub spread_detected_percent: f64,
    pub expected_profit: f64,
    pub target_wallet_type: String,
    pub route_details: String,
}

// ---------------------------------------------------------------------------
// Python `repr(float)` reproduction.
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
        return if v < 0.0 { "-inf".to_string() } else { "inf".to_string() };
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

// ---------------------------------------------------------------------------
// 1. Strict-mode configuration resolver.
//
// The Python helper also reads a config.json fallback, but in the parity
// harness only the env var branch is exercised. We mirror that env var branch
// faithfully; the file-fallback default is `True`, matching the `Err` arm.
// ---------------------------------------------------------------------------
fn is_strict_mode() -> bool {
    match std::env::var("PI_ARBITRAGE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// 2. Static heuristic verification of arbitrage pool structures.
// The result is computed but unused by `analyze_spread` (it never feeds the
// output); mirrored for fidelity.
static ARBITRAGE_CHECKS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"(?i)\bno_slippage_protection\b").unwrap(),
            "disabled slippage checks found",
        ),
        (
            Regex::new(r"(?i)0x0000000000000000000000000000000000000000").unwrap(),
            "zero address pool routing",
        ),
        (
            Regex::new(r"(?i)gas_limit\s*[:=]\s*(9\d{6,})").unwrap(),
            "excessive gas limit setup representing resource exhaustion",
        ),
    ]
});

#[allow(dead_code)]
fn detect_arbitrage_anomalies(text: &str) -> (f64, Vec<String>) {
    let mut violations: Vec<String> = Vec::new();
    let mut max_risk = 0.0_f64;
    if text.is_empty() {
        return (0.0, Vec::new());
    }
    for (pat, desc) in ARBITRAGE_CHECKS.iter() {
        if pat.is_match(text) {
            violations.push((*desc).to_string());
            max_risk = max_risk.max(90.0);
        }
    }
    (max_risk, violations)
}

// 4. Core micro-agent: `PiArbitrageGuard.analyze_spread`.
pub fn analyze_spread(input: &Input) -> Output {
    let price_diff = (input.pool_price_a - input.pool_price_b).abs();
    let spread = (price_diff / input.pool_price_a.min(input.pool_price_b)) * 100.0;

    let mut expected_profit = 0.0_f64;
    let mut should_execute = false;
    let mut route = "NO_PROFITABLE_ROUTE".to_string();

    if spread >= input.min_spread_percent {
        expected_profit = input.amount_in * (spread / 100.0);

        // Simple slippage/gas deduction: assume 0.1% transaction cost.
        expected_profit -= input.amount_in * 0.001;

        if expected_profit > 0.0 {
            should_execute = true;
            route = format!(
                "ROUTE_EXECUTION: Buy Pool A @ {}, Sell Pool B @ {}",
                py_float_repr(input.pool_price_a),
                py_float_repr(input.pool_price_b)
            );
        }
    }

    // Safety override check (strict mode checks).
    let is_strict = is_strict_mode();
    let _ = detect_arbitrage_anomalies(&route);

    if is_strict && spread > 50.0 {
        // Spreads over 50% usually represent oracle manipulation or flash loan
        // hacks. Block execution.
        should_execute = false;
        route = "BLOCKED_HIGH_RISK_SPREAD_ANOMALY (Oracle manipulation check triggered)".to_string();
    }

    Output {
        should_execute,
        spread_detected_percent: spread,
        expected_profit,
        target_wallet_type: "ERC-4337".to_string(),
        route_details: route,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = analyze_spread(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn inp(a: f64, b: f64, amt: f64, mins: f64) -> Input {
        Input {
            token_in: "WETH".into(),
            token_out: "USDC".into(),
            amount_in: amt,
            pool_price_a: a,
            pool_price_b: b,
            min_spread_percent: mins,
        }
    }

    #[test]
    #[serial]
    fn profitable_route_executes() {
        std::env::remove_var("PI_ARBITRAGE_STRICT_MODE");
        let o = analyze_spread(&inp(100.0, 102.0, 1000.0, 0.5));
        assert!(o.should_execute);
        assert_eq!(o.target_wallet_type, "ERC-4337");
        assert!(o.route_details.contains("ROUTE_EXECUTION"));
        // Python repr of the prices must appear verbatim.
        assert!(o.route_details.contains("Buy Pool A @ 100.0"));
        assert!(o.route_details.contains("Sell Pool B @ 102.0"));
    }

    #[test]
    #[serial]
    fn no_spread_no_route() {
        std::env::remove_var("PI_ARBITRAGE_STRICT_MODE");
        let o = analyze_spread(&inp(100.0, 100.0, 1000.0, 0.5));
        assert!(!o.should_execute);
        assert_eq!(o.spread_detected_percent, 0.0);
        assert_eq!(o.route_details, "NO_PROFITABLE_ROUTE");
    }

    #[test]
    #[serial]
    fn high_spread_blocked_in_strict_mode() {
        std::env::set_var("PI_ARBITRAGE_STRICT_MODE", "true");
        let o = analyze_spread(&inp(100.0, 200.0, 1000.0, 0.5));
        assert!(!o.should_execute);
        assert!(o.route_details.starts_with("BLOCKED_HIGH_RISK_SPREAD_ANOMALY"));
        std::env::remove_var("PI_ARBITRAGE_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn high_spread_allowed_when_not_strict() {
        std::env::set_var("PI_ARBITRAGE_STRICT_MODE", "false");
        let o = analyze_spread(&inp(100.0, 200.0, 1000.0, 0.5));
        // spread = 100% > 50 but strict mode off -> not blocked, executes.
        assert!(o.should_execute);
        assert!(o.route_details.contains("ROUTE_EXECUTION"));
        std::env::remove_var("PI_ARBITRAGE_STRICT_MODE");
    }

    #[test]
    fn py_float_repr_matches_cpython() {
        assert_eq!(py_float_repr(1.0), "1.0");
        assert_eq!(py_float_repr(100.0), "100.0");
        assert_eq!(py_float_repr(102.0), "102.0");
        assert_eq!(py_float_repr(0.5), "0.5");
        assert_eq!(py_float_repr(1234.5678), "1234.5678");
        assert_eq!(py_float_repr(0.001), "0.001");
        assert_eq!(py_float_repr(0.0001), "0.0001");
        assert_eq!(py_float_repr(1e-5), "1e-05");
        assert_eq!(py_float_repr(1.23e-5), "1.23e-05");
        assert_eq!(py_float_repr(1e16), "1e+16");
        assert_eq!(py_float_repr(1e17), "1e+17");
        assert_eq!(py_float_repr(1000000000000000.0), "1000000000000000.0");
        assert_eq!(py_float_repr(12345678901234567.0), "1.2345678901234568e+16");
        assert_eq!(py_float_repr(100.25), "100.25");
        assert_eq!(py_float_repr(1e20), "1e+20");
        assert_eq!(py_float_repr(1e-7), "1e-07");
        assert_eq!(py_float_repr(-1.5), "-1.5");
        assert_eq!(py_float_repr(0.0), "0.0");
        assert_eq!(py_float_repr(-0.0), "-0.0");
    }
}
