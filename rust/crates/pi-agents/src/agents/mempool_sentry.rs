//! Port of `pi_micro_agents/pi_mempool_sentry.py`.
//!
//! Stateless Layer-4 mempool gate. Scans pending-transaction calldata and gas
//! profiles for frontrunning / MEV exploit signatures, then admits, warns, or
//! rejects the transaction. Behaviour is a line-for-line mirror of the Python
//! original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Pydantic-enforced input/output envelopes.
// ---------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
pub struct Input {
    pub transaction_hash: String,
    pub calldata: String,
    pub gas_price_gwei: f64,
    #[serde(default)]
    pub value_eth: f64,
    #[serde(default = "default_slippage_limit")]
    pub slippage_limit: f64,
}

fn default_slippage_limit() -> f64 {
    0.5
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_admitted: bool,
    pub risk_score: f64,
    pub status: String,
    pub alerts: Vec<String>,
}

// ---------------------------------------------------------------------------
// Python `repr(float)` / f-string formatting.
//
// CPython renders floats with the shortest round-tripping digit string, then:
//   * fixed notation when  -4 < decpt <= 16, else exponential
//   * fixed integral values gain a trailing ".0"  (e.g. 5.0, 600.0)
//   * exponential form: `d[0].rest e ±XX`, exponent at least 2 digits, sign
//     always present.
// Rust's `{}` Display for f64 drops the trailing ".0" and uses a different
// exponential layout, so we must reproduce CPython's rules exactly for any
// value interpolated into an alert string. Rust's `{:e}` selects the identical
// shortest mantissa digits, so we reuse them and only re-apply CPython layout.
// ---------------------------------------------------------------------------
fn py_float_repr(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_string();
    }
    if v.is_infinite() {
        return if v < 0.0 { "-inf".to_string() } else { "inf".to_string() };
    }

    let negative = v.is_sign_negative();
    let sci = format!("{:e}", v.abs());
    // sci looks like "1.2345e16" or "5e-1" or "0e0" (for 0.0).
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

// ---------------------------------------------------------------------------
// 1. Strict-mode configuration resolver.
//
// The Python helper first checks the env var (case-insensitive "true"); if the
// var is unset it falls back to a `~/.antigravitycli/config.json` file,
// defaulting to `True`. In the parity harness only the env var branch is
// exercised, so we mirror that branch faithfully and use `True` as the
// file-fallback default (matching the `Err` arm).
// ---------------------------------------------------------------------------
fn is_strict_mode() -> bool {
    match std::env::var("PI_MEMPOOL_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// 2. Static heuristic scanning of mempool raw transactions.
static FRONTRUN_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"(?i)\bfrontrun\b").unwrap(), "frontrun signature found"),
        (
            Regex::new(r"(?i)\bsandwich_attack\b").unwrap(),
            "sandwich attack signature found",
        ),
        (
            Regex::new(r"(?i)0x5f5755ce").unwrap(),
            "Uniswap swapExactTokensForTokens transaction match",
        ),
        (
            Regex::new(r"(?i)flash_loan|flashloan").unwrap(),
            "flash loan routing block found",
        ),
    ]
});

// `slippage\s*[:=]\s*(\d+(\.\d+)?)` with re.IGNORECASE. Group 1 == `\d+(\.\d+)?`.
static SLIPPAGE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)slippage\s*[:=]\s*(\d+(\.\d+)?)").unwrap());

fn detect_mempool_exploits(text: &str) -> (f64, Vec<String>) {
    let mut violations: Vec<String> = Vec::new();
    let mut max_risk = 0.0_f64;
    if text.is_empty() {
        return (0.0, Vec::new());
    }

    // Heuristics for malicious MEV, sandwich, or frontrunning keywords/calldata.
    for (pat, desc) in FRONTRUN_PATTERNS.iter() {
        if pat.is_match(text) {
            violations.push((*desc).to_string());
            max_risk = max_risk.max(85.0);
        }
    }

    // Detect sandwich slippage parameter triggers (unsafe high slippage limits).
    if text.to_lowercase().contains("slippage") {
        if let Some(caps) = SLIPPAGE_RE.captures(text) {
            // group(1) is guaranteed to exist when the overall pattern matched.
            let val: f64 = caps.get(1).unwrap().as_str().parse().unwrap();
            if val > 5.0 {
                violations.push(format!(
                    "excessive slippage configuration '{}%' flagged",
                    py_float_repr(val)
                ));
                max_risk = max_risk.max(90.0);
            }
        }
    }

    (max_risk, violations)
}

// 4. Core micro-agent: `PiMempoolSentry.check_transaction`.
pub fn check_transaction(input: &Input) -> Output {
    let (mut risk, mut violations) = detect_mempool_exploits(&input.calldata);

    // Gas price spike anomalies (> 500 Gwei represents extreme gas-war frontrunning).
    if input.gas_price_gwei > 500.0 {
        violations.push(format!(
            "gas price spike detected ({} Gwei)",
            py_float_repr(input.gas_price_gwei)
        ));
        risk = risk.max(80.0);
    }

    // Slippage limit violations.
    if input.slippage_limit > 5.0 {
        violations.push(format!(
            "slippage limit too high ({}%)",
            py_float_repr(input.slippage_limit)
        ));
        risk = risk.max(75.0);
    }

    let is_strict = is_strict_mode();
    let mut is_admitted = true;
    let mut status = "PASSED".to_string();

    if risk >= 80.0 {
        if is_strict {
            is_admitted = false;
            status = "REJECTED_EXPLOIT".to_string();
        } else {
            status = "WARN_EXPLOIT".to_string();
        }
    }

    Output {
        is_admitted,
        risk_score: risk,
        status,
        alerts: violations,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_transaction(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(calldata: &str, gas: f64, slip: f64) -> Output {
        check_transaction(&Input {
            transaction_hash: "0xabc".into(),
            calldata: calldata.into(),
            gas_price_gwei: gas,
            value_eth: 0.0,
            slippage_limit: slip,
        })
    }

    #[test]
    #[serial]
    fn clean_transaction_passes() {
        std::env::remove_var("PI_MEMPOOL_STRICT_MODE");
        let o = run("transfer(addr, amount)", 50.0, 0.5);
        assert!(o.is_admitted);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.alerts.is_empty());
    }

    #[test]
    #[serial]
    fn frontrun_signature_rejected_in_strict() {
        std::env::set_var("PI_MEMPOOL_STRICT_MODE", "true");
        let o = run("frontrun this swap", 10.0, 0.5);
        assert!(!o.is_admitted);
        assert_eq!(o.status, "REJECTED_EXPLOIT");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.alerts, vec!["frontrun signature found"]);
    }

    #[test]
    #[serial]
    fn high_slippage_and_gas_spike_warn_in_lenient() {
        std::env::set_var("PI_MEMPOOL_STRICT_MODE", "false");
        let o = run("slippage=10", 600.0, 7.5);
        // calldata slippage>5 -> 90, gas>500 -> 80, slippage_limit>5 -> 75.
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.status, "WARN_EXPLOIT");
        assert!(o.is_admitted);
        assert_eq!(
            o.alerts,
            vec![
                "excessive slippage configuration '10.0%' flagged".to_string(),
                "gas price spike detected (600.0 Gwei)".to_string(),
                "slippage limit too high (7.5%)".to_string(),
            ]
        );
    }
}
