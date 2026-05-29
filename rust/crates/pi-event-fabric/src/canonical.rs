//! Canonical JSON serialization byte-identical to CPython's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
//!
//! This is the parity linchpin: the event bus hashes events as
//! `sha256(canonical(header) + canonical(payload))`, so the Rust string must
//! match Python's bytes exactly — sorted keys, compact separators, and
//! ASCII-escaped non-ASCII (incl. surrogate pairs for astral code points).
//!
//! Escaping correctness is verified end-to-end by the cross-language parity
//! harness (`rust/parity/event_fabric_parity.py`) with diverse unicode/control
//! payloads, which is stronger than hand-written assertions.

use serde_json::Value;

/// Serialize a JSON value exactly like Python's
/// `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub fn dumps_canonical(v: &Value) -> String {
    let mut s = String::new();
    write_value(v, &mut s);
    s
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                out.push_str(&py_float_repr(f));
            } else {
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => write_string_ascii(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // sort_keys=True: keys sorted by Unicode code point (== UTF-8 byte
            // order for valid UTF-8, == Python str comparison).
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string_ascii(k, out);
                out.push(':');
                write_value(&map[*k], out);
            }
            out.push('}');
        }
    }
}

/// String escaping matching Python's `py_encode_basestring_ascii`
/// (ensure_ascii=True): escapes `"` `\`, the short forms `\b \f \n \r \t`,
/// other control chars and all non-ASCII as `\uXXXX` (lowercase hex), with
/// surrogate pairs for code points above U+FFFF.
fn write_string_ascii(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            // printable ASCII space (0x20) .. tilde (0x7e), minus those above
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    let v = cp - 0x10000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// CPython `repr(float)` / `json.dumps(float)` for FINITE floats: shortest
/// round-tripping digits, fixed notation when `-4 < decpt <= 16` else
/// scientific with a signed >=2-digit exponent; integral values get `.0`.
/// (NaN/Infinity can't round-trip through serde_json::Number, so finite-only.)
fn py_float_repr(v: f64) -> String {
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
        format!("0.{}{}", "0".repeat((-decpt) as usize), digits)
    } else if decpt >= n {
        format!("{}{}.0", digits, "0".repeat((decpt - n) as usize))
    } else {
        let (int_part, frac_part) = digits.split_at(decpt as usize);
        format!("{int_part}.{frac_part}")
    }
}

fn format_exponential(digits: &str, decpt: i64) -> String {
    let e = decpt - 1;
    let (lead, rest) = digits.split_at(1);
    let mantissa = if rest.is_empty() {
        lead.to_string()
    } else {
        format!("{lead}.{rest}")
    };
    let sign = if e < 0 { '-' } else { '+' };
    format!("{}e{}{:02}", mantissa, sign, e.abs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn float_repr_matches_python_json() {
        assert_eq!(dumps_canonical(&json!(0.1)), "0.1");
        assert_eq!(dumps_canonical(&json!(1.5)), "1.5");
        assert_eq!(dumps_canonical(&json!(100.0)), "100.0");
        assert_eq!(dumps_canonical(&json!(1e-7)), "1e-07");
        assert_eq!(dumps_canonical(&json!(1e20)), "1e+20");
        assert_eq!(dumps_canonical(&json!(-2.25)), "-2.25");
    }

    #[test]
    fn sorts_keys_and_compacts() {
        let v = json!({"b": 1, "a": 2, "c": [3, 2, 1]});
        assert_eq!(dumps_canonical(&v), r#"{"a":2,"b":1,"c":[3,2,1]}"#);
    }

    #[test]
    fn primitives_and_simple_escapes() {
        assert_eq!(dumps_canonical(&json!(null)), "null");
        assert_eq!(dumps_canonical(&json!(true)), "true");
        assert_eq!(dumps_canonical(&json!(-7)), "-7");
        // backslash and quote
        assert_eq!(dumps_canonical(&json!("a\\b")).contains("\\\\"), true);
        assert_eq!(dumps_canonical(&json!("a\"b")).contains("\\\""), true);
        // non-ASCII becomes \u escape (ensure_ascii) — no raw non-ASCII byte
        let out = dumps_canonical(&json!("caf\u{e9}"));
        assert!(out.contains("\\u00e9"));
        assert!(out.is_ascii());
        // astral -> surrogate pair
        let emoji = dumps_canonical(&json!("\u{1f600}"));
        assert!(emoji.contains("\\ud83d\\ude00"));
    }
}
