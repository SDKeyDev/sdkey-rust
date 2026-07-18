//! Deterministic JSON encoding for Ed25519 signing.
//!
//! Object keys sorted lexicographically, no insignificant whitespace.
//! Does not escape `/` (matches Python `json.dumps` / JS `JSON.stringify`).

use serde_json::Value;

/// Encode `value` as canonical JSON UTF-8 bytes.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    Ok(canonicalize(value)?.into_bytes())
}

/// Encode `value` as a canonical JSON string.
pub fn canonicalize(value: &Value) -> Result<String, CanonicalJsonError> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(if *b {
            "true".to_string()
        } else {
            "false".to_string()
        }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                return Ok(i.to_string());
            }
            if let Some(u) = n.as_u64() {
                return Ok(u.to_string());
            }
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(CanonicalJsonError::NonFiniteNumber);
                }
                // Match JSON.stringify / Python json.dumps for finite floats.
                return Ok(serde_json::to_string(&Value::Number(n.clone())).unwrap());
            }
            Err(CanonicalJsonError::UnsupportedNumber)
        }
        Value::String(s) => Ok(escape_json_string(s)),
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonicalize(item)?);
            }
            out.push(']');
            Ok(out)
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&escape_json_string(key));
                out.push(':');
                out.push_str(&canonicalize(&map[*key])?);
            }
            out.push('}');
            Ok(out)
        }
    }
}

/// Escape a string as a JSON string literal without escaping `/`.
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Errors from canonical JSON encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalJsonError {
    NonFiniteNumber,
    UnsupportedNumber,
}

impl std::fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonFiniteNumber => write!(f, "canonicalJson: non-finite numbers are not allowed"),
            Self::UnsupportedNumber => write!(f, "canonicalJson: unsupported number"),
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_lexicographically() {
        assert_eq!(
            canonicalize(&json!({"b": 1, "a": 2})).unwrap(),
            r#"{"a":2,"b":1}"#
        );
    }

    #[test]
    fn encodes_null_fields() {
        assert_eq!(
            canonicalize(&json!({"a": 1, "b": null})).unwrap(),
            r#"{"a":1,"b":null}"#
        );
    }

    #[test]
    fn encodes_nested_structures_without_whitespace() {
        assert_eq!(
            canonicalize(&json!({"z": [true, null, "x"], "m": {"k": 0}})).unwrap(),
            r#"{"m":{"k":0},"z":[true,null,"x"]}"#
        );
    }

    #[test]
    fn returns_utf8_bytes() {
        let bytes = canonical_json(&json!({"a": 1})).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), r#"{"a":1}"#);
    }

    #[test]
    fn does_not_escape_solidus() {
        assert_eq!(
            canonicalize(&json!("https://example.com/a")).unwrap(),
            r#""https://example.com/a""#
        );
    }
}
