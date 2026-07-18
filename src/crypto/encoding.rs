//! Base64 helpers (standard and URL-safe).

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Encode raw bytes as standard base64 (no URL-safe alphabet).
pub fn bytes_to_base64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode standard or URL-safe base64 (padding optional).
pub fn base64_to_bytes(b64: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let normalized = b64.replace('-', "+").replace('_', "/");
    let pad = match normalized.len() % 4 {
        0 => String::new(),
        n => "=".repeat(4 - n),
    };
    STANDARD.decode(format!("{normalized}{pad}"))
}
