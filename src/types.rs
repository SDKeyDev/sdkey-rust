//! Public types for the SDKey client.

use serde_json::Value;

/// `(url, json_body) -> (status_code, response_json)` HTTP POST callback.
///
/// On transport failure, return `Err` — the client maps that to [`crate::SdkeyError`]
/// with code `NETWORK`.
pub type HttpPost = Box<
    dyn Fn(&str, &Value) -> Result<(u16, Value), Box<dyn std::error::Error + Send + Sync>>
        + Send
        + Sync,
>;

/// Active sealed session after a successful `init`.
#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_id: String,
    pub aes_key: [u8; 32],
    pub server_nonce_b64: String,
    pub hkdf_salt_b64: String,
}

/// Result of a sealed license validate (success or application denial).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateResult {
    pub success: bool,
    pub code: String,
    pub message: String,
    pub status: Option<String>,
    pub expires_at: Option<String>,
    pub timestamp: i64,
}
