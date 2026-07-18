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
    /// Server `message` (customizable per app) for both success and sealed failure.
    pub message: String,
    pub status: Option<String>,
    pub expires_at: Option<String>,
    /// License subscription tier (≥ 0). Defaults to `0` when absent.
    pub subscription_tier: i64,
    pub timestamp: i64,
}

/// Options for [`crate::Client::register`].
#[derive(Debug, Clone)]
pub struct RegisterOptions {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub license_key: Option<String>,
    pub hwid: Option<String>,
}

/// Options for [`crate::Client::login`].
#[derive(Debug, Clone)]
pub struct LoginOptions {
    pub username: String,
    pub password: String,
    pub hwid: Option<String>,
}

/// Options for [`crate::Client::upgrade`] (username + license key only; no password).
#[derive(Debug, Clone)]
pub struct UpgradeOptions {
    pub username: String,
    pub license_key: String,
    pub hwid: Option<String>,
}

/// User object returned by client auth success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthUser {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub application_id: String,
}

/// License object returned by client auth success (`null` when unlinked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthLicense {
    pub id: String,
    pub status: String,
    pub expires_at: Option<String>,
    pub subscription_tier: i64,
}

/// Session metadata returned by client auth success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthSession {
    pub ip: Option<String>,
    pub hwid: Option<String>,
}

/// Success result of `register` / `login` / `upgrade` (plaintext client auth).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthResult {
    pub success: bool,
    pub session_token: String,
    pub expires_at: String,
    pub user: ClientAuthUser,
    pub license: Option<ClientAuthLicense>,
    pub session: ClientAuthSession,
}
