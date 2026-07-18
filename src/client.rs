//! SDKey license client (sealed session protocol).

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use rand::RngCore;
use serde_json::{json, Map, Value};

use crate::crypto::constants::{
    CLIENT_NONCE_BYTES, CLOCK_SKEW_SECONDS, PROTOCOL_VERSION, VALIDATE_NONCE_BYTES,
};
use crate::crypto::encoding::{base64_to_bytes, bytes_to_base64};
use crate::crypto::seal::{
    derive_session_aes_key, import_public_key, open_aes_gcm, seal_aes_gcm, verify_signature_value,
};
use crate::errors::{SdkeyError, SdkeyErrorCode};
use crate::types::{HttpPost, SessionState, ValidateResult};

/// Default HTTPS JSON POST using `ureq`.
fn default_http_post(
    url: &str,
    body: &Value,
) -> Result<(u16, Value), Box<dyn std::error::Error + Send + Sync>> {
    match ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
    {
        Ok(response) => {
            let status = response.status();
            let parsed: Value = response
                .into_json()
                .unwrap_or(Value::Object(Default::default()));
            Ok((status, parsed))
        }
        Err(ureq::Error::Status(code, response)) => {
            let parsed: Value = response
                .into_json()
                .unwrap_or(Value::Object(Default::default()));
            Ok((code, parsed))
        }
        Err(err) => Err(Box::new(err)),
    }
}

/// SDKey license client.
///
/// Flow: `init()` (session handshake) → `validate(license_key, hwid)` (sealed request).
/// `validate` calls `init` automatically when no session exists.
pub struct Client {
    api_base_url: String,
    app_id: String,
    app_version: String,
    app_public_key_b64: String,
    http_post: HttpPost,
    public_key: Option<VerifyingKey>,
    session: Option<SessionState>,
}

impl Client {
    /// Create a client. Trailing slashes on `api_base_url` are stripped.
    ///
    /// `app_version` is sent as `clientVersion` and must exactly match the app's configured version.
    pub fn new(
        api_base_url: impl Into<String>,
        app_id: impl Into<String>,
        app_version: impl Into<String>,
        app_public_key_b64: impl Into<String>,
    ) -> Self {
        Self::with_http_post(
            api_base_url,
            app_id,
            app_version,
            app_public_key_b64,
            Box::new(default_http_post),
        )
    }

    /// Create a client with an injectable HTTP POST (for tests / custom transport).
    pub fn with_http_post(
        api_base_url: impl Into<String>,
        app_id: impl Into<String>,
        app_version: impl Into<String>,
        app_public_key_b64: impl Into<String>,
        http_post: HttpPost,
    ) -> Self {
        Self {
            api_base_url: api_base_url.into().trim_end_matches('/').to_string(),
            app_id: app_id.into(),
            app_version: app_version.into(),
            app_public_key_b64: app_public_key_b64.into(),
            http_post,
            public_key: None,
            session: None,
        }
    }

    /// Active session, if any.
    pub fn get_session(&self) -> Option<&SessionState> {
        self.session.as_ref()
    }

    /// Drop the current session (next `validate` will re-init).
    pub fn clear_session(&mut self) {
        self.session = None;
    }

    /// Challenge handshake; verifies the signed hello; derives the AES session key.
    pub fn init(&mut self) -> Result<&SessionState, SdkeyError> {
        let public_key = import_public_key(&self.app_public_key_b64).map_err(|_| {
            SdkeyError::new(SdkeyErrorCode::InitFailed, "invalid app public key")
        })?;
        self.public_key = Some(public_key);

        let mut client_nonce = [0u8; CLIENT_NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut client_nonce);

        let url = format!("{}/api/v1/session/init", self.api_base_url);
        let body = json!({
            "appId": self.app_id,
            "clientNonceB64": bytes_to_base64(&client_nonce),
            "clientVersion": self.app_version,
        });

        let (status, body) = (self.http_post)(&url, &body).map_err(|cause| {
            SdkeyError::with_source(
                SdkeyErrorCode::Network,
                "session init request failed",
                cause,
            )
        })?;

        let success = body.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        if !(200..300).contains(&status) || !success {
            return Err(plaintext_failure(
                SdkeyErrorCode::InitFailed,
                &body,
                "session init failed",
            ));
        }

        let hkdf_salt_b64 = required_str(&body, "hkdfSaltB64", SdkeyErrorCode::InitFailed)?;
        let server_nonce_b64 = required_str(&body, "serverNonceB64", SdkeyErrorCode::InitFailed)?;
        let session_id = required_str(&body, "sessionId", SdkeyErrorCode::InitFailed)?;
        let timestamp = body
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                SdkeyError::new(SdkeyErrorCode::InitFailed, "missing hello timestamp")
            })?;
        let signature_b64 = required_str(&body, "signatureB64", SdkeyErrorCode::InitFailed)?;

        let hello = json!({
            "appId": self.app_id,
            "hkdfSaltB64": hkdf_salt_b64,
            "serverNonceB64": server_nonce_b64,
            "sessionId": session_id,
            "timestamp": timestamp,
            "v": PROTOCOL_VERSION,
        });

        let public_key = self.public_key.as_ref().unwrap();
        if !verify_signature_value(public_key, &hello, signature_b64) {
            return Err(SdkeyError::new(
                SdkeyErrorCode::HelloSignatureInvalid,
                "hello signature verification failed",
            ));
        }

        let server_nonce =
            base64_to_bytes(server_nonce_b64).map_err(|_| {
                SdkeyError::new(SdkeyErrorCode::InitFailed, "invalid serverNonceB64")
            })?;
        let aes_key = derive_session_aes_key(
            &client_nonce,
            &server_nonce,
            hkdf_salt_b64,
            &self.app_id,
        )
        .map_err(|_| SdkeyError::new(SdkeyErrorCode::InitFailed, "session key derivation failed"))?;

        self.session = Some(SessionState {
            session_id: session_id.to_string(),
            aes_key,
            server_nonce_b64: server_nonce_b64.to_string(),
            hkdf_salt_b64: hkdf_salt_b64.to_string(),
        });
        Ok(self.session.as_ref().unwrap())
    }

    /// Sealed validate; always decrypts then verifies Ed25519 before trusting `success`.
    ///
    /// `hwid` is optional — omit (`None`) for web clients so the server skips HWID checks.
    /// License denials return `Ok(ValidateResult { success: false, ... })`.
    /// Protocol / transport failures return `Err(SdkeyError)`.
    pub fn validate(
        &mut self,
        license_key: &str,
        hwid: Option<&str>,
    ) -> Result<ValidateResult, SdkeyError> {
        if self.session.is_none() || self.public_key.is_none() {
            self.init()?;
        }
        let session = self.session.as_ref().unwrap().clone();
        let public_key = *self.public_key.as_ref().unwrap();

        let mut validate_nonce = [0u8; VALIDATE_NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut validate_nonce);
        let now = unix_now();

        let mut inner = Map::new();
        if let Some(hwid) = hwid {
            inner.insert("hwid".to_string(), Value::String(hwid.to_string()));
        }
        inner.insert("licenseKey".to_string(), Value::String(license_key.to_string()));
        inner.insert(
            "nonce".to_string(),
            Value::String(bytes_to_base64(&validate_nonce)),
        );
        inner.insert("timestamp".to_string(), Value::Number(now.into()));
        inner.insert("v".to_string(), Value::Number(PROTOCOL_VERSION.into()));

        let plaintext = serde_json::to_vec(&Value::Object(inner)).map_err(|e| {
            SdkeyError::with_source(SdkeyErrorCode::Unknown, "serialize validate payload failed", e)
        })?;
        let sealed = seal_aes_gcm(&session.aes_key, &plaintext).map_err(|_| {
            SdkeyError::new(SdkeyErrorCode::Unknown, "seal validate request failed")
        })?;

        let mut envelope_body = sealed.as_wire();
        envelope_body.insert(
            "sessionId".to_string(),
            Value::String(session.session_id.clone()),
        );
        let url = format!("{}/api/v1/licenses/validate", self.api_base_url);
        let request_body = Value::Object(envelope_body);

        let (_status, envelope) = (self.http_post)(&url, &request_body).map_err(|cause| {
            SdkeyError::with_source(SdkeyErrorCode::Network, "validate request failed", cause)
        })?;

        let iv_b64 = envelope.get("ivB64").and_then(|v| v.as_str());
        let ciphertext_b64 = envelope.get("ciphertextB64").and_then(|v| v.as_str());
        let tag_b64 = envelope.get("tagB64").and_then(|v| v.as_str());
        let signature_b64 = envelope.get("signatureB64").and_then(|v| v.as_str());

        if iv_b64.is_none()
            || ciphertext_b64.is_none()
            || tag_b64.is_none()
            || signature_b64.is_none()
        {
            if envelope.get("code").and_then(|v| v.as_str()) == Some("SESSION_EXPIRED") {
                self.clear_session();
            }
            return Err(plaintext_failure(
                SdkeyErrorCode::ValidateResponseInvalid,
                &envelope,
                "invalid validate response",
            ));
        }

        let sealed_env = crate::crypto::SealedEnvelope {
            iv_b64: iv_b64.unwrap().to_string(),
            ciphertext_b64: ciphertext_b64.unwrap().to_string(),
            tag_b64: tag_b64.unwrap().to_string(),
        };
        let plain_bytes = open_aes_gcm(&session.aes_key, &sealed_env).map_err(|_| {
            SdkeyError::new(
                SdkeyErrorCode::ValidateResponseInvalid,
                "decrypt validate response failed",
            )
        })?;
        let plaintext: Value = serde_json::from_slice(&plain_bytes).map_err(|_| {
            SdkeyError::new(
                SdkeyErrorCode::ValidateResponseInvalid,
                "invalid validate plaintext JSON",
            )
        })?;

        if !verify_signature_value(&public_key, &plaintext, signature_b64.unwrap()) {
            return Err(SdkeyError::new(
                SdkeyErrorCode::ResponseSignatureInvalid,
                "response signature verification failed",
            ));
        }

        let resp_session_id = plaintext.get("sessionId").and_then(|v| v.as_str());
        if resp_session_id != Some(session.session_id.as_str()) {
            return Err(SdkeyError::new(
                SdkeyErrorCode::SessionMismatch,
                "sessionId mismatch",
            ));
        }

        let timestamp = plaintext
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                SdkeyError::new(
                    SdkeyErrorCode::ValidateResponseInvalid,
                    "missing response timestamp",
                )
            })?;
        if (unix_now() - timestamp).abs() > CLOCK_SKEW_SECONDS {
            return Err(SdkeyError::new(
                SdkeyErrorCode::ClockSkew,
                "response clock skew",
            ));
        }

        if plaintext.get("code").and_then(|v| v.as_str()) == Some("SESSION_EXPIRED") {
            self.clear_session();
        }

        Ok(ValidateResult {
            success: plaintext
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            code: plaintext
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            message: plaintext
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            status: plaintext
                .get("status")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            expires_at: plaintext.get("expiresAt").and_then(|v| {
                if v.is_null() {
                    None
                } else {
                    v.as_str().map(str::to_string)
                }
            }),
            subscription_tier: plaintext
                .get("subscriptionTier")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
            timestamp,
        })
    }
}

fn plaintext_failure(
    code: SdkeyErrorCode,
    body: &Value,
    fallback: impl Into<String>,
) -> SdkeyError {
    let message = body
        .get("error")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| fallback.into());
    let server_code = body
        .get("code")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    SdkeyError::with_server_code(code, message, server_code)
}

fn required_str<'a>(
    body: &'a Value,
    key: &str,
    code: SdkeyErrorCode,
) -> Result<&'a str, SdkeyError> {
    body.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| SdkeyError::new(code, format!("missing {key}")))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
