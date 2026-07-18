//! Official Rust client for the SDKey license authentication protocol.
//!
//! Implements the sealed session protocol: Ed25519-verified handshake,
//! HKDF session keys, and AES-256-GCM validate envelopes, plus plaintext
//! client auth (register / login / upgrade). See `PROTOCOL.md`.

pub mod client;
pub mod crypto;
pub mod errors;
pub mod types;

pub use client::Client;
pub use errors::{SdkeyError, SdkeyErrorCode};
pub use types::{
    ClientAuthLicense, ClientAuthResult, ClientAuthSession, ClientAuthUser, HttpPost, LoginOptions,
    RegisterOptions, SessionState, UpgradeOptions, ValidateResult,
};

pub use crypto::constants::{
    AES_GCM_IV_BYTES, CLIENT_NONCE_BYTES, CLOCK_SKEW_SECONDS, PROTOCOL_VERSION,
    SERVER_NONCE_BYTES, SESSION_AES_KEY_BYTES, SESSION_HKDF_INFO_PREFIX, VALIDATE_FAILURE_CODES,
    VALIDATE_NONCE_BYTES,
};
pub use crypto::encoding::{base64_to_bytes, bytes_to_base64};
pub use crypto::{canonical_json, canonicalize};
pub use crypto::{
    derive_session_aes_key, import_public_key, open_aes_gcm, seal_aes_gcm, verify_signature,
    verify_signature_value, SealedEnvelope,
};
