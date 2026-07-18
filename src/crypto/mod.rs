//! Crypto helpers for the SDKey sealed session protocol.

pub mod canonical_json;
pub mod constants;
pub mod encoding;
pub mod seal;

pub use canonical_json::{canonical_json, canonicalize};
pub use encoding::{base64_to_bytes, bytes_to_base64};
pub use seal::{
    derive_session_aes_key, import_public_key, open_aes_gcm, seal_aes_gcm, verify_signature,
    SealedEnvelope,
};
