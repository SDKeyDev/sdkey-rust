//! Ed25519, HKDF session keys, and AES-GCM seal helpers.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;

use super::canonical_json::canonical_json;
use super::constants::{AES_GCM_IV_BYTES, AES_GCM_TAG_BYTES, SESSION_AES_KEY_BYTES, SESSION_HKDF_INFO_PREFIX};
use super::encoding::{base64_to_bytes, bytes_to_base64};

/// Import an Ed25519 verifying key from base64-encoded raw 32-byte public key.
pub fn import_public_key(public_key_b64: &str) -> Result<VerifyingKey, SealError> {
    let bytes = base64_to_bytes(public_key_b64).map_err(|_| SealError::InvalidPublicKey)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| SealError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| SealError::InvalidPublicKey)
}

/// Verify an Ed25519 signature over canonical JSON of `payload`.
pub fn verify_signature<T: Serialize>(
    public_key: &VerifyingKey,
    payload: &T,
    signature_b64: &str,
) -> bool {
    let value = match serde_json::to_value(payload) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verify_signature_value(public_key, &value, signature_b64)
}

/// Verify an Ed25519 signature over canonical JSON of a JSON value.
pub fn verify_signature_value(
    public_key: &VerifyingKey,
    payload: &Value,
    signature_b64: &str,
) -> bool {
    let Ok(message) = canonical_json(payload) else {
        return false;
    };
    let Ok(sig_bytes) = base64_to_bytes(signature_b64) else {
        return false;
    };
    let Ok(arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&arr);
    public_key.verify(&message, &signature).is_ok()
}

/// Derive the 32-byte AES session key via HKDF-SHA256.
pub fn derive_session_aes_key(
    client_nonce: &[u8],
    server_nonce: &[u8],
    salt_b64: &str,
    app_id: &str,
) -> Result<[u8; SESSION_AES_KEY_BYTES], SealError> {
    let mut ikm = Vec::with_capacity(client_nonce.len() + server_nonce.len());
    ikm.extend_from_slice(client_nonce);
    ikm.extend_from_slice(server_nonce);
    let salt = base64_to_bytes(salt_b64).map_err(|_| SealError::InvalidBase64)?;
    let info = format!("{SESSION_HKDF_INFO_PREFIX}{app_id}");
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; SESSION_AES_KEY_BYTES];
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|_| SealError::HkdfExpandFailed)?;
    Ok(okm)
}

/// AES-GCM sealed envelope with separate IV / ciphertext / tag (wire format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedEnvelope {
    pub iv_b64: String,
    pub ciphertext_b64: String,
    pub tag_b64: String,
}

impl SealedEnvelope {
    /// Wire fields for the validate request/response envelope.
    pub fn as_wire(&self) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("ivB64".to_string(), Value::String(self.iv_b64.clone()));
        map.insert(
            "ciphertextB64".to_string(),
            Value::String(self.ciphertext_b64.clone()),
        );
        map.insert("tagB64".to_string(), Value::String(self.tag_b64.clone()));
        map
    }
}

/// Seal plaintext with AES-256-GCM; tag is returned separately from ciphertext.
pub fn seal_aes_gcm(aes_key: &[u8], plaintext: &[u8]) -> Result<SealedEnvelope, SealError> {
    let key: [u8; 32] = aes_key
        .try_into()
        .map_err(|_| SealError::InvalidAesKey)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| SealError::InvalidAesKey)?;
    let mut iv = [0u8; AES_GCM_IV_BYTES];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);
    let encrypted = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| SealError::EncryptFailed)?;
    if encrypted.len() < AES_GCM_TAG_BYTES {
        return Err(SealError::EncryptFailed);
    }
    let split = encrypted.len() - AES_GCM_TAG_BYTES;
    let (ciphertext, tag) = encrypted.split_at(split);
    Ok(SealedEnvelope {
        iv_b64: bytes_to_base64(&iv),
        ciphertext_b64: bytes_to_base64(ciphertext),
        tag_b64: bytes_to_base64(tag),
    })
}

/// Open an AES-256-GCM envelope (ciphertext and tag separate).
pub fn open_aes_gcm(aes_key: &[u8], envelope: &SealedEnvelope) -> Result<Vec<u8>, SealError> {
    let key: [u8; 32] = aes_key
        .try_into()
        .map_err(|_| SealError::InvalidAesKey)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| SealError::InvalidAesKey)?;
    let iv = base64_to_bytes(&envelope.iv_b64).map_err(|_| SealError::InvalidBase64)?;
    let ciphertext = base64_to_bytes(&envelope.ciphertext_b64).map_err(|_| SealError::InvalidBase64)?;
    let tag = base64_to_bytes(&envelope.tag_b64).map_err(|_| SealError::InvalidBase64)?;
    if iv.len() != AES_GCM_IV_BYTES {
        return Err(SealError::InvalidIv);
    }
    let mut combined = ciphertext;
    combined.extend_from_slice(&tag);
    let nonce = Nonce::from_slice(&iv);
    cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|_| SealError::DecryptFailed)
}

/// Crypto helper errors (internal; client maps to [`crate::SdkeyError`] where needed).
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid base64")]
    InvalidBase64,
    #[error("HKDF expand failed")]
    HkdfExpandFailed,
    #[error("invalid AES key")]
    InvalidAesKey,
    #[error("invalid AES-GCM IV")]
    InvalidIv,
    #[error("AES-GCM encrypt failed")]
    EncryptFailed,
    #[error("AES-GCM decrypt failed")]
    DecryptFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn aes_gcm_round_trips_plaintext() {
        let mut aes_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut aes_key);
        let plaintext = br#"{"ok":true}"#;
        let sealed = seal_aes_gcm(&aes_key, plaintext).unwrap();
        let opened = open_aes_gcm(&aes_key, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn derive_session_aes_key_is_deterministic() {
        let mut client_nonce = [0u8; 32];
        let mut server_nonce = [0u8; 32];
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut client_nonce);
        rand::thread_rng().fill_bytes(&mut server_nonce);
        rand::thread_rng().fill_bytes(&mut salt);
        let salt_b64 = bytes_to_base64(&salt);
        let app_id = "11111111-2222-3333-4444-555555555555";

        let a = derive_session_aes_key(&client_nonce, &server_nonce, &salt_b64, app_id).unwrap();
        let b = derive_session_aes_key(&client_nonce, &server_nonce, &salt_b64, app_id).unwrap();
        assert_eq!(bytes_to_base64(&a), bytes_to_base64(&b));
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn derive_session_aes_key_changes_when_app_id_changes() {
        let client_nonce = [1u8; 32];
        let server_nonce = [2u8; 32];
        let salt_b64 = bytes_to_base64(&[3u8; 16]);

        let a = derive_session_aes_key(
            &client_nonce,
            &server_nonce,
            &salt_b64,
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )
        .unwrap();
        let b = derive_session_aes_key(
            &client_nonce,
            &server_nonce,
            &salt_b64,
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        )
        .unwrap();
        assert_ne!(bytes_to_base64(&a), bytes_to_base64(&b));
    }
}
