//! Wire-protocol constants (protocol v1).

/// Protocol version embedded in signed payloads.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum allowed `|now - timestamp|` in seconds.
pub const CLOCK_SKEW_SECONDS: i64 = 60;

/// Client nonce length for session init (bytes).
pub const CLIENT_NONCE_BYTES: usize = 32;

/// Server nonce length from hello (bytes).
pub const SERVER_NONCE_BYTES: usize = 32;

/// Per-validate request nonce length (bytes).
pub const VALIDATE_NONCE_BYTES: usize = 16;

/// AES-GCM IV length (bytes).
pub const AES_GCM_IV_BYTES: usize = 12;

/// AES-GCM authentication tag length in bits.
pub const AES_GCM_TAG_BITS: usize = 128;

/// AES-GCM authentication tag length (bytes).
pub const AES_GCM_TAG_BYTES: usize = 16;

/// Derived session AES key length (bytes).
pub const SESSION_AES_KEY_BYTES: usize = 32;

/// HKDF info prefix; concatenated with `appId` as UTF-8.
pub const SESSION_HKDF_INFO_PREFIX: &str = "sdkey-session-v1";

/// Failure codes that may appear in sealed `success: false` responses.
pub const VALIDATE_FAILURE_CODES: &[&str] = &[
    "SESSION_EXPIRED",
    "CLOCK_SKEW",
    "REPLAY",
    "LICENSE_NOT_FOUND",
    "APP_MISMATCH",
    "BANNED",
    "EXPIRED",
    "HWID_MISMATCH",
    "DECRYPT_FAIL",
    "APP_DISABLED",
    "APP_OUTDATED",
    "HWID_BANNED",
    "IP_BANNED",
];
