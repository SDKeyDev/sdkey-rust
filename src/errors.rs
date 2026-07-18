//! Protocol and transport errors for the SDKey client.

use std::fmt;

/// Stable error codes for protocol / transport failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkeyErrorCode {
    InitFailed,
    HelloSignatureInvalid,
    ValidateResponseInvalid,
    ResponseSignatureInvalid,
    SessionMismatch,
    ClockSkew,
    Network,
    Unknown,
}

impl SdkeyErrorCode {
    /// Wire / API code string (matches Python/TS).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InitFailed => "INIT_FAILED",
            Self::HelloSignatureInvalid => "HELLO_SIGNATURE_INVALID",
            Self::ValidateResponseInvalid => "VALIDATE_RESPONSE_INVALID",
            Self::ResponseSignatureInvalid => "RESPONSE_SIGNATURE_INVALID",
            Self::SessionMismatch => "SESSION_MISMATCH",
            Self::ClockSkew => "CLOCK_SKEW",
            Self::Network => "NETWORK",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for SdkeyErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Protocol or transport failure (license denials use [`crate::ValidateResult`] instead).
#[derive(Debug, thiserror::Error)]
pub struct SdkeyError {
    pub code: SdkeyErrorCode,
    /// Local or server-provided human-readable text (`error` field from init).
    pub message: String,
    /// Server `code` when present (e.g. `APP_OUTDATED`).
    pub server_code: Option<String>,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SdkeyError {
    pub fn new(code: SdkeyErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            server_code: None,
            source: None,
        }
    }

    pub fn with_server_code(
        code: SdkeyErrorCode,
        message: impl Into<String>,
        server_code: Option<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            server_code,
            source: None,
        }
    }

    pub fn with_source(
        code: SdkeyErrorCode,
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            server_code: None,
            source: Some(source.into()),
        }
    }
}

impl fmt::Display for SdkeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref server_code) = self.server_code {
            write!(f, "{} ({}): {}", self.code.as_str(), server_code, self.message)
        } else {
            write!(f, "{}: {}", self.code.as_str(), self.message)
        }
    }
}
