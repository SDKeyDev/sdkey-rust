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
    pub message: String,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SdkeyError {
    pub fn new(code: SdkeyErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
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
            source: Some(source.into()),
        }
    }
}

impl fmt::Display for SdkeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}
