//! Stable hardware ID helper for desktop clients.
//!
//! Reads a platform machine identifier, then returns its SHA-256 as lowercase hex.
//! Opt-in only — pass the result to `validate` / auth APIs; do not invent IDs.

use sha2::{Digest, Sha256};

use crate::errors::{SdkeyError, SdkeyErrorCode};

/// Collect a stable hashed hardware ID for this machine.
///
/// Reads an OS machine identifier, trims whitespace, then returns SHA-256 of the
/// UTF-8 bytes as lowercase hex (64 characters).
///
/// Platform sources:
/// - **Windows:** `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
/// - **Linux:** `/etc/machine-id`, else `/var/lib/dbus/machine-id`
/// - **macOS:** `IOPlatformUUID` via `ioreg`
///
/// Returns [`SdkeyError`] when the platform is unsupported or the ID is missing/empty.
/// Do not invent a random fallback.
///
/// # Example
///
/// ```no_run
/// use sdkey::{get_hardware_id, Client};
///
/// let mut client = Client::new(
///     "https://api.sdkey.dev",
///     "YOUR_APP_ID",
///     "1.0.0",
///     "YOUR_APP_PUBLIC_KEY_BASE64",
/// );
/// let hwid = get_hardware_id()?;
/// let _ = client.validate("SDKY-XXXX-XXXX-XXXX-XXXX", Some(&hwid))?;
/// # Ok::<(), sdkey::SdkeyError>(())
/// ```
pub fn get_hardware_id() -> Result<String, SdkeyError> {
    let raw = read_raw_machine_id()?;
    hash_machine_id(&raw)
}

/// Trim, reject empty, SHA-256 UTF-8 bytes → lowercase hex.
pub(crate) fn hash_machine_id(raw: &str) -> Result<String, SdkeyError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SdkeyError::new(
            SdkeyErrorCode::Unknown,
            "Hardware ID is empty after trimming whitespace",
        ));
    }
    let digest = Sha256::digest(trimmed.as_bytes());
    Ok(digest.iter().map(|b| format!("{:02x}", b)).collect())
}

fn read_raw_machine_id() -> Result<String, SdkeyError> {
    #[cfg(target_os = "windows")]
    {
        return read_windows_machine_guid();
    }
    #[cfg(target_os = "linux")]
    {
        return read_linux_machine_id();
    }
    #[cfg(target_os = "macos")]
    {
        return read_macos_platform_uuid();
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(SdkeyError::new(
            SdkeyErrorCode::Unknown,
            "Hardware ID is not supported on this platform",
        ))
    }
}

#[cfg(target_os = "windows")]
fn read_windows_machine_guid() -> Result<String, SdkeyError> {
    use std::process::Command;

    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .map_err(|err| {
            SdkeyError::with_source(
                SdkeyErrorCode::Unknown,
                "Failed to query Windows MachineGuid from the registry",
                err,
            )
        })?;

    if !output.status.success() {
        return Err(SdkeyError::new(
            SdkeyErrorCode::Unknown,
            "Failed to read Windows MachineGuid from the registry",
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        // Typical: MachineGuid    REG_SZ    xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        if line.starts_with("MachineGuid") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(guid) = parts.last() {
                if !guid.is_empty() && *guid != "MachineGuid" && *guid != "REG_SZ" {
                    return Ok((*guid).to_string());
                }
            }
        }
    }

    Err(SdkeyError::new(
        SdkeyErrorCode::Unknown,
        "Windows MachineGuid not found in registry query output",
    ))
}

#[cfg(target_os = "linux")]
fn read_linux_machine_id() -> Result<String, SdkeyError> {
    use std::fs;

    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(contents) = fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }

    Err(SdkeyError::new(
        SdkeyErrorCode::Unknown,
        "Linux machine-id not found at /etc/machine-id or /var/lib/dbus/machine-id",
    ))
}

#[cfg(target_os = "macos")]
fn read_macos_platform_uuid() -> Result<String, SdkeyError> {
    use std::process::Command;

    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map_err(|err| {
            SdkeyError::with_source(
                SdkeyErrorCode::Unknown,
                "Failed to run ioreg for IOPlatformUUID",
                err,
            )
        })?;

    if !output.status.success() {
        return Err(SdkeyError::new(
            SdkeyErrorCode::Unknown,
            "ioreg failed while reading IOPlatformUUID",
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // Typical: "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        if line.contains("IOPlatformUUID") {
            if let Some(start) = line.rfind('"') {
                let before = &line[..start];
                if let Some(inner_start) = before.rfind('"') {
                    let uuid = &before[inner_start + 1..];
                    if !uuid.is_empty() && uuid != "IOPlatformUUID" {
                        return Ok(uuid.to_string());
                    }
                }
            }
        }
    }

    Err(SdkeyError::new(
        SdkeyErrorCode::Unknown,
        "IOPlatformUUID not found in ioreg output",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_fixture_to_known_sha256_hex() {
        let hex = hash_machine_id("test-machine-id").unwrap();
        assert_eq!(
            hex,
            "9fa52d819a388ed6c394855fe82c664d771f939b2fa1fee83ff3030e9ca2a284"
        );
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn trims_whitespace_before_hashing() {
        let a = hash_machine_id("abc").unwrap();
        let b = hash_machine_id("  abc  \n").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            a,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rejects_empty_and_whitespace_only() {
        let empty = hash_machine_id("").unwrap_err();
        assert_eq!(empty.code, SdkeyErrorCode::Unknown);
        assert!(empty.message.contains("empty"));

        let ws = hash_machine_id("   \n\t  ").unwrap_err();
        assert_eq!(ws.code, SdkeyErrorCode::Unknown);
        assert!(ws.message.contains("empty"));
    }

    #[test]
    fn get_hardware_id_returns_64_char_hex_on_supported_os() {
        let hex = get_hardware_id().expect("machine id should be available on CI/dev hosts");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));

        // Stable across calls on the same machine.
        let again = get_hardware_id().unwrap();
        assert_eq!(hex, again);
    }
}
