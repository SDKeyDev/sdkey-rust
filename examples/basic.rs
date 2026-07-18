//! Minimal usage example. Replace placeholders with values from the SDKey dashboard.
//!
//! ```bash
//! cargo run --example basic
//! ```

use std::env;
use std::process;

use sdkey::{Client, SdkeyError};

fn main() {
    if let Err(err) = run() {
        if let Some(ref server_code) = err.server_code {
            eprintln!("[{}] ({}) {}", err.code, server_code, err.message);
        } else {
            eprintln!("[{}] {}", err.code, err.message);
        }
        process::exit(1);
    }
}

fn run() -> Result<(), SdkeyError> {
    let api_base_url =
        env::var("SDKEY_API_BASE_URL").unwrap_or_else(|_| "https://api.sdkey.dev".to_string());
    let app_id = env::var("SDKEY_APP_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string());
    let app_version = env::var("SDKEY_APP_VERSION").unwrap_or_else(|_| "1.0.0".to_string());
    let app_public_key_b64 = env::var("SDKEY_APP_PUBLIC_KEY_B64").unwrap_or_default();
    let license_key =
        env::var("SDKEY_LICENSE_KEY").unwrap_or_else(|_| "SDKY-XXXX-XXXX-XXXX-XXXX".to_string());
    let hwid = env::var("SDKEY_HWID").ok();

    let mut client = Client::new(api_base_url, app_id, app_version, app_public_key_b64);
    let result = client.validate(&license_key, hwid.as_deref())?;
    if result.success {
        println!(
            "licensed {:?} tier={} {:?}",
            result.status, result.subscription_tier, result.expires_at
        );
    } else {
        println!("denied {} {}", result.code, result.message);
    }
    Ok(())
}
