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
        eprintln!("[{}] {}", err.code, err.message);
        process::exit(1);
    }
}

fn run() -> Result<(), SdkeyError> {
    let api_base_url =
        env::var("SDKEY_API_BASE_URL").unwrap_or_else(|_| "https://api.sdkey.dev".to_string());
    let app_id = env::var("SDKEY_APP_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string());
    let app_public_key_b64 = env::var("SDKEY_APP_PUBLIC_KEY_B64").unwrap_or_default();
    let license_key =
        env::var("SDKEY_LICENSE_KEY").unwrap_or_else(|_| "SDKY-XXXX-XXXX-XXXX-XXXX".to_string());
    let hwid = env::var("SDKEY_HWID").unwrap_or_else(|_| "example-machine-1".to_string());

    let mut client = Client::new(api_base_url, app_id, app_public_key_b64);
    let result = client.validate(&license_key, &hwid)?;
    println!("{result:?}");
    Ok(())
}
