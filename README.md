# sdkey

Official Rust client for [SDKey](https://docs.sdkey.dev) license authentication.

Implements the sealed session protocol: Ed25519-verified handshake, HKDF session keys, and AES-256-GCM validate envelopes. See [PROTOCOL.md](./PROTOCOL.md).

## Install

```toml
[dependencies]
sdkey = "0.1"
```

Requires Rust 1.70+.

## Quick start

Embed these values from the SDKey dashboard when you ship your app:

```rust
use sdkey::{Client, SdkeyError};

fn main() -> Result<(), SdkeyError> {
    let mut client = Client::new(
        "https://api.sdkey.dev",
        "YOUR_APP_ID",
        "YOUR_APP_PUBLIC_KEY_BASE64",
    );

    match client.validate("SDKY-XXXX-XXXX-XXXX-XXXX", "machine-hwid") {
        Ok(result) if result.success => {
            println!("licensed {:?} {:?}", result.status, result.expires_at);
        }
        Ok(result) => {
            println!("denied {} {}", result.code, result.message);
        }
        Err(err) => {
            eprintln!("{} {}", err.code, err.message);
            return Err(err);
        }
    }
    Ok(())
}
```

`validate` calls `init()` automatically when no session exists. Sessions last ~15 minutes server-side; on `SESSION_EXPIRED` the client clears local state so the next call re-handshakes.

## API

### `Client::new(api_base_url, app_id, app_public_key_b64)`

| Option | Type | Description |
|---|---|---|
| `api_base_url` | `String` | API origin (no trailing slash) |
| `app_id` | `String` | Application UUID |
| `app_public_key_b64` | `String` | Raw Ed25519 public key (32 bytes), base64 |

Use `Client::with_http_post(...)` to inject a custom HTTP POST for tests or alternate transports.

### Methods

- `init()` — challenge handshake; verifies the signed hello; derives the AES session key
- `validate(license_key, hwid)` — sealed validate; **always** decrypts then verifies the Ed25519 signature before trusting `success`
- `get_session()` / `clear_session()` — inspect or drop the local session

### Errors

Protocol / transport failures return `SdkeyError` with a `code`:

`INIT_FAILED` · `HELLO_SIGNATURE_INVALID` · `VALIDATE_RESPONSE_INVALID` · `RESPONSE_SIGNATURE_INVALID` · `SESSION_MISMATCH` · `CLOCK_SKEW` · `NETWORK`

License denials (banned, HWID mismatch, etc.) return a normal `ValidateResult` with `success: false` — they are not errors.

## Security notes

- Never ship app **private** keys in a client.
- Do not skip signature verification — that is the anti-spoof binding.
- This crate is open source; the SDKey server remains a separate product.

## Development

```bash
cargo test
cargo run --example basic
```

## Publishing

Releases are triggered by pushing a `v*` tag (see `.github/workflows/publish.yml`). The workflow always runs `cargo test` and `cargo publish --dry-run`. The real `cargo publish` step needs a crates.io API token stored as the GitHub Actions secret `CARGO_REGISTRY_TOKEN` (required for the first release).

## License

MIT
