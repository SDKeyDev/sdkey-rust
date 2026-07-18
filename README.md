# sdkey

Official Rust client for [SDKey](https://docs.sdkey.dev) license authentication.

Implements the sealed session protocol: Ed25519-verified handshake, HKDF session keys, and AES-256-GCM validate envelopes, plus plaintext client auth (register / login / upgrade). See [PROTOCOL.md](./PROTOCOL.md).

## Install

```toml
[dependencies]
sdkey = "0.2"
```

Requires Rust 1.70+.

## Quick start

Embed these values from the SDKey dashboard when you ship your app. `app_version` must **exactly match** the application's configured version (mismatch → `APP_OUTDATED`).

```rust
use sdkey::{Client, SdkeyError};

fn main() -> Result<(), SdkeyError> {
    let mut client = Client::new(
        "https://api.sdkey.dev",
        "YOUR_APP_ID",
        "1.0.0", // app_version → sent as clientVersion
        "YOUR_APP_PUBLIC_KEY_BASE64",
    );

    // hwid is optional — use None for web clients (server skips HWID checks)
    match client.validate("SDKY-XXXX-XXXX-XXXX-XXXX", Some("machine-hwid")) {
        Ok(result) if result.success => {
            println!(
                "licensed {:?} tier={} {:?}",
                result.status, result.subscription_tier, result.expires_at
            );
            println!("message: {}", result.message);
        }
        Ok(result) => {
            // Sealed validate failures use `message` (not `error`)
            println!("denied {} {}", result.code, result.message);
        }
        Err(err) => {
            // Init / transport failures: server text is in `error` → err.message
            eprintln!("{} {:?} {}", err.code, err.server_code, err.message);
            return Err(err);
        }
    }
    Ok(())
}
```

`validate` calls `init()` automatically when no session exists. Sessions last ~15 minutes server-side; on `SESSION_EXPIRED` the client clears local state so the next call re-handshakes.

## Client auth (register / login / upgrade)

Plaintext JSON against `/api/v1/client/*` — not AES-sealed. Still sends `appId` + `clientVersion`. Optional `hwid` is omitted from JSON when absent.

```rust
use sdkey::{Client, LoginOptions, RegisterOptions, UpgradeOptions};

let client = Client::new(
    "https://api.sdkey.dev",
    "YOUR_APP_ID",
    "1.0.0",
    "YOUR_APP_PUBLIC_KEY_BASE64",
);

let registered = client.register(&RegisterOptions {
    username: "player1".into(),
    password: "password123".into(),
    email: Some("player@example.com".into()),
    license_key: Some("SDKY-XXXX-XXXX-XXXX-XXXX".into()),
    hwid: Some("machine-hwid".into()),
})?;

let logged_in = client.login(&LoginOptions {
    username: "player1".into(),
    password: "password123".into(),
    hwid: None, // web: omit HWID
})?;

// Upgrade = username + license key only (no password)
let upgraded = client.upgrade(&UpgradeOptions {
    username: "player1".into(),
    license_key: "SDKY-YYYY-YYYY-YYYY-YYYY".into(),
    hwid: Some("machine-hwid".into()),
})?;

println!("token {} expires {}", logged_in.session_token, logged_in.expires_at);
println!("upgrade tier {:?}", upgraded.license.as_ref().map(|l| l.subscription_tier));
let _ = registered;
```

Auth failures expose the server `error` string and `code` on `SdkeyError` (`message` + `server_code`).

## Message vs error fields

Per-app `responseMessages` can customize many strings. Clients surface whatever the server returns:

| Surface | Success text field | Failure text field |
|---|---|---|
| Session init | *(none)* | `error` |
| Sealed validate | `message` | `message` |
| Client register / login / upgrade | *(none)* | `error` |

### Sealed validate success

```json
{
  "success": true,
  "code": "OK",
  "message": "validated",
  "status": "active",
  "expiresAt": null,
  "subscriptionTier": 0,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

### Sealed validate failure

```json
{
  "success": false,
  "code": "HWID_MISMATCH",
  "message": "Hardware ID mismatch",
  "status": null,
  "expiresAt": null,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

### Init / auth failure (plaintext)

```json
{
  "success": false,
  "error": "Client version outdated",
  "code": "APP_OUTDATED"
}
```

## API

### `Client::new(api_base_url, app_id, app_version, app_public_key_b64)`

| Option | Type | Description |
|---|---|---|
| `api_base_url` | `String` | API origin (no trailing slash) |
| `app_id` | `String` | Application UUID |
| `app_version` | `String` | Exact app version → wire field `clientVersion` |
| `app_public_key_b64` | `String` | Raw Ed25519 public key (32 bytes), base64 |

Use `Client::with_http_post(...)` to inject a custom HTTP POST for tests or alternate transports.

### Methods

- `init()` — challenge handshake; verifies the signed hello; derives the AES session key; sends `clientVersion`
- `validate(license_key, hwid)` — sealed validate; `hwid: Option<&str>` (omit key when `None`); **always** decrypts then verifies Ed25519 before trusting `success`
- `register` / `login` / `upgrade` — plaintext `/api/v1/client/*` (upgrade has no password)
- `get_session()` / `clear_session()` — inspect or drop the local session

### Errors

Protocol / transport / auth failures return `SdkeyError` with a `code`:

`INIT_FAILED` · `HELLO_SIGNATURE_INVALID` · `VALIDATE_RESPONSE_INVALID` · `RESPONSE_SIGNATURE_INVALID` · `SESSION_MISMATCH` · `CLOCK_SKEW` · `AUTH_FAILED` · `NETWORK`

When the server returns a plaintext failure, `message` is the server `error` string and `server_code` is the server `code` (e.g. `APP_OUTDATED`).

License denials (banned, HWID mismatch, etc.) return a normal `ValidateResult` with `success: false` — they are not errors. Their user-facing text is in `ValidateResult.message`.

## Security notes

- Never ship app **private** keys in a client.
- Do not skip signature verification — that is the anti-spoof binding.
- This crate is open source; the SDKey server remains a separate product.
- This crate does **not** include developer tooling / Bearer management APIs.

## Development

```bash
cargo test
cargo run --example basic
```

## Publishing

Releases are triggered by pushing a `v*` tag (see `.github/workflows/publish.yml`). The workflow always runs `cargo test` and `cargo publish --dry-run`. The real `cargo publish` step needs a crates.io API token stored as the GitHub Actions secret `CARGO_REGISTRY_TOKEN` (required for the first release).

## License

MIT
