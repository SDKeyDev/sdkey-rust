# SDKey Client Protocol

Wire protocol for official SDKey clients (TypeScript, Python, Rust, …). All languages must use the same byte layouts and verification order.

**Protocol version:** `1`  
**Package:** [`sdkey`](https://crates.io/crates/sdkey) (Rust), [`sdkey`](https://pypi.org/project/sdkey/) (Python), and [`@sdkey/sdk`](https://www.npmjs.com/package/@sdkey/sdk) (TypeScript) implement this document.

## Embed at build time

| Constant | Description |
|---|---|
| `API_BASE_URL` | e.g. `https://api.sdkey.dev` (no trailing slash) |
| `APP_ID` | Application UUID |
| `APP_VERSION` | Exact app version string (must match `applications.version`) |
| `APP_PUBLIC_KEY` | Ed25519 public key, 32 raw bytes (or base64 of those bytes) |

## Algorithms

| Primitive | Spec |
|---|---|
| App identity | Ed25519 sign / verify |
| Session key | HKDF-SHA256 → 32-byte AES key |
| Payload seal | AES-256-GCM, 12-byte IV, 128-bit tag |
| Canonical JSON | Object keys sorted lexicographically, no insignificant whitespace |
| Clock skew | Reject if `|now - timestamp| > 60` seconds |

## Session key derivation

```
IKM  = clientNonce (32) || serverNonce (32)
salt = SESSION_HKDF_SALT (from signed hello as hkdfSaltB64)
info = UTF8("sdkey-session-v1" || appId)
OKM  = HKDF-SHA256(IKM, salt, info, length=32)
```

## Flow

### 1. `POST /api/v1/session/init`

Request:

```json
{
  "appId": "<uuid>",
  "clientNonceB64": "<base64 32 bytes>",
  "clientVersion": "<exact app version>"
}
```

`clientVersion` must exactly match the application's configured version. Mismatch → `APP_OUTDATED`. Banned client IP → `IP_BANNED`. Disabled app → `APP_DISABLED`.

Success response (no `message` field):

```json
{
  "success": true,
  "sessionId": "<uuid>",
  "serverNonceB64": "...",
  "hkdfSaltB64": "...",
  "timestamp": 1720000000,
  "signatureB64": "...",
  "v": 1
}
```

Failures are plaintext JSON. Customizable text for `APP_DISABLED` / `APP_OUTDATED` / `IP_BANNED` is in `error`:

```json
{
  "success": false,
  "error": "Client version outdated",
  "code": "APP_OUTDATED"
}
```

**Client must** verify Ed25519 signature over canonical JSON of:

```json
{
  "appId": "...",
  "hkdfSaltB64": "...",
  "serverNonceB64": "...",
  "sessionId": "...",
  "timestamp": 1720000000,
  "v": 1
}
```

Then derive the AES session key.

### 2. `POST /api/v1/licenses/validate`

Outer request envelope (HTTPS JSON):

```json
{
  "sessionId": "...",
  "ivB64": "...",
  "ciphertextB64": "...",
  "tagB64": "..."
}
```

Inner plaintext (before AES-GCM seal) — omit `hwid` entirely when unused:

```json
{
  "licenseKey": "SDKY-....",
  "nonce": "<base64 16 bytes>",
  "timestamp": 1720000001,
  "v": 1
}
```

With HWID:

```json
{
  "hwid": "...",
  "licenseKey": "SDKY-....",
  "nonce": "<base64 16 bytes>",
  "timestamp": 1720000001,
  "v": 1
}
```

`hwid` is **optional**. When omitted, the server skips HWID lock, HWID mismatch, and HWID-ban checks. IP bans apply regardless of HWID.

Response envelope:

```json
{
  "sessionId": "...",
  "ivB64": "...",
  "ciphertextB64": "...",
  "tagB64": "...",
  "signatureB64": "..."
}
```

After AES-GCM open, **both success and failure plaintext include `message`** (not a top-level `error`). Success also includes integer `subscriptionTier` (≥ 0; default `0`):

```json
{
  "success": true,
  "code": "OK",
  "message": "validated",
  "status": "active",
  "expiresAt": "2026-01-01T00:00:00.000Z",
  "subscriptionTier": 0,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

Sealed failure plaintext example:

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

**Client order of operations (mandatory):**

1. AES-GCM open → plaintext JSON
2. Ed25519 verify(`APP_PUBLIC_KEY`, `canonicalJson(plaintext)`, `signature`)
3. Check `timestamp` skew and `sessionId` match
4. Only then honor `success`

Skipping step 2 defeats anti-spoof protection.

## Public client auth (plaintext JSON)

These endpoints are **not** sealed. They still require `appId` + `clientVersion` (exact match). Optional `hwid` follows the same omit-when-absent rules as validate. Rate limit: 30 / min / IP. Opaque `sessionToken` TTL: 7 days.

### `POST /api/v1/client/register`

```json
{
  "appId": "<uuid>",
  "username": "player1",
  "password": "••••••••",
  "email": "optional@example.com",
  "licenseKey": "SDKY-....",
  "hwid": "...",
  "clientVersion": "1.0.0"
}
```

HTTP `201` on success.

### `POST /api/v1/client/login`

```json
{
  "appId": "<uuid>",
  "username": "player1",
  "password": "••••••••",
  "hwid": "...",
  "clientVersion": "1.0.0"
}
```

### `POST /api/v1/client/upgrade`

Upgrade the user's linked license with a higher-tier key. **No password** — username + new key only. New key's `subscriptionTier` must be **greater than** the user's current tier (no linked license → current = `0`).

```json
{
  "appId": "<uuid>",
  "username": "player1",
  "licenseKey": "SDKY-....",
  "hwid": "...",
  "clientVersion": "1.0.0"
}
```

### Auth success shape

Success has **no** customizable `message` field:

```json
{
  "success": true,
  "sessionToken": "<opaque>",
  "expiresAt": "2026-01-01T00:00:00.000Z",
  "user": {
    "id": "<uuid>",
    "username": "player1",
    "email": null,
    "applicationId": "<uuid>"
  },
  "license": {
    "id": "<uuid>",
    "status": "active",
    "expiresAt": null,
    "subscriptionTier": 1
  },
  "session": {
    "ip": "203.0.113.1",
    "hwid": "..."
  }
}
```

`license` may be `null` when the user has no linked license.

### Auth failure shape

Customizable text is in **`error`** (not `message`):

```json
{
  "success": false,
  "error": "License tier must be higher than the current tier",
  "code": "TIER_NOT_HIGHER"
}
```

## Where custom messages appear

| Surface | Success text field | Failure text field |
|---|---|---|
| Session init | *(none)* | `error` |
| Sealed validate | `message` | `message` |
| Client register/login/upgrade | *(none)* | `error` |

## Failure codes

### Sealed validate / crypto session

`SESSION_EXPIRED`, `CLOCK_SKEW`, `REPLAY`, `LICENSE_NOT_FOUND`, `APP_MISMATCH`, `BANNED`, `EXPIRED`, `HWID_MISMATCH`, `DECRYPT_FAIL`, `APP_DISABLED`, `APP_OUTDATED`, `HWID_BANNED`, `IP_BANNED`

Cryptographic protocol failures after a valid session typically return HTTP **200** with a sealed body so clients always take the decrypt/verify path.

### Client auth

Also: `LICENSE_REQUIRED`, `INVALID_CREDENTIALS`, `USERNAME_TAKEN`, `USER_NOT_FOUND`, `TIER_NOT_HIGHER`, plus shared codes such as `APP_OUTDATED`, `APP_DISABLED`, `IP_BANNED`, `HWID_BANNED`, `LICENSE_NOT_FOUND`, `BANNED`, `EXPIRED`, `APP_MISMATCH`, `HWID_MISMATCH`.

## Threat model notes

- TLS alone is insufficient: an attacker who injects at the process boundary after decrypt can feed `success: true` unless Ed25519 verify binds the response to the app public key.
- Debugger skip-verify remains a residual bypass class for determined attackers.

## Account modes vs validate wire format

Dashboard Private mode does **not** change this validate protocol. Sealed validate still sends plaintext `licenseKey` inside the AES-GCM inner payload.

## Developer tooling (not part of this client SDK)

Bearer `sdk_live_…` management APIs (create licenses, bans, app settings) are out of scope for this crate.
