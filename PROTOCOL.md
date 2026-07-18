# SDKey Client Protocol

Wire protocol for official SDKey clients (TypeScript, Python, Rust, …). All languages must use the same byte layouts and verification order.

**Protocol version:** `1`  
**Package:** [`sdkey`](https://crates.io/crates/sdkey) (Rust), [`sdkey`](https://pypi.org/project/sdkey/) (Python), and [`@sdkey/sdk`](https://www.npmjs.com/package/@sdkey/sdk) (TypeScript) implement this document.

## Embed at build time

| Constant | Description |
|---|---|
| `API_BASE_URL` | e.g. `https://api.sdkey.dev` |
| `APP_ID` | Application UUID |
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
{ "appId": "<uuid>", "clientNonceB64": "<base64 32 bytes>" }
```

Response:

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

Inner plaintext (before AES-GCM seal):

```json
{
  "hwid": "...",
  "licenseKey": "SDKY-....",
  "nonce": "<base64 16 bytes>",
  "timestamp": 1720000001,
  "v": 1
}
```

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

**Client order of operations (mandatory):**

1. AES-GCM open → plaintext JSON
2. Ed25519 verify(`APP_PUBLIC_KEY`, `canonicalJson(plaintext)`, `signature`)
3. Check `timestamp` skew and `sessionId` match
4. Only then honor `success`

Skipping step 2 defeats anti-spoof protection.

## Failure codes (sealed `success: false`)

`SESSION_EXPIRED`, `CLOCK_SKEW`, `REPLAY`, `LICENSE_NOT_FOUND`, `APP_MISMATCH`, `BANNED`, `EXPIRED`, `HWID_MISMATCH`, `DECRYPT_FAIL`, `APP_DISABLED`

Cryptographic protocol failures after a valid session typically return HTTP **200** with a sealed body so clients always take the decrypt/verify path.

## Threat model notes

- TLS alone is insufficient: an attacker who injects at the process boundary after decrypt can feed `success: true` unless Ed25519 verify binds the response to the app public key.
- Debugger skip-verify remains a residual bypass class for determined attackers.

## Account modes vs validate wire format

Dashboard Private mode does **not** change this validate protocol. Sealed validate still sends plaintext `licenseKey` inside the AES-GCM inner payload.
