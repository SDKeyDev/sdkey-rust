use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sdkey::{
    base64_to_bytes, bytes_to_base64, canonical_json, derive_session_aes_key, open_aes_gcm,
    seal_aes_gcm, Client, SdkeyErrorCode,
    PROTOCOL_VERSION,
};

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn generate_ed25519_pair() -> (SigningKey, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key_b64 = bytes_to_base64(signing_key.verifying_key().as_bytes());
    (signing_key, public_key_b64)
}

fn sign_payload(signing_key: &SigningKey, payload: &Value) -> String {
    let message = canonical_json(payload).unwrap();
    let sig = signing_key.sign(&message);
    bytes_to_base64(&sig.to_bytes())
}

#[test]
fn inits_session_and_validates_sealed_license_response() {
    let (signing_key, public_key_b64) = generate_ed25519_pair();
    let app_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let app_version = "1.0.0";
    let session_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let mut server_nonce = [0u8; 32];
    let mut hkdf_salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut server_nonce);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut hkdf_salt);
    let timestamp = unix_now();

    let captured_client_nonce: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let captured_init_body: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let captured_validate_inner: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let call_count = Arc::new(Mutex::new(0u32));
    let captured_for_http = Arc::clone(&captured_client_nonce);
    let init_body_for_http = Arc::clone(&captured_init_body);
    let validate_inner_for_http = Arc::clone(&captured_validate_inner);
    let count_for_http = Arc::clone(&call_count);
    let signing_for_http = signing_key.clone();

    let http_post = Box::new(move |url: &str, body: &Value| {
        *count_for_http.lock().unwrap() += 1;

        if url.ends_with("/api/v1/session/init") {
            *init_body_for_http.lock().unwrap() = Some(body.clone());
            let client_nonce_b64 = body["clientNonceB64"].as_str().unwrap();
            *captured_for_http.lock().unwrap() =
                Some(base64_to_bytes(client_nonce_b64).unwrap());
            let hello = json!({
                "appId": app_id,
                "hkdfSaltB64": bytes_to_base64(&hkdf_salt),
                "serverNonceB64": bytes_to_base64(&server_nonce),
                "sessionId": session_id,
                "timestamp": timestamp,
                "v": PROTOCOL_VERSION,
            });
            let mut response = hello.as_object().unwrap().clone();
            response.insert("success".to_string(), Value::Bool(true));
            response.insert(
                "signatureB64".to_string(),
                Value::String(sign_payload(&signing_for_http, &hello)),
            );
            return Ok((200, Value::Object(response)));
        }

        if url.ends_with("/api/v1/licenses/validate") {
            let client_nonce = captured_for_http.lock().unwrap().clone().unwrap();
            let aes_key = derive_session_aes_key(
                &client_nonce,
                &server_nonce,
                &bytes_to_base64(&hkdf_salt),
                app_id,
            )
            .unwrap();
            let sealed_req = sdkey::SealedEnvelope {
                iv_b64: body["ivB64"].as_str().unwrap().to_string(),
                ciphertext_b64: body["ciphertextB64"].as_str().unwrap().to_string(),
                tag_b64: body["tagB64"].as_str().unwrap().to_string(),
            };
            let inner_bytes = open_aes_gcm(&aes_key, &sealed_req).unwrap();
            let inner: Value = serde_json::from_slice(&inner_bytes).unwrap();
            *validate_inner_for_http.lock().unwrap() = Some(inner);

            let plaintext = json!({
                "success": true,
                "code": "OK",
                "message": "validated",
                "status": "active",
                "expiresAt": null,
                "subscriptionTier": 2,
                "sessionId": session_id,
                "timestamp": unix_now(),
                "v": PROTOCOL_VERSION,
            });
            let sealed = seal_aes_gcm(
                &aes_key,
                serde_json::to_vec(&plaintext).unwrap().as_slice(),
            )
            .unwrap();
            let mut response = sealed.as_wire();
            response.insert("sessionId".to_string(), Value::String(session_id.to_string()));
            response.insert(
                "signatureB64".to_string(),
                Value::String(sign_payload(&signing_for_http, &plaintext)),
            );
            return Ok((200, Value::Object(response)));
        }

        Ok((404, json!({"error": "not found"})))
    });

    let mut client = Client::with_http_post(
        "https://api.example.test",
        app_id,
        app_version,
        public_key_b64,
        http_post,
    );

    let result = client
        .validate("SDKY-TEST-TEST-TEST-TEST", Some("hwid-1"))
        .unwrap();
    assert!(result.success);
    assert_eq!(result.code, "OK");
    assert_eq!(result.message, "validated");
    assert_eq!(result.subscription_tier, 2);
    assert_eq!(
        client.get_session().unwrap().session_id,
        session_id
    );
    assert_eq!(*call_count.lock().unwrap(), 2);

    let init_body = captured_init_body.lock().unwrap().clone().unwrap();
    assert_eq!(init_body["clientVersion"], app_version);

    let inner = captured_validate_inner.lock().unwrap().clone().unwrap();
    assert_eq!(inner["hwid"], "hwid-1");
    assert!(inner.get("licenseKey").is_some());
}

#[test]
fn validate_omits_hwid_json_key_when_absent() {
    let (signing_key, public_key_b64) = generate_ed25519_pair();
    let app_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let session_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let mut server_nonce = [0u8; 32];
    let mut hkdf_salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut server_nonce);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut hkdf_salt);
    let timestamp = unix_now();

    let captured_client_nonce: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let captured_validate_inner: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let captured_for_http = Arc::clone(&captured_client_nonce);
    let validate_inner_for_http = Arc::clone(&captured_validate_inner);
    let signing_for_http = signing_key.clone();

    let http_post = Box::new(move |url: &str, body: &Value| {
        if url.ends_with("/api/v1/session/init") {
            let client_nonce_b64 = body["clientNonceB64"].as_str().unwrap();
            *captured_for_http.lock().unwrap() =
                Some(base64_to_bytes(client_nonce_b64).unwrap());
            let hello = json!({
                "appId": app_id,
                "hkdfSaltB64": bytes_to_base64(&hkdf_salt),
                "serverNonceB64": bytes_to_base64(&server_nonce),
                "sessionId": session_id,
                "timestamp": timestamp,
                "v": PROTOCOL_VERSION,
            });
            let mut response = hello.as_object().unwrap().clone();
            response.insert("success".to_string(), Value::Bool(true));
            response.insert(
                "signatureB64".to_string(),
                Value::String(sign_payload(&signing_for_http, &hello)),
            );
            return Ok((200, Value::Object(response)));
        }

        if url.ends_with("/api/v1/licenses/validate") {
            let client_nonce = captured_for_http.lock().unwrap().clone().unwrap();
            let aes_key = derive_session_aes_key(
                &client_nonce,
                &server_nonce,
                &bytes_to_base64(&hkdf_salt),
                app_id,
            )
            .unwrap();
            let sealed_req = sdkey::SealedEnvelope {
                iv_b64: body["ivB64"].as_str().unwrap().to_string(),
                ciphertext_b64: body["ciphertextB64"].as_str().unwrap().to_string(),
                tag_b64: body["tagB64"].as_str().unwrap().to_string(),
            };
            let inner_bytes = open_aes_gcm(&aes_key, &sealed_req).unwrap();
            let inner: Value = serde_json::from_slice(&inner_bytes).unwrap();
            *validate_inner_for_http.lock().unwrap() = Some(inner);

            let plaintext = json!({
                "success": true,
                "code": "OK",
                "message": "validated",
                "status": "active",
                "expiresAt": null,
                "subscriptionTier": 0,
                "sessionId": session_id,
                "timestamp": unix_now(),
                "v": PROTOCOL_VERSION,
            });
            let sealed = seal_aes_gcm(
                &aes_key,
                serde_json::to_vec(&plaintext).unwrap().as_slice(),
            )
            .unwrap();
            let mut response = sealed.as_wire();
            response.insert("sessionId".to_string(), Value::String(session_id.to_string()));
            response.insert(
                "signatureB64".to_string(),
                Value::String(sign_payload(&signing_for_http, &plaintext)),
            );
            return Ok((200, Value::Object(response)));
        }

        Ok((404, json!({"error": "not found"})))
    });

    let mut client = Client::with_http_post(
        "https://api.example.test",
        app_id,
        "1.2.3",
        public_key_b64,
        http_post,
    );

    let result = client.validate("SDKY-TEST-TEST-TEST-TEST", None).unwrap();
    assert!(result.success);
    assert_eq!(result.subscription_tier, 0);

    let inner = captured_validate_inner.lock().unwrap().clone().unwrap();
    assert!(inner.get("hwid").is_none());
}

#[test]
fn init_surfaces_server_error_and_code() {
    let (_signing_key, public_key_b64) = generate_ed25519_pair();

    let http_post = Box::new(move |_url: &str, body: &Value| {
        assert_eq!(body["clientVersion"], "9.9.9");
        Ok((
            403,
            json!({
                "success": false,
                "error": "Client version outdated",
                "code": "APP_OUTDATED",
            }),
        ))
    });

    let mut client = Client::with_http_post(
        "https://api.example.test",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "9.9.9",
        public_key_b64,
        http_post,
    );

    let err = client.init().unwrap_err();
    assert_eq!(err.code, SdkeyErrorCode::InitFailed);
    assert_eq!(err.message, "Client version outdated");
    assert_eq!(err.server_code.as_deref(), Some("APP_OUTDATED"));
}

#[test]
fn throws_sdkey_error_when_hello_signature_is_wrong() {
    let (_signing_key, public_key_b64) = generate_ed25519_pair();
    let (other_private, _) = generate_ed25519_pair();

    let http_post = Box::new(move |_url: &str, _body: &Value| {
        let hello = json!({
            "appId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "hkdfSaltB64": bytes_to_base64(&[0u8; 16]),
            "serverNonceB64": bytes_to_base64(&[0u8; 32]),
            "sessionId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "timestamp": unix_now(),
            "v": PROTOCOL_VERSION,
        });
        let mut response = hello.as_object().unwrap().clone();
        response.insert("success".to_string(), Value::Bool(true));
        response.insert(
            "signatureB64".to_string(),
            Value::String(sign_payload(&other_private, &hello)),
        );
        Ok((200, Value::Object(response)))
    });

    let mut client = Client::with_http_post(
        "https://api.example.test",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "1.0.0",
        public_key_b64,
        http_post,
    );

    let err = client.init().unwrap_err();
    assert_eq!(err.code, SdkeyErrorCode::HelloSignatureInvalid);
}

