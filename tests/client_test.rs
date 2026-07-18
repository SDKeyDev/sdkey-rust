use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sdkey::{
    base64_to_bytes, bytes_to_base64, canonical_json, derive_session_aes_key, seal_aes_gcm,
    Client, SdkeyErrorCode, PROTOCOL_VERSION,
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
    let session_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let mut server_nonce = [0u8; 32];
    let mut hkdf_salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut server_nonce);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut hkdf_salt);
    let timestamp = unix_now();

    let captured_client_nonce: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let call_count = Arc::new(Mutex::new(0u32));
    let captured_for_http = Arc::clone(&captured_client_nonce);
    let count_for_http = Arc::clone(&call_count);
    let signing_for_http = signing_key.clone();

    let http_post = Box::new(move |url: &str, body: &Value| {
        *count_for_http.lock().unwrap() += 1;

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
            let plaintext = json!({
                "success": true,
                "code": "OK",
                "message": "valid",
                "status": "active",
                "expiresAt": null,
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
        public_key_b64,
        http_post,
    );

    let result = client
        .validate("SDKY-TEST-TEST-TEST-TEST", "hwid-1")
        .unwrap();
    assert!(result.success);
    assert_eq!(result.code, "OK");
    assert_eq!(
        client.get_session().unwrap().session_id,
        session_id
    );
    assert_eq!(*call_count.lock().unwrap(), 2);
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
        public_key_b64,
        http_post,
    );

    let err = client.init().unwrap_err();
    assert_eq!(err.code, SdkeyErrorCode::HelloSignatureInvalid);
}
