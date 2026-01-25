// Copyright 2026 Grzegorz Blach
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{ClientData, ClientDataType, Passki};

// ===== ClientData::verify tests =====

#[test]
fn test_verify_valid_create() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&challenge),
        "origin": origin,
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Create, &challenge, origin);

    assert!(
        result.is_ok(),
        "Valid client data should verify successfully"
    );
}

#[test]
fn test_verify_valid_get() {
    let challenge = Passki::generate_challenge();
    let origin = "https://example.com";

    let client_data_json = serde_json::json!({
        "type": "webauthn.get",
        "challenge": Passki::base64_encode(&challenge),
        "origin": origin,
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Get, &challenge, origin);

    assert!(
        result.is_ok(),
        "Valid client data should verify successfully"
    );
}

#[test]
fn test_verify_wrong_type() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.get",
        "challenge": Passki::base64_encode(&challenge),
        "origin": origin,
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(
        ClientDataType::Create, // Expected create, but got get
        &challenge,
        origin,
    );

    assert!(result.is_err(), "Wrong type should fail");
    assert!(result.unwrap_err().to_string().contains("Invalid type"));
}

#[test]
fn test_verify_missing_type() {
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "challenge": "test-challenge",
        "origin": origin,
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let result = ClientData::from_base64(&encoded);

    assert!(result.is_err(), "Missing type should fail");
    assert!(result.unwrap_err().to_string().contains("Missing type"));
}

#[test]
fn test_verify_wrong_challenge() {
    let challenge = Passki::generate_challenge();
    let wrong_challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&wrong_challenge),
        "origin": origin,
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Create, &challenge, origin);

    assert!(result.is_err(), "Wrong challenge should fail");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Challenge mismatch")
    );
}

#[test]
fn test_verify_missing_challenge() {
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "origin": origin,
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let result = ClientData::from_base64(&encoded);

    assert!(result.is_err(), "Missing challenge should fail");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Missing challenge")
    );
}

#[test]
fn test_verify_wrong_origin() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&challenge),
        "origin": "https://evil.com",
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Create, &challenge, origin);

    assert!(result.is_err(), "Wrong origin should fail");
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Invalid origin"), "Error was: {}", error);
}

#[test]
fn test_verify_missing_origin() {
    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": "test-challenge",
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let result = ClientData::from_base64(&encoded);

    assert!(result.is_err(), "Missing origin should fail");
    assert!(result.unwrap_err().to_string().contains("Missing origin"));
}

#[test]
fn test_verify_invalid_json() {
    let invalid_json = Passki::base64_encode(b"{ invalid json }");

    let result = ClientData::from_base64(&invalid_json);

    assert!(result.is_err(), "Invalid JSON should fail");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid client data JSON")
    );
}

#[test]
fn test_verify_empty_json() {
    let empty_json = Passki::base64_encode(b"{}");

    let result = ClientData::from_base64(&empty_json);

    assert!(result.is_err(), "Empty JSON should fail");
}

#[test]
fn test_verify_origin_case_sensitive() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&challenge),
        "origin": "HTTP://LOCALHOST:3000", // Wrong case
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Create, &challenge, origin);

    assert!(result.is_err(), "Origin should be case-sensitive");
    assert!(result.unwrap_err().to_string().contains("Invalid origin"));
}

#[test]
fn test_verify_origin_with_trailing_slash() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&challenge),
        "origin": "http://localhost:3000/", // Trailing slash
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Create, &challenge, origin);

    assert!(
        result.is_err(),
        "Origin with trailing slash should not match"
    );
    assert!(result.unwrap_err().to_string().contains("Invalid origin"));
}

#[test]
fn test_verify_type_case_sensitive() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "WEBAUTHN.CREATE", // Wrong case
        "challenge": Passki::base64_encode(&challenge),
        "origin": origin,
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let result = ClientData::from_base64(&encoded);

    assert!(result.is_err(), "Type should be case-sensitive");
    assert!(result.unwrap_err().to_string().contains("Invalid type"));
}

#[test]
fn test_verify_invalid_base64_challenge() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": "not-valid-base64!!!",
        "origin": origin,
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Create, &challenge, origin);

    assert!(result.is_err(), "Invalid base64 challenge should fail");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Base64 decode error")
    );
}

#[test]
fn test_verify_with_extra_fields() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&challenge),
        "origin": origin,
        "crossOrigin": false,
        "extraField": "should be ignored"
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Create, &challenge, origin);

    assert!(result.is_ok(), "Extra fields should be ignored");
}

#[test]
fn test_verify_different_rp_origins() {
    let challenge = Passki::generate_challenge();

    // Test with HTTP
    let origin_http = "http://localhost:3000";
    let client_data_http = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&challenge),
        "origin": origin_http,
        "crossOrigin": false
    });
    let encoded_http = Passki::base64_encode(&serde_json::to_vec(&client_data_http).unwrap());
    let client_data = ClientData::from_base64(&encoded_http).unwrap();
    let result_http = client_data.verify(ClientDataType::Create, &challenge, origin_http);
    assert!(result_http.is_ok());

    // Test with HTTPS
    let origin_https = "https://example.com";
    let client_data_https = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&challenge),
        "origin": origin_https,
        "crossOrigin": false
    });
    let encoded_https = Passki::base64_encode(&serde_json::to_vec(&client_data_https).unwrap());
    let client_data = ClientData::from_base64(&encoded_https).unwrap();
    let result_https = client_data.verify(ClientDataType::Create, &challenge, origin_https);
    assert!(result_https.is_ok());
}

#[test]
fn test_verify_port_mismatch() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&challenge),
        "origin": "http://localhost:8080", // Different port
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Create, &challenge, origin);

    assert!(result.is_err(), "Port mismatch should fail");
    assert!(result.unwrap_err().to_string().contains("Invalid origin"));
}

#[test]
fn test_verify_protocol_mismatch() {
    let challenge = Passki::generate_challenge();
    let origin = "http://localhost:3000";

    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(&challenge),
        "origin": "https://localhost:3000", // HTTPS instead of HTTP
        "crossOrigin": false
    });

    let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result = client_data.verify(ClientDataType::Create, &challenge, origin);

    assert!(result.is_err(), "Protocol mismatch should fail");
    assert!(result.unwrap_err().to_string().contains("Invalid origin"));
}

#[test]
fn test_verify_multiple_valid_calls() {
    let origin = "http://localhost:3000";

    for _ in 0..10 {
        let challenge = Passki::generate_challenge();

        let client_data_json = serde_json::json!({
            "type": "webauthn.create",
            "challenge": Passki::base64_encode(&challenge),
            "origin": origin,
            "crossOrigin": false
        });

        let encoded = Passki::base64_encode(&serde_json::to_vec(&client_data_json).unwrap());
        let client_data = ClientData::from_base64(&encoded).unwrap();

        let result = client_data.verify(ClientDataType::Create, &challenge, origin);

        assert!(result.is_ok(), "All valid calls should succeed");
    }
}

// ===== ClientData::from_base64 tests =====

#[test]
fn test_from_base64_valid_create() {
    let challenge = Passki::base64_encode(&Passki::generate_challenge());

    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:3000",
        "crossOrigin": false
    });

    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    let encoded = Passki::base64_encode(&client_data_json);

    let result = ClientData::from_base64(&encoded).unwrap();

    assert_eq!(result.type_, ClientDataType::Create);
    assert_eq!(result.challenge, challenge);
    assert_eq!(result.origin, "http://localhost:3000");
    assert!(!result.cross_origin);
}

#[test]
fn test_from_base64_valid_get() {
    let challenge = Passki::base64_encode(&Passki::generate_challenge());

    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": "https://example.com",
        "crossOrigin": true
    });

    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    let encoded = Passki::base64_encode(&client_data_json);

    let result = ClientData::from_base64(&encoded).unwrap();

    assert_eq!(result.type_, ClientDataType::Get);
    assert_eq!(result.challenge, challenge);
    assert_eq!(result.origin, "https://example.com");
    assert!(result.cross_origin);
}

#[test]
fn test_from_base64_missing_cross_origin_defaults_to_false() {
    let challenge = Passki::base64_encode(&Passki::generate_challenge());

    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:3000"
    });

    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    let encoded = Passki::base64_encode(&client_data_json);

    let result = ClientData::from_base64(&encoded).unwrap();

    assert!(!result.cross_origin);
}

#[test]
fn test_from_base64_missing_type() {
    let client_data = serde_json::json!({
        "challenge": "test-challenge",
        "origin": "http://localhost:3000"
    });

    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    let encoded = Passki::base64_encode(&client_data_json);

    let result = ClientData::from_base64(&encoded);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("type"));
}

#[test]
fn test_from_base64_missing_challenge() {
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "origin": "http://localhost:3000"
    });

    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    let encoded = Passki::base64_encode(&client_data_json);

    let result = ClientData::from_base64(&encoded);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("challenge"));
}

#[test]
fn test_from_base64_missing_origin() {
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": "test-challenge"
    });

    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    let encoded = Passki::base64_encode(&client_data_json);

    let result = ClientData::from_base64(&encoded);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("origin"));
}

#[test]
fn test_from_base64_invalid_base64() {
    let result = ClientData::from_base64("not-valid-base64!!!");

    assert!(result.is_err());
}

#[test]
fn test_from_base64_invalid_json() {
    let encoded = Passki::base64_encode(b"not valid json");

    let result = ClientData::from_base64(&encoded);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid client data JSON"));
}

#[test]
fn test_from_base64_with_extra_fields() {
    let challenge = Passki::base64_encode(&Passki::generate_challenge());

    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": "https://example.com",
        "crossOrigin": false,
        "extraField": "should be ignored",
        "anotherExtra": 12345
    });

    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    let encoded = Passki::base64_encode(&client_data_json);

    let result = ClientData::from_base64(&encoded).unwrap();

    assert_eq!(result.type_, ClientDataType::Get);
    assert_eq!(result.challenge, challenge);
    assert_eq!(result.origin, "https://example.com");
}
