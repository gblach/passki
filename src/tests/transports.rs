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

use super::helpers::{create_test_attestation_object, create_test_client_data_json};
use crate::*;

fn credential_with_transports(transports: serde_json::Value) -> RegistrationCredential {
    let json = serde_json::json!({
        "credential_id": "AAAA",
        "public_key": "AAAA",
        "client_data_json": "AAAA",
        "transports": transports,
    });

    serde_json::from_value(json).unwrap()
}

fn passkey_with_transports(transports: Vec<AuthenticatorTransport>) -> StoredPasskey {
    StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 32],
        counter: 0,
        algorithm: -7,
        aaguid: [0u8; 16],
        attestation_type: AttestationType::None,
        transports,
        rk: None,
        large_blob_supported: None,
        be: false,
        bs: false,
    }
}

#[test]
fn test_credential_reads_every_defined_transport() {
    let credential = credential_with_transports(serde_json::json!([
        "usb",
        "nfc",
        "ble",
        "smart-card",
        "hybrid",
        "internal"
    ]));

    assert_eq!(
        credential.transports,
        vec![
            AuthenticatorTransport::Usb,
            AuthenticatorTransport::Nfc,
            AuthenticatorTransport::Ble,
            AuthenticatorTransport::SmartCard,
            AuthenticatorTransport::Hybrid,
            AuthenticatorTransport::Internal,
        ]
    );
}

#[test]
fn test_credential_tolerates_unknown_transports() {
    // A client is free to report a transport from a later specification level
    // than this crate knows about; that must not fail the whole registration.
    let credential = credential_with_transports(serde_json::json!(["usb", "quantum-tunnel"]));

    assert_eq!(credential.transports, vec![AuthenticatorTransport::Usb]);
}

#[test]
fn test_credential_normalizes_legacy_cable_transport() {
    let credential = credential_with_transports(serde_json::json!(["cable"]));

    assert_eq!(credential.transports, vec![AuthenticatorTransport::Hybrid]);
}

#[test]
fn test_credential_deduplicates_cable_and_hybrid() {
    // Normalizing `cable` can collide with an explicit `hybrid`, and the
    // descriptor member is a set.
    let credential = credential_with_transports(serde_json::json!(["cable", "hybrid"]));

    assert_eq!(credential.transports, vec![AuthenticatorTransport::Hybrid]);
}

#[test]
fn test_credential_without_transports() {
    let json = serde_json::json!({
        "credential_id": "AAAA",
        "public_key": "AAAA",
        "client_data_json": "AAAA"
    });

    let credential: RegistrationCredential = serde_json::from_value(json).unwrap();
    assert!(credential.transports.is_empty());
}

#[test]
fn test_credential_with_null_transports() {
    let credential = credential_with_transports(serde_json::Value::Null);

    assert!(credential.transports.is_empty());
}

#[test]
fn test_registration_stores_the_reported_transports() {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test App");
    let (_, state) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "testuser",
            "Test User",
            RegistrationOptions::default(),
        )
        .unwrap();

    let attestation_obj = create_test_attestation_object(-7, FLAG_UP | FLAG_AT);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: None,
        authenticator_attachment: None,
        transports: vec![AuthenticatorTransport::Usb, AuthenticatorTransport::Nfc],
    };

    let passkey = passki
        .finish_passkey_registration(&credential, &state)
        .unwrap();

    assert_eq!(
        passkey.transports,
        vec![AuthenticatorTransport::Usb, AuthenticatorTransport::Nfc]
    );
}

#[test]
fn test_allow_credentials_carry_the_transports() {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test App");
    let passkeys = vec![passkey_with_transports(vec![
        AuthenticatorTransport::Internal,
    ])];

    let (challenge, _) =
        passki.start_passkey_authentication(&passkeys, AuthenticationOptions::default());
    let json = serde_json::to_value(&challenge).unwrap();

    assert_eq!(json["allowCredentials"][0]["transports"][0], "internal");
}

#[test]
fn test_exclude_credentials_carry_the_transports() {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test App");
    let passkeys = vec![passkey_with_transports(vec![
        AuthenticatorTransport::SmartCard,
    ])];

    let (challenge, _) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "testuser",
            "Test User",
            RegistrationOptions {
                exclude_credentials: Some(&passkeys),
                ..Default::default()
            },
        )
        .unwrap();
    let json = serde_json::to_value(&challenge).unwrap();

    // The WebAuthn value is hyphenated, not camelCase.
    assert_eq!(json["excludeCredentials"][0]["transports"][0], "smart-card");
}

#[test]
fn test_descriptors_omit_empty_transports() {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test App");
    let passkeys = vec![passkey_with_transports(Vec::new())];

    let (challenge, _) =
        passki.start_passkey_authentication(&passkeys, AuthenticationOptions::default());
    let json = serde_json::to_value(&challenge).unwrap();

    // An absent member means "no hint"; an empty array tells the client the
    // credential is reachable over nothing at all.
    assert!(json["allowCredentials"][0].get("transports").is_none());
    assert_eq!(json["allowCredentials"][0]["type"], "public-key");
}

#[test]
fn test_stored_passkey_transports_round_trip_through_json() {
    let passkey = passkey_with_transports(vec![
        AuthenticatorTransport::Hybrid,
        AuthenticatorTransport::Internal,
    ]);

    let json = serde_json::to_string(&passkey).unwrap();
    assert!(json.contains(r#""transports":["hybrid","internal"]"#));

    let decoded: StoredPasskey = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.transports, passkey.transports);
}

#[test]
fn test_stored_passkey_without_transports_deserializes() {
    let json = r#"{
        "credential_id": [1],
        "public_key": [2],
        "counter": 0,
        "algorithm": -7
    }"#;

    let decoded: StoredPasskey = serde_json::from_str(json).unwrap();
    assert!(decoded.transports.is_empty());
}
