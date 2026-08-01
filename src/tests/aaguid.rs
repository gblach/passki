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

use super::helpers::{create_test_attestation_object_with_aaguid, create_test_client_data_json};
use crate::*;

const TEST_AAGUID: [u8; 16] = [
    0xad, 0xce, 0x00, 0x02, 0x35, 0xbc, 0xc6, 0x0a, 0x64, 0x8b, 0x0b, 0x25, 0xf1, 0xf0, 0x55, 0x03,
];

fn register(passki: &Passki, aaguid: [u8; 16]) -> StoredPasskey {
    let state = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "testuser",
            "Test User",
            RegistrationOptions::default(),
        )
        .unwrap()
        .1;

    // flags: AT | UP
    let attestation_obj = create_test_attestation_object_with_aaguid(-7, 0x40 | 0x01, 0, aaguid);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: None,
        authenticator_attachment: None,
        transports: Vec::new(),
    };

    passki
        .finish_passkey_registration(&credential, &state)
        .unwrap()
}

#[test]
fn test_finish_passkey_registration_surfaces_aaguid() {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test App");
    let passkey = register(&passki, TEST_AAGUID);

    assert_eq!(passkey.aaguid, TEST_AAGUID);
}

#[test]
fn test_finish_passkey_registration_surfaces_anonymized_aaguid() {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test App");
    let passkey = register(&passki, [0u8; 16]);

    // An all-zero AAGUID is what an authenticator reports when it stays anonymous.
    assert_eq!(passkey.aaguid, [0u8; 16]);
}

#[test]
fn test_stored_passkey_zero_aaguid_roundtrip() {
    let passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 32],
        counter: 0,
        algorithm: -7,
        aaguid: [0u8; 16],
        attestation_type: AttestationType::None,
        transports: Vec::new(),
        rk: None,
        large_blob_supported: None,
        be: false,
        bs: false,
    };

    let json = serde_json::to_string(&passkey).unwrap();
    let restored: StoredPasskey = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.aaguid, [0u8; 16]);
}

#[test]
fn test_stored_passkey_aaguid_roundtrip() {
    let passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 32],
        counter: 0,
        algorithm: -7,
        aaguid: TEST_AAGUID,
        attestation_type: AttestationType::None,
        transports: Vec::new(),
        rk: None,
        large_blob_supported: None,
        be: false,
        bs: false,
    };

    let json = serde_json::to_string(&passkey).unwrap();
    let restored: StoredPasskey = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.aaguid, TEST_AAGUID);
}

#[test]
fn test_stored_passkey_zero_aaguid_is_serialized() {
    let passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 32],
        counter: 0,
        algorithm: -7,
        aaguid: [0u8; 16],
        attestation_type: AttestationType::None,
        transports: Vec::new(),
        rk: None,
        large_blob_supported: None,
        be: false,
        bs: false,
    };

    // A round trip cannot catch a stray `skip_serializing_if` here: an omitted
    // field deserializes back to the same zeros it started as.
    let json = serde_json::to_string(&passkey).unwrap();
    assert!(json.contains("aaguid"));
}

#[test]
fn test_stored_passkey_deserializes_without_aaguid_field() {
    // Simulates a passkey stored before the aaguid field existed.
    let json = serde_json::json!({
        "credential_id": [1, 2, 3],
        "public_key": [4, 5, 6],
        "counter": 0,
        "algorithm": -7
    });

    let passkey: StoredPasskey = serde_json::from_value(json).unwrap();
    assert_eq!(passkey.aaguid, [0u8; 16]);
}
