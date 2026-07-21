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

use super::helpers::{
    create_test_attestation_object, create_test_auth_client_data_json,
    create_test_authenticator_data, create_test_client_data_json,
};
use crate::*;

fn registration_state(passki: &Passki) -> RegistrationState {
    passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "testuser",
            "Test User",
            60000,
            AttestationConveyancePreference::None,
            ResidentKeyRequirement::Preferred,
            UserVerificationRequirement::Preferred,
            None,
            None,
        )
        .unwrap()
        .1
}

#[test]
fn test_finish_passkey_registration_populates_be_and_bs() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");
    let state = registration_state(&passki);

    // flags: AT | UP | BE | BS
    let attestation_obj = create_test_attestation_object(-7, 0x40 | 0x01 | 0x08 | 0x10);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: None,
    };

    let passkey = passki
        .finish_passkey_registration(&credential, &state)
        .unwrap();
    assert!(passkey.be);
    assert!(passkey.bs);
}

#[test]
fn test_finish_passkey_registration_be_without_bs() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");
    let state = registration_state(&passki);

    // flags: AT | UP | BE (no BS)
    let attestation_obj = create_test_attestation_object(-7, 0x40 | 0x01 | 0x08);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: None,
    };

    let passkey = passki
        .finish_passkey_registration(&credential, &state)
        .unwrap();
    assert!(passkey.be);
    assert!(!passkey.bs);
}

#[test]
fn test_finish_passkey_registration_no_backup_flags() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");
    let state = registration_state(&passki);

    // flags: AT | UP (no BE, no BS)
    let attestation_obj = create_test_attestation_object(-7, 0x40 | 0x01);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: None,
    };

    let passkey = passki
        .finish_passkey_registration(&credential, &state)
        .unwrap();
    assert!(!passkey.be);
    assert!(!passkey.bs);
}

#[test]
fn test_finish_passkey_registration_bs_without_be_rejected() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");
    let state = registration_state(&passki);

    // flags: AT | UP | BS (BS without BE is spec-invalid)
    let attestation_obj = create_test_attestation_object(-7, 0x40 | 0x01 | 0x10);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: None,
    };

    let result = passki.finish_passkey_registration(&credential, &state);
    assert!(matches!(
        result.unwrap_err(),
        PasskiError::InvalidBackupFlags
    ));
}

#[test]
fn test_finish_passkey_authentication_bs_without_be_rejected() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let stored_passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 64],
        counter: 5,
        algorithm: -7,
        rk: None,
        be: false,
        bs: false,
    };

    let passkeys = vec![stored_passkey.clone()];
    let (_challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
        None,
    );

    // flags: UP | BS (no BE)
    let authenticator_data = create_test_authenticator_data(6, 0x01 | 0x10);
    let client_data_json =
        create_test_auth_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = AuthenticationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        authenticator_data: Passki::base64_encode(&authenticator_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(&[9u8; 64]),
        user_handle: None,
        client_extension_results: None,
    };

    let result = passki.finish_passkey_authentication(&credential, &state, &stored_passkey);
    assert!(matches!(
        result.unwrap_err(),
        PasskiError::InvalidBackupFlags
    ));
}

#[test]
fn test_stored_passkey_deserializes_without_be_bs_fields() {
    // Simulates a passkey stored before the be/bs fields existed.
    let json = serde_json::json!({
        "credential_id": [1, 2, 3],
        "public_key": [4, 5, 6],
        "counter": 0,
        "algorithm": -7
    });

    let passkey: StoredPasskey = serde_json::from_value(json).unwrap();
    assert!(!passkey.be);
    assert!(!passkey.bs);
}

#[test]
fn test_stored_passkey_be_bs_roundtrip() {
    let passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 32],
        counter: 0,
        algorithm: -7,
        rk: None,
        be: true,
        bs: true,
    };

    let json = serde_json::to_string(&passkey).unwrap();
    let restored: StoredPasskey = serde_json::from_str(&json).unwrap();
    assert!(restored.be);
    assert!(restored.bs);
}
