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

use crate::*;
use super::helpers::{create_test_attestation_object, create_test_client_data_json};

#[test]
fn test_passki_new() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    assert_eq!(passki.rp_id, "localhost");
    assert_eq!(passki.rp_origin, "http://localhost:3000");
    assert_eq!(passki.rp_name, "Test App");
}

#[test]
fn test_start_passkey_registration_returns_challenge() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let user_id = b"user123_16_bytes";
    let (challenge, state) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    ).unwrap();

    // Verify challenge structure
    assert_eq!(challenge.rp.id, "localhost");
    assert_eq!(challenge.rp.name, "Test App");
    assert_eq!(challenge.user.name, "testuser");
    assert_eq!(challenge.user.display_name, "Test User");
    assert_eq!(challenge.timeout, 60000);
    assert!(!challenge.challenge.is_empty());

    // Verify algorithm support
    assert_eq!(challenge.pub_key_cred_params.len(), 3);
    assert_eq!(challenge.pub_key_cred_params[0].alg, -8); // EdDSA
    assert_eq!(challenge.pub_key_cred_params[1].alg, -7); // ES256
    assert_eq!(challenge.pub_key_cred_params[2].alg, -257); // RS256

    // Verify state
    assert_eq!(state.challenge.len(), 32);
    assert!(!state.user.id.is_empty());
}

#[test]
fn test_start_passkey_registration_with_different_settings() {
    let passki = Passki::new("example.com", "https://example.com", "Example App");

    let user_id = b"admin_user_id_16";
    let (challenge, _state) = passki.start_passkey_registration(
        user_id,
        "adminuser",
        "Admin User",
        30000,
        AttestationConveyancePreference::Direct,
        ResidentKeyRequirement::Required,
        UserVerificationRequirement::Required,
        None,
    ).unwrap();

    assert_eq!(challenge.timeout, 30000);
    assert_eq!(challenge.user.name, "adminuser");
    assert_eq!(challenge.user.display_name, "Admin User");
}

#[test]
fn test_start_passkey_registration_generates_unique_challenges() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let user_id1 = b"user1_identifier";
    let (challenge1, state1) = passki.start_passkey_registration(
        user_id1,
        "user1",
        "User 1",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    ).unwrap();

    let user_id2 = b"user2_identifier";
    let (challenge2, state2) = passki.start_passkey_registration(
        user_id2,
        "user2",
        "User 2",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    ).unwrap();

    // Challenges should be unique
    assert_ne!(challenge1.challenge, challenge2.challenge);
    assert_ne!(state1.challenge, state2.challenge);
}

#[test]
fn test_start_passkey_registration_user_id_stored_as_bytes() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let user_id = b"testuser_16bytes";
    let (challenge, state) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    ).unwrap();

    // User info should be stored in state
    assert_eq!(state.user.id, challenge.user.id);
    assert_eq!(state.user.name, "testuser");

    // Decode the base64url user ID from state
    let decoded_user_id = Passki::base64_decode(&state.user.id).unwrap();
    assert_eq!(decoded_user_id, user_id);
}

#[test]
fn test_start_passkey_registration_with_single_existing_credential() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let existing_passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 32],
        counter: 5,
        algorithm: -7,
    };

    let user_id = b"user123_16bytes_";
    let (challenge, state) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        Some(&[existing_passkey.clone()]),
    ).unwrap();

    // Verify exclude_credentials contains the existing credential
    assert_eq!(challenge.exclude_credentials.len(), 1);
    assert_eq!(challenge.exclude_credentials[0].type_, "public-key");

    // Verify the credential ID is properly encoded
    let decoded_id = Passki::base64_decode(&challenge.exclude_credentials[0].id).unwrap();
    assert_eq!(decoded_id, existing_passkey.credential_id);

    // Verify state is still correct
    assert_eq!(state.challenge.len(), 32);
    assert!(!state.user.id.is_empty());
}

#[test]
fn test_start_passkey_registration_with_multiple_existing_credentials() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let existing_passkeys = vec![
        StoredPasskey {
            credential_id: vec![1u8; 16],
            public_key: vec![2u8; 32],
            counter: 5,
            algorithm: -7,
        },
        StoredPasskey {
            credential_id: vec![3u8; 16],
            public_key: vec![4u8; 32],
            counter: 10,
            algorithm: -8,
        },
        StoredPasskey {
            credential_id: vec![5u8; 16],
            public_key: vec![6u8; 64],
            counter: 15,
            algorithm: -257,
        },
    ];

    let user_id = b"user123_16bytes_";
    let (challenge, state) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        Some(&existing_passkeys),
    ).unwrap();

    // Verify all credentials are excluded
    assert_eq!(challenge.exclude_credentials.len(), 3);

    // Verify each credential is properly encoded
    for (i, excluded) in challenge.exclude_credentials.iter().enumerate() {
        assert_eq!(excluded.type_, "public-key");
        let decoded_id = Passki::base64_decode(&excluded.id).unwrap();
        assert_eq!(decoded_id, existing_passkeys[i].credential_id);
    }

    // Verify state
    assert_eq!(state.challenge.len(), 32);
    assert!(!state.user.id.is_empty());
}

#[test]
fn test_start_passkey_registration_none_vs_empty_slice() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let user_id = b"user123_16bytes_";

    // Test with None
    let (challenge_none, _state_none) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    ).unwrap();

    // Test with empty slice
    let empty_slice: Vec<StoredPasskey> = vec![];
    let (challenge_empty, _state_empty) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        Some(&empty_slice),
    ).unwrap();

    // Both should result in no excluded credentials
    assert_eq!(challenge_none.exclude_credentials.len(), 0);
    assert_eq!(challenge_empty.exclude_credentials.len(), 0);
}

#[test]
fn test_start_passkey_registration_user_id_validation_success() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    // Exactly 16 bytes
    let user_id = b"1234567890123456";
    let result = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    );

    assert!(result.is_ok(), "16-byte user_id should be valid");
}

#[test]
fn test_start_passkey_registration_user_id_validation_fails_empty() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let user_id = b"";
    let result = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    );

    assert!(result.is_err(), "Empty user_id should fail");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("user_id must be at least 16 bytes")
    );
}

#[test]
fn test_start_passkey_registration_user_id_validation_fails_15_bytes() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    // 15 bytes - one less than minimum
    let user_id = b"123456789012345";
    let result = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    );

    assert!(result.is_err(), "15-byte user_id should fail");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("user_id must be at least 16 bytes")
    );
}

#[test]
fn test_finish_passkey_registration_success() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let user_id = b"user123_16bytes_";
    let (_challenge, state) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    ).unwrap();

    let attestation_obj = create_test_attestation_object(-7);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
    };

    let result = passki.finish_passkey_registration(&credential, &state);
    assert!(result.is_ok());

    let passkey = result.unwrap();
    assert_eq!(passkey.credential_id, vec![1u8; 16]);
    assert_eq!(passkey.algorithm, -7);
    assert_eq!(passkey.counter, 0);
    assert!(!passkey.public_key.is_empty());
}

#[test]
fn test_finish_passkey_registration_wrong_challenge() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let user_id = b"user123_16bytes_";
    let (_challenge, state) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    ).unwrap();

    let attestation_obj = create_test_attestation_object(-7);
    let wrong_challenge = vec![99u8; 32];
    let client_data_json = create_test_client_data_json(&wrong_challenge, "http://localhost:3000");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
    };

    let result = passki.finish_passkey_registration(&credential, &state);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Challenge mismatch")
    );
}

#[test]
fn test_finish_passkey_registration_wrong_origin() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let user_id = b"user123_16bytes_";
    let (_challenge, state) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    ).unwrap();

    let attestation_obj = create_test_attestation_object(-7);
    let client_data_json = create_test_client_data_json(&state.challenge, "https://evil.com");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
    };

    let result = passki.finish_passkey_registration(&credential, &state);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid origin"));
}

#[test]
fn test_finish_passkey_registration_eddsa_algorithm() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let user_id = b"user123_16bytes_";
    let (_challenge, state) = passki.start_passkey_registration(
        user_id,
        "testuser",
        "Test User",
        60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
    ).unwrap();

    let attestation_obj = create_test_attestation_object(-8);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[2u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
    };

    let result = passki.finish_passkey_registration(&credential, &state);
    assert!(result.is_ok());

    let passkey = result.unwrap();
    assert_eq!(passkey.algorithm, -8);
}
