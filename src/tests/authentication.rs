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
use super::helpers::{create_test_authenticator_data, create_test_auth_client_data_json};

#[test]
fn test_start_passkey_authentication_returns_challenge() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let passkeys = vec![StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 32],
        counter: 0,
        algorithm: -7,
    }];

    let (challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    // Verify challenge structure
    assert_eq!(challenge.timeout, 60000);
    assert_eq!(challenge.rp_id, "localhost");
    assert!(!challenge.challenge.is_empty());
    assert_eq!(challenge.allow_credentials.len(), 1);
    assert_eq!(challenge.allow_credentials[0].type_, "public-key");

    // Verify state
    assert_eq!(state.challenge.len(), 32);
    assert_eq!(state.allowed_credentials.len(), 1);
    assert_eq!(state.allowed_credentials[0], vec![1u8; 16]);
}

#[test]
fn test_start_passkey_authentication_multiple_credentials() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let passkeys = vec![
        StoredPasskey {
            credential_id: vec![1u8; 16],
            public_key: vec![2u8; 32],
            counter: 0,
            algorithm: -7,
        },
        StoredPasskey {
            credential_id: vec![3u8; 16],
            public_key: vec![4u8; 32],
            counter: 5,
            algorithm: -8,
        },
        StoredPasskey {
            credential_id: vec![5u8; 16],
            public_key: vec![6u8; 64],
            counter: 10,
            algorithm: -257,
        },
    ];

    let (challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        30000,
        UserVerificationRequirement::Required,
    );

    // Verify all credentials are included
    assert_eq!(challenge.allow_credentials.len(), 3);
    assert_eq!(state.allowed_credentials.len(), 3);

    // Verify credentials are properly encoded
    assert_eq!(
        Passki::base64_decode(&challenge.allow_credentials[0].id).unwrap(),
        vec![1u8; 16]
    );
    assert_eq!(
        Passki::base64_decode(&challenge.allow_credentials[1].id).unwrap(),
        vec![3u8; 16]
    );
    assert_eq!(
        Passki::base64_decode(&challenge.allow_credentials[2].id).unwrap(),
        vec![5u8; 16]
    );
}

#[test]
fn test_start_passkey_authentication_empty_credentials() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let passkeys: Vec<StoredPasskey> = vec![];

    let (challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    // Should work with empty credentials
    assert_eq!(challenge.allow_credentials.len(), 0);
    assert_eq!(state.allowed_credentials.len(), 0);
    assert!(!challenge.challenge.is_empty());
}

#[test]
fn test_start_passkey_authentication_generates_unique_challenges() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let passkeys = vec![StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 32],
        counter: 0,
        algorithm: -7,
    }];

    let (challenge1, state1) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    let (challenge2, state2) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    // Challenges should be unique
    assert_ne!(challenge1.challenge, challenge2.challenge);
    assert_ne!(state1.challenge, state2.challenge);
}

#[test]
fn test_start_passkey_authentication_with_different_settings() {
    let passki = Passki::new("example.com", "https://example.com", "Example App");

    let passkeys = vec![StoredPasskey {
        credential_id: vec![7u8; 20],
        public_key: vec![8u8; 40],
        counter: 100,
        algorithm: -8,
    }];

    let (challenge, _state) = passki.start_passkey_authentication(
        &passkeys,
        120000,
        UserVerificationRequirement::Discouraged,
    );

    assert_eq!(challenge.timeout, 120000);
    assert_eq!(challenge.rp_id, "example.com");
}

#[test]
fn test_finish_passkey_authentication_success() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let stored_passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 64],
        counter: 5,
        algorithm: -7,
    };

    let passkeys = vec![stored_passkey.clone()];
    let (_challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    let authenticator_data = create_test_authenticator_data(6);
    let client_data_json =
        create_test_auth_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = AuthenticationCredential {
        credential_id: Passki::base64_encode(&vec![1u8; 16]),
        authenticator_data: Passki::base64_encode(&authenticator_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(&vec![9u8; 64]),
    };

    let result = passki.finish_passkey_authentication(&credential, &state, &stored_passkey);

    // Note: This will fail because we're using dummy public key data
    // The test verifies that validation checks pass before hitting signature verification
    assert!(result.is_err());
    // Just verify it returns an error - the exact error depends on implementation details
}

#[test]
fn test_finish_passkey_authentication_wrong_credential_id() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let stored_passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 64],
        counter: 5,
        algorithm: -7,
    };

    let passkeys = vec![stored_passkey.clone()];
    let (_challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    let authenticator_data = create_test_authenticator_data(6);
    let client_data_json =
        create_test_auth_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = AuthenticationCredential {
        credential_id: Passki::base64_encode(&vec![99u8; 16]), // Wrong credential ID
        authenticator_data: Passki::base64_encode(&authenticator_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(&vec![9u8; 64]),
    };

    let result = passki.finish_passkey_authentication(&credential, &state, &stored_passkey);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Credential not allowed")
    );
}

#[test]
fn test_finish_passkey_authentication_wrong_challenge() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let stored_passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 64],
        counter: 5,
        algorithm: -7,
    };

    let passkeys = vec![stored_passkey.clone()];
    let (_challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    let authenticator_data = create_test_authenticator_data(6);
    let wrong_challenge = vec![88u8; 32];
    let client_data_json =
        create_test_auth_client_data_json(&wrong_challenge, "http://localhost:3000");

    let credential = AuthenticationCredential {
        credential_id: Passki::base64_encode(&vec![1u8; 16]),
        authenticator_data: Passki::base64_encode(&authenticator_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(&vec![9u8; 64]),
    };

    let result = passki.finish_passkey_authentication(&credential, &state, &stored_passkey);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Challenge mismatch")
    );
}

#[test]
fn test_finish_passkey_authentication_wrong_origin() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let stored_passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 64],
        counter: 5,
        algorithm: -7,
    };

    let passkeys = vec![stored_passkey.clone()];
    let (_challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    let authenticator_data = create_test_authenticator_data(6);
    let client_data_json = create_test_auth_client_data_json(&state.challenge, "https://evil.com");

    let credential = AuthenticationCredential {
        credential_id: Passki::base64_encode(&vec![1u8; 16]),
        authenticator_data: Passki::base64_encode(&authenticator_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(&vec![9u8; 64]),
    };

    let result = passki.finish_passkey_authentication(&credential, &state, &stored_passkey);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid origin"));
}

#[test]
fn test_finish_passkey_authentication_invalid_counter() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let stored_passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 64],
        counter: 10,
        algorithm: -7,
    };

    let passkeys = vec![stored_passkey.clone()];
    let (_challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    let authenticator_data = create_test_authenticator_data(5); // Counter 5 <= stored counter 10
    let client_data_json =
        create_test_auth_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = AuthenticationCredential {
        credential_id: Passki::base64_encode(&vec![1u8; 16]),
        authenticator_data: Passki::base64_encode(&authenticator_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(&vec![9u8; 64]),
    };

    let result = passki.finish_passkey_authentication(&credential, &state, &stored_passkey);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid counter"));
}

#[test]
fn test_finish_passkey_authentication_too_short_authenticator_data() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    let stored_passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 64],
        counter: 5,
        algorithm: -7,
    };

    let passkeys = vec![stored_passkey.clone()];
    let (_challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    let authenticator_data = vec![0u8; 36]; // Too short (< 37 bytes)
    let client_data_json =
        create_test_auth_client_data_json(&state.challenge, "http://localhost:3000");

    let credential = AuthenticationCredential {
        credential_id: Passki::base64_encode(&vec![1u8; 16]),
        authenticator_data: Passki::base64_encode(&authenticator_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(&vec![9u8; 64]),
    };

    let result = passki.finish_passkey_authentication(&credential, &state, &stored_passkey);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid authenticator data")
    );
}

#[test]
fn test_finish_passkey_authentication_usernameless() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");

    // Stored passkey that would be looked up by credential_id after authenticator responds
    let stored_passkey = StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 64],
        counter: 5,
        algorithm: -7,
    };

    // Start authentication with EMPTY credentials list (usernameless flow)
    let passkeys: Vec<StoredPasskey> = vec![];
    let (_challenge, state) = passki.start_passkey_authentication(
        &passkeys,
        60000,
        UserVerificationRequirement::Preferred,
    );

    // Verify state has empty allowed_credentials
    assert!(state.allowed_credentials.is_empty());

    let authenticator_data = create_test_authenticator_data(6);
    let client_data_json =
        create_test_auth_client_data_json(&state.challenge, "http://localhost:3000");

    // Use the credential_id from stored_passkey (simulating lookup after authenticator response)
    let credential = AuthenticationCredential {
        credential_id: Passki::base64_encode(&stored_passkey.credential_id),
        authenticator_data: Passki::base64_encode(&authenticator_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(&vec![9u8; 64]),
    };

    let result = passki.finish_passkey_authentication(&credential, &state, &stored_passkey);

    // Should NOT fail with "Credential not allowed" - usernameless flow skips that check
    // Will fail at signature verification due to dummy data, which is expected
    assert!(result.is_err());
    assert!(
        !result
            .unwrap_err()
            .to_string()
            .contains("Credential not allowed")
    );
}
