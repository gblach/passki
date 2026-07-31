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
    create_eddsa_cose_key, create_test_attestation_object, create_test_auth_client_data_json,
    create_test_authenticator_data, create_test_client_data_json,
};
use crate::*;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

fn registration_challenge(support: Option<LargeBlobSupport>) -> serde_json::Value {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test");
    let extensions = support.map(|support| RegistrationExtensions {
        large_blob: Some(LargeBlobRegistrationInput { support }),
        ..Default::default()
    });
    let (challenge, _) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            RegistrationOptions {
                extensions,
                ..Default::default()
            },
        )
        .unwrap();

    serde_json::to_value(&challenge).unwrap()
}

// ===== Registration challenge serialization =====

#[test]
fn test_large_blob_required_in_challenge() {
    let json = registration_challenge(Some(LargeBlobSupport::Required));
    assert_eq!(json["extensions"]["largeBlob"]["support"], "required");
}

#[test]
fn test_large_blob_preferred_in_challenge() {
    let json = registration_challenge(Some(LargeBlobSupport::Preferred));
    assert_eq!(json["extensions"]["largeBlob"]["support"], "preferred");
}

#[test]
fn test_large_blob_absent_from_challenge_when_not_requested() {
    let json = registration_challenge(None);
    assert!(json.get("extensions").is_none());
}

#[test]
fn test_large_blob_and_cred_props_can_be_requested_together() {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test");
    let (challenge, _) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            RegistrationOptions {
                extensions: Some(RegistrationExtensions {
                    cred_props: Some(true),
                    prf: None,
                    large_blob: Some(LargeBlobRegistrationInput {
                        support: LargeBlobSupport::Preferred,
                    }),
                }),
                ..Default::default()
            },
        )
        .unwrap();

    let json = serde_json::to_value(&challenge).unwrap();
    assert_eq!(json["extensions"]["credProps"], true);
    assert_eq!(json["extensions"]["largeBlob"]["support"], "preferred");
}

// ===== Support probe surfaced on StoredPasskey =====

fn make_registration_credential(
    state: &RegistrationState,
    large_blob: Option<LargeBlobResult>,
) -> RegistrationCredential {
    let attestation_obj = create_test_attestation_object(-7, 0x45);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");
    RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: large_blob.map(|lb| ClientExtensionResults {
            cred_props: None,
            prf: None,
            large_blob: Some(lb),
        }),
        authenticator_attachment: None,
        transports: Vec::new(),
    }
}

fn register_with_large_blob_result(large_blob: Option<LargeBlobResult>) -> StoredPasskey {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test App");
    let (_, state) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "testuser",
            "Test User",
            RegistrationOptions {
                extensions: Some(RegistrationExtensions {
                    large_blob: Some(LargeBlobRegistrationInput {
                        support: LargeBlobSupport::Preferred,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();

    let credential = make_registration_credential(&state, large_blob);
    passki
        .finish_passkey_registration(&credential, &state)
        .unwrap()
}

#[test]
fn test_large_blob_supported_true_stored() {
    let passkey = register_with_large_blob_result(Some(LargeBlobResult {
        supported: Some(true),
        blob: None,
        written: None,
    }));
    assert_eq!(passkey.large_blob_supported, Some(true));
}

#[test]
fn test_large_blob_supported_false_stored() {
    let passkey = register_with_large_blob_result(Some(LargeBlobResult {
        supported: Some(false),
        blob: None,
        written: None,
    }));
    assert_eq!(passkey.large_blob_supported, Some(false));
}

#[test]
fn test_large_blob_supported_none_when_not_reported() {
    let passkey = register_with_large_blob_result(None);
    assert_eq!(passkey.large_blob_supported, None);
}

#[test]
fn test_large_blob_supported_round_trips_through_json() {
    let passkey = register_with_large_blob_result(Some(LargeBlobResult {
        supported: Some(true),
        blob: None,
        written: None,
    }));

    let json = serde_json::to_string(&passkey).unwrap();
    let restored: StoredPasskey = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.large_blob_supported, Some(true));
}

#[test]
fn test_stored_passkey_without_large_blob_supported_deserializes() {
    let json = r#"{
        "credential_id": [1, 2, 3],
        "public_key": [4, 5, 6],
        "counter": 0,
        "algorithm": -7
    }"#;
    let passkey: StoredPasskey = serde_json::from_str(json).unwrap();
    assert_eq!(passkey.large_blob_supported, None);
}

// ===== Authentication challenge serialization =====

fn authentication_challenge(large_blob: Option<LargeBlobAuthenticationInput>) -> serde_json::Value {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test");
    let (challenge, _) = passki.start_passkey_authentication(
        &[],
        AuthenticationOptions {
            extensions: Some(AuthenticationExtensions {
                large_blob,
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    serde_json::to_value(&challenge).unwrap()
}

#[test]
fn test_large_blob_read_in_challenge() {
    let json = authentication_challenge(Some(LargeBlobAuthenticationInput::Read));
    assert_eq!(json["extensions"]["largeBlob"]["read"], true);
    assert!(json["extensions"]["largeBlob"].get("write").is_none());
}

#[test]
fn test_large_blob_write_in_challenge() {
    let blob = Passki::base64_encode(b"ssh-ed25519 AAAA");
    let json = authentication_challenge(Some(LargeBlobAuthenticationInput::Write(blob.clone())));
    assert_eq!(json["extensions"]["largeBlob"]["write"], blob);
    assert!(json["extensions"]["largeBlob"].get("read").is_none());
}

#[test]
fn test_large_blob_absent_from_authentication_challenge_when_not_requested() {
    let json = authentication_challenge(None);
    assert!(json["extensions"].get("largeBlob").is_none());
}

// ===== Blob and write flag in AuthenticationResult =====

// Creates a fully signed AuthenticationCredential, which the largeBlob outputs
// are only extracted from after signature verification succeeds.
fn signed_auth_credential(
    credential_id: &[u8],
    challenge: &[u8],
    key_pair: &Ed25519KeyPair,
    large_blob: Option<LargeBlobResult>,
) -> AuthenticationCredential {
    let client_extension_results = large_blob.map(|lb| ClientExtensionResults {
        cred_props: None,
        prf: None,
        large_blob: Some(lb),
    });
    let auth_data = create_test_authenticator_data(1, 0x01);
    let client_data_json = create_test_auth_client_data_json(challenge, "http://localhost:3000");

    let client_data_hash = digest::digest(&SHA256, &client_data_json);
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(client_data_hash.as_ref());
    let signature = key_pair.sign(&signed_data);

    AuthenticationCredential {
        credential_id: Passki::base64_encode(credential_id),
        authenticator_data: Passki::base64_encode(&auth_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(signature.as_ref()),
        user_handle: None,
        client_extension_results,
        authenticator_attachment: None,
    }
}

fn authenticate_with_large_blob_result(
    large_blob: Option<LargeBlobResult>,
) -> Result<AuthenticationResult> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![7u8; 16];

    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test");
    let stored = StoredPasskey {
        credential_id: cred_id.clone(),
        public_key: create_eddsa_cose_key(pub_key),
        counter: 0,
        algorithm: -8,
        aaguid: [0u8; 16],
        attestation_type: AttestationType::None,
        transports: Vec::new(),
        rk: None,
        large_blob_supported: Some(true),
        be: false,
        bs: false,
    };
    let (_, state) = passki.start_passkey_authentication(
        std::slice::from_ref(&stored),
        AuthenticationOptions {
            extensions: Some(AuthenticationExtensions {
                large_blob: Some(LargeBlobAuthenticationInput::Read),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let credential = signed_auth_credential(&cred_id, &state.challenge, &key_pair, large_blob);
    passki.finish_passkey_authentication(&credential, &state, &stored)
}

#[test]
fn test_large_blob_read_output_decoded() {
    let blob_bytes = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5".to_vec();
    let result = authenticate_with_large_blob_result(Some(LargeBlobResult {
        supported: None,
        blob: Some(Passki::base64_encode(&blob_bytes)),
        written: None,
    }))
    .unwrap();

    assert_eq!(result.large_blob, Some(blob_bytes));
    assert_eq!(result.large_blob_written, None);
}

#[test]
fn test_large_blob_written_true_surfaced() {
    let result = authenticate_with_large_blob_result(Some(LargeBlobResult {
        supported: None,
        blob: None,
        written: Some(true),
    }))
    .unwrap();

    assert_eq!(result.large_blob_written, Some(true));
    assert!(result.large_blob.is_none());
}

#[test]
fn test_large_blob_written_false_surfaced() {
    let result = authenticate_with_large_blob_result(Some(LargeBlobResult {
        supported: None,
        blob: None,
        written: Some(false),
    }))
    .unwrap();

    assert_eq!(result.large_blob_written, Some(false));
}

#[test]
fn test_large_blob_outputs_none_when_no_extension_results() {
    let result = authenticate_with_large_blob_result(None).unwrap();

    assert!(result.large_blob.is_none());
    assert!(result.large_blob_written.is_none());
}

#[test]
fn test_large_blob_invalid_base64_returns_error() {
    let result = authenticate_with_large_blob_result(Some(LargeBlobResult {
        supported: None,
        blob: Some("not valid base64!!!".to_string()),
        written: None,
    }));

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Base64 decode error")
    );
}

// ===== LargeBlobResult deserialization =====

#[test]
fn test_client_extension_results_deserializes_supported() {
    let json = r#"{"largeBlob": {"supported": true}}"#;
    let result: ClientExtensionResults = serde_json::from_str(json).unwrap();
    let large_blob = result.large_blob.unwrap();
    assert_eq!(large_blob.supported, Some(true));
    assert!(large_blob.blob.is_none());
    assert!(large_blob.written.is_none());
}

#[test]
fn test_client_extension_results_deserializes_blob() {
    let blob = Passki::base64_encode(b"stored bytes");
    let json = format!(r#"{{"largeBlob": {{"blob": "{blob}"}}}}"#);
    let result: ClientExtensionResults = serde_json::from_str(&json).unwrap();
    assert_eq!(result.large_blob.unwrap().blob, Some(blob));
}

#[test]
fn test_client_extension_results_deserializes_written() {
    let json = r#"{"largeBlob": {"written": true}}"#;
    let result: ClientExtensionResults = serde_json::from_str(json).unwrap();
    assert_eq!(result.large_blob.unwrap().written, Some(true));
}

#[test]
fn test_client_extension_results_without_large_blob() {
    let json = r#"{"credProps": {"rk": true}}"#;
    let result: ClientExtensionResults = serde_json::from_str(json).unwrap();
    assert!(result.large_blob.is_none());
}
