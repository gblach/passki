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
    create_eddsa_cose_key, create_test_auth_client_data_json, create_test_authenticator_data,
};
use crate::*;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

// Builds a fully signed AuthenticationCredential with the given optional user handle.
fn signed_auth_credential(
    credential_id: &[u8],
    challenge: &[u8],
    origin: &str,
    counter: u32,
    key_pair: &Ed25519KeyPair,
    user_handle: Option<String>,
) -> AuthenticationCredential {
    let auth_data = create_test_authenticator_data(counter, 0x01);
    let client_data_json = create_test_auth_client_data_json(challenge, origin);

    let client_data_hash = digest::digest(&SHA256, &client_data_json);
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(client_data_hash.as_ref());
    let signature = key_pair.sign(&signed_data);

    AuthenticationCredential {
        credential_id: Passki::base64_encode(credential_id),
        authenticator_data: Passki::base64_encode(&auth_data),
        client_data_json: Passki::base64_encode(&client_data_json),
        signature: Passki::base64_encode(signature.as_ref()),
        user_handle,
        client_extension_results: None,
    }
}

fn authenticate_with_user_handle(user_handle: Option<String>) -> AuthenticationResult {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![1u8; 16];

    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let stored = StoredPasskey {
        credential_id: cred_id.clone(),
        public_key: create_eddsa_cose_key(pub_key),
        counter: 0,
        algorithm: -8,
        rk: None,
    };

    // Usernameless flow: empty allowCredentials so the user is identified by the handle.
    let (_, state) = passki.start_passkey_authentication(
        &[],
        60000,
        UserVerificationRequirement::Preferred,
        None,
    );

    let credential = signed_auth_credential(
        &cred_id,
        &state.challenge,
        "http://localhost:3000",
        1,
        &key_pair,
        user_handle,
    );

    passki
        .finish_passkey_authentication(&credential, &state, &stored)
        .unwrap()
}

#[test]
fn test_user_handle_decoded_from_response() {
    let raw_handle = b"user-1234567890_";
    let result = authenticate_with_user_handle(Some(Passki::base64_encode(raw_handle)));
    assert_eq!(result.user_handle.as_deref(), Some(raw_handle.as_slice()));
}

#[test]
fn test_user_handle_none_when_absent() {
    let result = authenticate_with_user_handle(None);
    assert!(result.user_handle.is_none());
}

#[test]
fn test_user_handle_invalid_base64_returns_error() {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![1u8; 16];

    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let stored = StoredPasskey {
        credential_id: cred_id.clone(),
        public_key: create_eddsa_cose_key(pub_key),
        counter: 0,
        algorithm: -8,
        rk: None,
    };
    let (_, state) = passki.start_passkey_authentication(
        std::slice::from_ref(&stored),
        60000,
        UserVerificationRequirement::Preferred,
        None,
    );

    let credential = signed_auth_credential(
        &cred_id,
        &state.challenge,
        "http://localhost:3000",
        1,
        &key_pair,
        Some("not valid base64!".to_string()),
    );

    let result = passki.finish_passkey_authentication(&credential, &state, &stored);
    assert!(result.is_err());
}
