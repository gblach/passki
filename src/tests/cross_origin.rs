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

use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

use super::helpers::{
    create_eddsa_cose_key, create_test_attestation_object_for_rp,
    create_test_authenticator_data_for_rp,
};
use crate::*;

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";
const TOP_ORIGIN: &str = "https://partner.example";

// flags: AT | UP | UV
const FLAGS: u8 = 0x45;

fn passki() -> Passki {
    Passki::new(RP_ID, &[ORIGIN], "Example Corp").with_embedding_origins(&[TOP_ORIGIN])
}

/// Client data as a browser writes it inside a cross-origin iframe, with `topOrigin` omitted
/// when `top_origin` is `None`.
fn embedded_client_data_json(type_: &str, challenge: &[u8], top_origin: Option<&str>) -> Vec<u8> {
    let mut client_data = serde_json::json!({
        "type": type_,
        "challenge": Passki::base64_encode(challenge),
        "origin": ORIGIN,
        "crossOrigin": true
    });

    if let Some(top_origin) = top_origin {
        client_data["topOrigin"] = top_origin.into();
    }

    serde_json::to_vec(&client_data).unwrap()
}

/// Registers a credential from an iframe embedded on `top_origin`, against a relying party
/// configured with `embedding_origins`.
fn register_embedded_on(
    embedding_origins: &[&str],
    top_origin: Option<&str>,
) -> Result<StoredPasskey> {
    let passki =
        Passki::new(RP_ID, &[ORIGIN], "Example Corp").with_embedding_origins(embedding_origins);
    let (_, state) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            RegistrationOptions::default(),
        )
        .unwrap();

    let attestation_obj =
        create_test_attestation_object_for_rp(RP_ID, -7, FLAGS, 0, [0u8; 16], &[]);
    let credential = RegistrationCredential {
        raw_id: Passki::base64_encode(&[1u8; 16]),
        response: RegistrationResponse {
            client_data_json: Passki::base64_encode(&embedded_client_data_json(
                "webauthn.create",
                &state.challenge,
                top_origin,
            )),
            attestation_object: Passki::base64_encode(&attestation_obj),
            transports: Vec::new(),
        },
        client_extension_results: None,
        authenticator_attachment: None,
    };

    passki.finish_passkey_registration(&credential, &state)
}

#[test]
fn test_top_origin_is_parsed() {
    let encoded = Passki::base64_encode(&embedded_client_data_json(
        "webauthn.get",
        &[1, 2, 3],
        Some(TOP_ORIGIN),
    ));

    let client_data = ClientData::from_base64(&encoded).unwrap();

    assert!(client_data.cross_origin);
    assert_eq!(client_data.top_origin.as_deref(), Some(TOP_ORIGIN));
}

#[test]
fn test_top_origin_is_none_when_absent() {
    let encoded =
        Passki::base64_encode(&embedded_client_data_json("webauthn.get", &[1, 2, 3], None));

    let client_data = ClientData::from_base64(&encoded).unwrap();

    assert!(client_data.top_origin.is_none());
}

#[test]
fn test_verify_embedded_accepts_a_listed_top_origin() {
    let challenge = Passki::generate_challenge();
    let encoded = Passki::base64_encode(&embedded_client_data_json(
        "webauthn.get",
        &challenge,
        Some(TOP_ORIGIN),
    ));
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result =
        client_data.verify_embedded(ClientDataType::Get, &challenge, &[ORIGIN], &[TOP_ORIGIN]);

    assert!(result.is_ok());
}

#[test]
fn test_verify_embedded_rejects_an_unlisted_top_origin() {
    let challenge = Passki::generate_challenge();
    let encoded = Passki::base64_encode(&embedded_client_data_json(
        "webauthn.get",
        &challenge,
        Some("https://attacker.example"),
    ));
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let err = client_data
        .verify_embedded(ClientDataType::Get, &challenge, &[ORIGIN], &[TOP_ORIGIN])
        .unwrap_err();

    assert!(matches!(err, PasskiError::TopOriginMismatch { .. }));
}

#[test]
fn test_verify_embedded_rejects_a_missing_top_origin() {
    let challenge = Passki::generate_challenge();
    let encoded =
        Passki::base64_encode(&embedded_client_data_json("webauthn.get", &challenge, None));
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let err = client_data
        .verify_embedded(ClientDataType::Get, &challenge, &[ORIGIN], &[TOP_ORIGIN])
        .unwrap_err();

    assert!(matches!(err, PasskiError::MissingClientDataField(field) if field == "topOrigin"));
}

#[test]
fn test_verify_embedded_with_an_empty_allowlist_refuses_as_verify_does() {
    let challenge = Passki::generate_challenge();
    let encoded = Passki::base64_encode(&embedded_client_data_json(
        "webauthn.get",
        &challenge,
        Some(TOP_ORIGIN),
    ));
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let err = client_data
        .verify_embedded(ClientDataType::Get, &challenge, &[ORIGIN], &[] as &[&str])
        .unwrap_err();

    assert!(matches!(err, PasskiError::CrossOriginNotAllowed));
}

#[test]
fn test_verify_embedded_still_checks_the_frame_origin() {
    let challenge = Passki::generate_challenge();
    let encoded = Passki::base64_encode(&embedded_client_data_json(
        "webauthn.get",
        &challenge,
        Some(TOP_ORIGIN),
    ));
    let client_data = ClientData::from_base64(&encoded).unwrap();

    // The embedded page itself must still be ours; an allowlisted embedder does not widen it.
    let err = client_data
        .verify_embedded(
            ClientDataType::Get,
            &challenge,
            &["https://other.example"],
            &[TOP_ORIGIN],
        )
        .unwrap_err();

    assert!(matches!(err, PasskiError::OriginMismatch { .. }));
}

#[test]
fn test_same_origin_ceremony_ignores_the_allowlist() {
    let challenge = Passki::generate_challenge();
    let client_data_json = super::helpers::create_test_auth_client_data_json(&challenge, ORIGIN);
    let encoded = Passki::base64_encode(&client_data_json);
    let client_data = ClientData::from_base64(&encoded).unwrap();

    let result =
        client_data.verify_embedded(ClientDataType::Get, &challenge, &[ORIGIN], &[TOP_ORIGIN]);

    assert!(result.is_ok());
}

#[test]
fn test_registration_accepts_a_listed_embedding_origin() {
    let passkey = register_embedded_on(&[TOP_ORIGIN], Some(TOP_ORIGIN)).unwrap();

    assert_eq!(passkey.credential_id, vec![1u8; 16]);
}

#[test]
fn test_registration_rejects_an_unlisted_embedding_origin() {
    let err = register_embedded_on(&[TOP_ORIGIN], Some("https://attacker.example")).unwrap_err();

    assert!(matches!(err, PasskiError::TopOriginMismatch { .. }));
}

#[test]
fn test_registration_refuses_an_iframe_by_default() {
    let err = register_embedded_on(&[], Some(TOP_ORIGIN)).unwrap_err();

    assert!(matches!(err, PasskiError::CrossOriginNotAllowed));
}

#[test]
fn test_authentication_accepts_a_listed_embedding_origin() {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();

    let passki = passki();
    let stored = StoredPasskey {
        credential_id: vec![7u8; 16],
        public_key: create_eddsa_cose_key(pub_key),
        counter: 0,
        algorithm: -8,
        ..StoredPasskey::default()
    };
    let (_, state) = passki.start_passkey_authentication(
        std::slice::from_ref(&stored),
        AuthenticationOptions::default(),
    );

    let auth_data = create_test_authenticator_data_for_rp(RP_ID, 1, 0x01);
    let client_data_json =
        embedded_client_data_json("webauthn.get", &state.challenge, Some(TOP_ORIGIN));
    let client_data_hash = digest::digest(&SHA256, &client_data_json);
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(client_data_hash.as_ref());
    let signature = key_pair.sign(&signed_data);

    let credential = AuthenticationCredential {
        raw_id: Passki::base64_encode(&[7u8; 16]),
        response: AuthenticationResponse {
            client_data_json: Passki::base64_encode(&client_data_json),
            authenticator_data: Passki::base64_encode(&auth_data),
            signature: Passki::base64_encode(signature.as_ref()),
            user_handle: None,
        },
        client_extension_results: None,
        authenticator_attachment: None,
    };

    let result = passki
        .finish_passkey_authentication(&credential, &state, &stored)
        .unwrap();

    assert_eq!(result.counter, 1);
}
