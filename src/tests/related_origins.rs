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
    create_test_auth_client_data_json, create_test_authenticator_data_for_rp,
    create_test_client_data_json,
};
use crate::*;

const RP_ID: &str = "example.com";
const ORIGINS: [&str; 2] = ["https://example.com", "https://example.co.uk"];

// flags: AT | UP | UV
const FLAGS: u8 = 0x45;

fn passki() -> Passki {
    Passki::new(RP_ID, &ORIGINS, "Example Corp")
}

/// Registers a credential from `origin`, which the browser only reaches after the well-known file
/// authorized it.
fn register_from(origin: &str) -> Result<StoredPasskey> {
    let passki = passki();
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
            client_data_json: Passki::base64_encode(&create_test_client_data_json(
                &state.challenge,
                origin,
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
fn test_well_known_lists_the_origins_the_rp_id_does_not_cover() {
    assert_eq!(
        passki().related_origins().origins,
        ["https://example.co.uk"]
    );
}

#[test]
fn test_well_known_omits_origins_the_rp_id_already_covers() {
    let passki = Passki::new(
        RP_ID,
        &[
            "https://example.com",
            "https://www.example.com",
            "https://example.com:8443",
            "https://example.co.uk",
        ],
        "Example Corp",
    );

    // Only the last one needs authorizing; the rp_id itself reaches the other three.
    assert_eq!(passki.related_origins().origins, ["https://example.co.uk"]);
}

#[test]
fn test_well_known_is_empty_for_a_single_domain_relying_party() {
    let passki = Passki::new(RP_ID, &["https://example.com"], "Example Corp");

    assert!(passki.related_origins().origins.is_empty());
}

#[test]
fn test_well_known_keeps_a_domain_the_rp_id_only_looks_like() {
    let passki = Passki::new(
        "login.example.com",
        &["https://login.example.com", "https://example.com"],
        "Example Corp",
    );

    // `example.com` is a parent of the rp_id, not a child, so it still needs the file.
    assert_eq!(passki.related_origins().origins, ["https://example.com"]);
}

#[test]
fn test_well_known_serializes_as_the_file_the_browser_fetches() {
    let json = serde_json::to_string(&passki().related_origins()).unwrap();

    assert_eq!(json, r#"{"origins":["https://example.co.uk"]}"#);
}

#[test]
fn test_registration_accepts_any_listed_origin() {
    for origin in ORIGINS {
        let passkey = register_from(origin).unwrap();
        assert_eq!(passkey.credential_id, vec![1u8; 16]);
    }
}

#[test]
fn test_registration_rejects_an_unlisted_origin() {
    let err = register_from("https://example.org").unwrap_err();

    assert!(matches!(err, PasskiError::OriginMismatch { .. }));
}

#[test]
fn test_authentication_accepts_an_origin_other_than_the_one_registered_on() {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();

    // Registered from the first origin, as far as the relying party is concerned.
    let passki = passki();
    let stored = StoredPasskey {
        credential_id: vec![7u8; 16],
        public_key: create_eddsa_cose_key(pub_key),
        counter: 0,
        algorithm: -8,
        aaguid: [0u8; 16],
        attestation_type: AttestationType::None,
        transports: Vec::new(),
        rk: None,
        large_blob_supported: None,
        cred_protect: None,
        min_pin_length: None,
        be: false,
        bs: false,
    };
    let (_, state) = passki
        .start_passkey_authentication(
            std::slice::from_ref(&stored),
            AuthenticationOptions::default(),
        )
        .unwrap();

    // The same credential asserting from the second origin, under the one shared rp_id.
    let auth_data = create_test_authenticator_data_for_rp(RP_ID, 1, 0x01);
    let client_data_json = create_test_auth_client_data_json(&state.challenge, ORIGINS[1]);
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
