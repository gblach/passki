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

// Creates a fully signed AuthenticationCredential using a real Ed25519 key pair.
// This is required for tests that need to reach the PRF extraction step, which
// only runs after successful signature verification.
fn signed_auth_credential(
    credential_id: &[u8],
    challenge: &[u8],
    origin: &str,
    counter: u32,
    key_pair: &Ed25519KeyPair,
    prf: Option<PrfExtensionResult>,
) -> AuthenticationCredential {
    let client_extension_results = prf.map(|p| ClientExtensionResults {
        prf: Some(p),
        cred_props: None,
    });
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
        client_extension_results,
    }
}

fn make_stored_passkey(
    credential_id: &[u8],
    public_key_bytes: &[u8; 32],
    counter: u32,
) -> StoredPasskey {
    StoredPasskey {
        credential_id: credential_id.to_vec(),
        public_key: create_eddsa_cose_key(public_key_bytes),
        counter,
        algorithm: -8,
        rk: None,
    }
}

// ===== Registration challenge extensions =====

#[test]
fn test_registration_challenge_omits_extensions_when_prf_none() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let (challenge, _) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            60000,
            AttestationConveyancePreference::None,
            ResidentKeyRequirement::Preferred,
            UserVerificationRequirement::Preferred,
            None,
            None,
        )
        .unwrap();

    let json = serde_json::to_value(&challenge).unwrap();
    assert!(
        json.get("extensions").is_none(),
        "extensions must be absent when prf_eval is None"
    );
}

#[test]
fn test_registration_challenge_includes_extensions_when_prf_some() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let extensions = Some(RegistrationExtensions {
        prf: Some(PrfInput {
            eval: Some(PrfEval {
                first: Passki::base64_encode(b"salt-one"),
                second: None,
            }),
        }),
        ..Default::default()
    });
    let (challenge, _) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            60000,
            AttestationConveyancePreference::None,
            ResidentKeyRequirement::Preferred,
            UserVerificationRequirement::Preferred,
            None,
            extensions,
        )
        .unwrap();

    let json = serde_json::to_value(&challenge).unwrap();
    assert!(
        json.get("extensions").is_some(),
        "extensions must be present when prf is Some"
    );
}

#[test]
fn test_registration_challenge_extensions_json_shape() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let salt = b"my-salt-bytes";
    let extensions = Some(RegistrationExtensions {
        prf: Some(PrfInput {
            eval: Some(PrfEval {
                first: Passki::base64_encode(salt),
                second: None,
            }),
        }),
        ..Default::default()
    });
    let (challenge, _) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            60000,
            AttestationConveyancePreference::None,
            ResidentKeyRequirement::Preferred,
            UserVerificationRequirement::Preferred,
            None,
            extensions,
        )
        .unwrap();

    let json = serde_json::to_value(&challenge).unwrap();
    let eval = &json["extensions"]["prf"]["eval"];
    assert_eq!(eval["first"], Passki::base64_encode(salt));
    assert!(
        eval.get("second").is_none(),
        "second must be absent when None"
    );
}

#[test]
fn test_registration_challenge_extensions_includes_second_input() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let extensions = Some(RegistrationExtensions {
        prf: Some(PrfInput {
            eval: Some(PrfEval {
                first: Passki::base64_encode(b"first-salt"),
                second: Some(Passki::base64_encode(b"second-salt")),
            }),
        }),
        ..Default::default()
    });
    let (challenge, _) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            60000,
            AttestationConveyancePreference::None,
            ResidentKeyRequirement::Preferred,
            UserVerificationRequirement::Preferred,
            None,
            extensions,
        )
        .unwrap();

    let json = serde_json::to_value(&challenge).unwrap();
    let eval = &json["extensions"]["prf"]["eval"];
    assert_eq!(eval["first"], Passki::base64_encode(b"first-salt"));
    assert_eq!(eval["second"], Passki::base64_encode(b"second-salt"));
}

#[test]
fn test_registration_challenge_probe_only_has_no_eval() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    // RegistrationExtensions { prf: Some(PrfInput { eval: None }), .. } -> { "prf": {} } - asks for support flag without evaluating
    let extensions = Some(RegistrationExtensions {
        prf: Some(PrfInput { eval: None }),
        ..Default::default()
    });
    let (challenge, _) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            60000,
            AttestationConveyancePreference::None,
            ResidentKeyRequirement::Preferred,
            UserVerificationRequirement::Preferred,
            None,
            extensions,
        )
        .unwrap();

    let json = serde_json::to_value(&challenge).unwrap();
    let prf_ext = &json["extensions"]["prf"];
    assert!(prf_ext.is_object(), "prf extension must be present");
    assert!(
        prf_ext.get("eval").is_none(),
        "eval must be absent in probe-only mode"
    );
}

// ===== Authentication challenge extensions =====

#[test]
fn test_authentication_challenge_omits_extensions_when_prf_none() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let (challenge, _) = passki.start_passkey_authentication(
        &[],
        60000,
        UserVerificationRequirement::Preferred,
        None,
    );

    let json = serde_json::to_value(&challenge).unwrap();
    assert!(
        json.get("extensions").is_none(),
        "extensions must be absent when prf_eval is None"
    );
}

#[test]
fn test_authentication_challenge_includes_extensions_when_prf_some() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let extensions = Some(AuthenticationExtensions {
        prf: PrfInput {
            eval: Some(PrfEval {
                first: Passki::base64_encode(b"salt"),
                second: None,
            }),
        },
    });
    let (challenge, _) = passki.start_passkey_authentication(
        &[],
        60000,
        UserVerificationRequirement::Preferred,
        extensions,
    );

    let json = serde_json::to_value(&challenge).unwrap();
    assert!(
        json.get("extensions").is_some(),
        "extensions must be present when prf_eval is Some"
    );
}

#[test]
fn test_authentication_challenge_extensions_json_shape() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let salt = b"app-context-v1";
    let extensions = Some(AuthenticationExtensions {
        prf: PrfInput {
            eval: Some(PrfEval {
                first: Passki::base64_encode(salt),
                second: None,
            }),
        },
    });
    let (challenge, _) = passki.start_passkey_authentication(
        &[],
        60000,
        UserVerificationRequirement::Preferred,
        extensions,
    );

    let json = serde_json::to_value(&challenge).unwrap();
    let eval = &json["extensions"]["prf"]["eval"];
    assert_eq!(eval["first"], Passki::base64_encode(salt));
    assert!(
        eval.get("second").is_none(),
        "second must be absent when None"
    );
}

#[test]
fn test_authentication_challenge_extensions_includes_second_input() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let extensions = Some(AuthenticationExtensions {
        prf: PrfInput {
            eval: Some(PrfEval {
                first: Passki::base64_encode(b"first"),
                second: Some(Passki::base64_encode(b"second")),
            }),
        },
    });
    let (challenge, _) = passki.start_passkey_authentication(
        &[],
        60000,
        UserVerificationRequirement::Preferred,
        extensions,
    );

    let json = serde_json::to_value(&challenge).unwrap();
    let eval = &json["extensions"]["prf"]["eval"];
    assert_eq!(eval["second"], Passki::base64_encode(b"second"));
}

// ===== PRF outputs in AuthenticationResult =====

#[test]
fn test_prf_outputs_none_when_no_extension_results() {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![1u8; 16];

    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let stored = make_stored_passkey(&cred_id, pub_key, 0);
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
        None,
    );
    let result = passki
        .finish_passkey_authentication(&credential, &state, &stored)
        .unwrap();

    assert!(result.prf_first.is_none());
    assert!(result.prf_second.is_none());
}

#[test]
fn test_prf_outputs_none_when_results_absent_in_extension() {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![2u8; 16];

    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let stored = make_stored_passkey(&cred_id, pub_key, 0);
    let (_, state) = passki.start_passkey_authentication(
        std::slice::from_ref(&stored),
        60000,
        UserVerificationRequirement::Preferred,
        None,
    );

    // enabled = true but no results (registration probe response shape)
    let ext = PrfExtensionResult {
        enabled: Some(true),
        results: None,
    };
    let credential = signed_auth_credential(
        &cred_id,
        &state.challenge,
        "http://localhost:3000",
        1,
        &key_pair,
        Some(ext),
    );
    let result = passki
        .finish_passkey_authentication(&credential, &state, &stored)
        .unwrap();

    assert!(result.prf_first.is_none());
    assert!(result.prf_second.is_none());
}

#[test]
fn test_prf_first_output_decoded() {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![3u8; 16];

    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let stored = make_stored_passkey(&cred_id, pub_key, 0);
    let (_, state) = passki.start_passkey_authentication(
        std::slice::from_ref(&stored),
        60000,
        UserVerificationRequirement::Preferred,
        None,
    );

    let prf_bytes = vec![0xABu8; 32];
    let ext = PrfExtensionResult {
        enabled: None,
        results: Some(PrfResults {
            first: Some(Passki::base64_encode(&prf_bytes)),
            second: None,
        }),
    };
    let credential = signed_auth_credential(
        &cred_id,
        &state.challenge,
        "http://localhost:3000",
        1,
        &key_pair,
        Some(ext),
    );
    let result = passki
        .finish_passkey_authentication(&credential, &state, &stored)
        .unwrap();

    assert_eq!(result.prf_first, Some(prf_bytes));
    assert!(result.prf_second.is_none());
}

#[test]
fn test_prf_both_outputs_decoded() {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![4u8; 16];

    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let stored = make_stored_passkey(&cred_id, pub_key, 0);
    let (_, state) = passki.start_passkey_authentication(
        std::slice::from_ref(&stored),
        60000,
        UserVerificationRequirement::Preferred,
        None,
    );

    let first_bytes = vec![0x11u8; 32];
    let second_bytes = vec![0x22u8; 32];
    let ext = PrfExtensionResult {
        enabled: None,
        results: Some(PrfResults {
            first: Some(Passki::base64_encode(&first_bytes)),
            second: Some(Passki::base64_encode(&second_bytes)),
        }),
    };
    let credential = signed_auth_credential(
        &cred_id,
        &state.challenge,
        "http://localhost:3000",
        1,
        &key_pair,
        Some(ext),
    );
    let result = passki
        .finish_passkey_authentication(&credential, &state, &stored)
        .unwrap();

    assert_eq!(result.prf_first, Some(first_bytes));
    assert_eq!(result.prf_second, Some(second_bytes));
}

#[test]
fn test_prf_invalid_base64_first_returns_error() {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![5u8; 16];

    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let stored = make_stored_passkey(&cred_id, pub_key, 0);
    let (_, state) = passki.start_passkey_authentication(
        std::slice::from_ref(&stored),
        60000,
        UserVerificationRequirement::Preferred,
        None,
    );

    let ext = PrfExtensionResult {
        enabled: None,
        results: Some(PrfResults {
            first: Some("not valid base64!!!".to_string()),
            second: None,
        }),
    };
    let credential = signed_auth_credential(
        &cred_id,
        &state.challenge,
        "http://localhost:3000",
        1,
        &key_pair,
        Some(ext),
    );
    let result = passki.finish_passkey_authentication(&credential, &state, &stored);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Base64 decode error")
    );
}

#[test]
fn test_prf_invalid_base64_second_returns_error() {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![6u8; 16];

    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let stored = make_stored_passkey(&cred_id, pub_key, 0);
    let (_, state) = passki.start_passkey_authentication(
        std::slice::from_ref(&stored),
        60000,
        UserVerificationRequirement::Preferred,
        None,
    );

    let ext = PrfExtensionResult {
        enabled: None,
        results: Some(PrfResults {
            first: Some(Passki::base64_encode(&[0xAAu8; 32])),
            second: Some("!!!bad base64!!!".to_string()),
        }),
    };
    let credential = signed_auth_credential(
        &cred_id,
        &state.challenge,
        "http://localhost:3000",
        1,
        &key_pair,
        Some(ext),
    );
    let result = passki.finish_passkey_authentication(&credential, &state, &stored);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Base64 decode error")
    );
}

// ===== PrfExtensionResult deserialization =====

#[test]
fn test_prf_extension_result_deserializes_enabled_flag() {
    let json = r#"{"enabled": true}"#;
    let result: PrfExtensionResult = serde_json::from_str(json).unwrap();
    assert_eq!(result.enabled, Some(true));
    assert!(result.results.is_none());
}

#[test]
fn test_prf_extension_result_deserializes_results() {
    let first = Passki::base64_encode(&[0xFFu8; 32]);
    let second = Passki::base64_encode(&[0x00u8; 32]);
    let json = format!(r#"{{"results": {{"first": "{first}", "second": "{second}"}}}}"#);
    let result: PrfExtensionResult = serde_json::from_str(&json).unwrap();
    assert!(result.enabled.is_none());
    let results = result.results.unwrap();
    assert_eq!(results.first.unwrap(), first);
    assert_eq!(results.second.unwrap(), second);
}

#[test]
fn test_prf_extension_result_deserializes_partial_results() {
    let first = Passki::base64_encode(b"output");
    let json = format!(r#"{{"results": {{"first": "{first}"}}}}"#);
    let result: PrfExtensionResult = serde_json::from_str(&json).unwrap();
    let results = result.results.unwrap();
    assert!(results.first.is_some());
    assert!(results.second.is_none());
}
