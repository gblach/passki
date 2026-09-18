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
use ciborium::Value;

use super::helpers::{
    create_eddsa_cose_key, create_test_attestation_object_with_extensions,
    create_test_auth_client_data_json, create_test_authenticator_data,
    create_test_client_data_json,
};
use crate::*;

use CredentialProtectionPolicy::{
    UserVerificationOptional, UserVerificationOptionalWithCredentialIdList,
    UserVerificationRequired,
};

// flags: AT | UP | UV
const FLAGS: u8 = 0x45;
// flags: AT | UP | UV | ED
const FLAGS_ED: u8 = 0xC5;

fn passki() -> Passki {
    Passki::new("localhost", &["http://localhost:3000"], "Test App")
}

fn start(
    policy: Option<CredentialProtectionPolicy>,
    enforce: Option<bool>,
) -> (RegistrationChallenge, RegistrationState) {
    passki()
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            RegistrationOptions {
                extensions: Some(RegistrationExtensions {
                    credential_protection_policy: policy,
                    enforce_credential_protection_policy: enforce,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap()
}

/// The authenticator extension block reporting `value` as the `credProtect` output.
fn cred_protect_block(value: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(
        &Value::Map(vec![(Value::Text("credProtect".to_string()), value)]),
        &mut bytes,
    )
    .unwrap();
    bytes
}

/// Finishes a registration whose authenticator data reports `output` as the applied level, or no
/// extension block at all when `output` is `None`.
fn finish(state: &RegistrationState, output: Option<Value>) -> Result<StoredPasskey> {
    let attestation_obj = match output {
        Some(value) => create_test_attestation_object_with_extensions(
            -7,
            FLAGS_ED,
            0,
            [0u8; 16],
            &cred_protect_block(value),
        ),
        None => create_test_attestation_object_with_extensions(-7, FLAGS, 0, [0u8; 16], &[]),
    };
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");
    let credential = RegistrationCredential {
        raw_id: Passki::base64_encode(&[1u8; 16]),
        response: RegistrationResponse {
            client_data_json: Passki::base64_encode(&client_data_json),
            attestation_object: Passki::base64_encode(&attestation_obj),
            transports: Vec::new(),
        },
        client_extension_results: None,
        authenticator_attachment: None,
    };

    passki().finish_passkey_registration(&credential, state)
}

fn level(n: u8) -> Option<Value> {
    Some(Value::Integer(n.into()))
}

// Registration challenge serialization

#[test]
fn test_cred_protect_policies_serialize_as_spec_strings() {
    for (policy, expected) in [
        (UserVerificationOptional, "userVerificationOptional"),
        (
            UserVerificationOptionalWithCredentialIdList,
            "userVerificationOptionalWithCredentialIDList",
        ),
        (UserVerificationRequired, "userVerificationRequired"),
    ] {
        let (challenge, _) = start(Some(policy), None);
        let json = serde_json::to_value(&challenge).unwrap();

        assert_eq!(json["extensions"]["credentialProtectionPolicy"], expected);
        assert!(
            json["extensions"]
                .get("enforceCredentialProtectionPolicy")
                .is_none()
        );
    }
}

#[test]
fn test_cred_protect_enforce_flag_in_challenge() {
    let (challenge, _) = start(Some(UserVerificationRequired), Some(true));
    let json = serde_json::to_value(&challenge).unwrap();

    assert_eq!(
        json["extensions"]["enforceCredentialProtectionPolicy"],
        true
    );
}

#[test]
fn test_cred_protect_absent_from_challenge_when_not_requested() {
    let (challenge, _) = start(None, None);
    let json = serde_json::to_value(&challenge).unwrap();

    assert!(
        json["extensions"]
            .get("credentialProtectionPolicy")
            .is_none()
    );
}

// Registration state

#[test]
fn test_cred_protect_required_only_when_enforced() {
    let (_, state) = start(Some(UserVerificationRequired), None);
    assert_eq!(state.required_cred_protect, None);

    let (_, state) = start(Some(UserVerificationRequired), Some(false));
    assert_eq!(state.required_cred_protect, None);

    let (_, state) = start(Some(UserVerificationRequired), Some(true));
    assert_eq!(state.required_cred_protect, Some(UserVerificationRequired));
}

#[test]
fn test_cred_protect_enforcing_the_lowest_level_requires_nothing() {
    let (_, state) = start(Some(UserVerificationOptional), Some(true));
    assert_eq!(state.required_cred_protect, None);
}

#[test]
fn test_registration_state_without_cred_protect_deserializes() {
    let json = r#"{
        "challenge": [1, 2, 3],
        "user": {"id": "dXNlcg", "name": "alice", "displayName": "Alice"},
        "user_verification": "preferred"
    }"#;
    let state: RegistrationState = serde_json::from_str(json).unwrap();

    assert_eq!(state.required_cred_protect, None);
}

// Applied level surfaced on StoredPasskey

#[test]
fn test_cred_protect_levels_stored() {
    for (n, policy) in [
        (1, UserVerificationOptional),
        (2, UserVerificationOptionalWithCredentialIdList),
        (3, UserVerificationRequired),
    ] {
        let (_, state) = start(Some(policy), None);
        let passkey = finish(&state, level(n)).unwrap();

        assert_eq!(passkey.cred_protect, Some(policy));
    }
}

#[test]
fn test_cred_protect_none_when_not_reported() {
    let (_, state) = start(Some(UserVerificationRequired), None);
    let passkey = finish(&state, None).unwrap();

    assert_eq!(passkey.cred_protect, None);
}

#[test]
fn test_cred_protect_stored_when_the_browser_requested_it_alone() {
    let (_, state) = passki()
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            RegistrationOptions::default(),
        )
        .unwrap();
    let passkey = finish(&state, level(2)).unwrap();

    assert_eq!(
        passkey.cred_protect,
        Some(UserVerificationOptionalWithCredentialIdList)
    );
}

#[test]
fn test_cred_protect_rejects_an_unknown_level() {
    for value in [level(0), level(4), Some(Value::Text("3".to_string()))] {
        let (_, state) = start(None, None);
        let err = finish(&state, value).unwrap_err();

        assert!(matches!(err, PasskiError::InvalidAuthenticatorData));
    }
}

// Enforcement

#[test]
fn test_cred_protect_enforced_level_met() {
    let (_, state) = start(
        Some(UserVerificationOptionalWithCredentialIdList),
        Some(true),
    );
    let passkey = finish(&state, level(2)).unwrap();

    assert_eq!(
        passkey.cred_protect,
        Some(UserVerificationOptionalWithCredentialIdList)
    );
}

#[test]
fn test_cred_protect_enforced_level_exceeded() {
    let (_, state) = start(
        Some(UserVerificationOptionalWithCredentialIdList),
        Some(true),
    );
    let passkey = finish(&state, level(3)).unwrap();

    assert_eq!(passkey.cred_protect, Some(UserVerificationRequired));
}

#[test]
fn test_cred_protect_enforced_level_weaker_rejected() {
    let (_, state) = start(Some(UserVerificationRequired), Some(true));
    let err = finish(&state, level(2)).unwrap_err();

    assert!(matches!(
        err,
        PasskiError::CredentialProtectionNotApplied {
            required: UserVerificationRequired,
            applied: Some(UserVerificationOptionalWithCredentialIdList),
        }
    ));
}

#[test]
fn test_cred_protect_enforced_level_not_reported_rejected() {
    let (_, state) = start(Some(UserVerificationRequired), Some(true));
    let err = finish(&state, None).unwrap_err();

    assert!(matches!(
        err,
        PasskiError::CredentialProtectionNotApplied {
            required: UserVerificationRequired,
            applied: None,
        }
    ));
}

#[test]
fn test_cred_protect_unenforced_weaker_level_accepted() {
    let (_, state) = start(Some(UserVerificationRequired), None);
    let passkey = finish(&state, level(1)).unwrap();

    assert_eq!(passkey.cred_protect, Some(UserVerificationOptional));
}

// StoredPasskey serialization

#[test]
fn test_stored_passkey_cred_protect_roundtrip() {
    let (_, state) = start(Some(UserVerificationRequired), None);
    let passkey = finish(&state, level(3)).unwrap();

    let json = serde_json::to_value(&passkey).unwrap();
    assert_eq!(json["cred_protect"], "userVerificationRequired");

    let restored: StoredPasskey = serde_json::from_value(json).unwrap();
    assert_eq!(restored.cred_protect, Some(UserVerificationRequired));
}

#[test]
fn test_stored_passkey_without_cred_protect_deserializes() {
    let (_, state) = start(None, None);
    let passkey = finish(&state, None).unwrap();

    let json = serde_json::to_value(&passkey).unwrap();
    assert!(json.get("cred_protect").is_none());

    let restored: StoredPasskey = serde_json::from_value(json).unwrap();
    assert_eq!(restored.cred_protect, None);
}

// User verification at authentication

fn authenticate(
    cred_protect: Option<CredentialProtectionPolicy>,
    flags: u8,
) -> Result<AuthenticationResult> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cred_id = vec![7u8; 16];

    let stored = StoredPasskey {
        credential_id: cred_id.clone(),
        public_key: create_eddsa_cose_key(pub_key),
        counter: 0,
        algorithm: -8,
        aaguid: [0u8; 16],
        attestation_type: AttestationType::None,
        transports: Vec::new(),
        rk: None,
        large_blob_supported: None,
        cred_protect,
        min_pin_length: None,
        be: false,
        bs: false,
    };
    let (_, state) = passki().start_passkey_authentication(
        std::slice::from_ref(&stored),
        AuthenticationOptions {
            user_verification: UserVerificationRequirement::Preferred,
            ..Default::default()
        },
    );

    let auth_data = create_test_authenticator_data(1, flags);
    let client_data_json =
        create_test_auth_client_data_json(&state.challenge, "http://localhost:3000");
    let client_data_hash = digest::digest(&SHA256, &client_data_json);
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(client_data_hash.as_ref());
    let signature = key_pair.sign(&signed_data);

    let credential = AuthenticationCredential {
        raw_id: Passki::base64_encode(&cred_id),
        response: AuthenticationResponse {
            client_data_json: Passki::base64_encode(&client_data_json),
            authenticator_data: Passki::base64_encode(&auth_data),
            signature: Passki::base64_encode(signature.as_ref()),
            user_handle: None,
        },
        client_extension_results: None,
        authenticator_attachment: None,
    };

    passki().finish_passkey_authentication(&credential, &state, &stored)
}

#[test]
fn test_cred_protect_uv_required_rejects_assertion_without_uv() {
    // flags: UP
    let err = authenticate(Some(UserVerificationRequired), 0x01).unwrap_err();

    assert!(matches!(err, PasskiError::UserVerificationRequired));
}

#[test]
fn test_cred_protect_uv_required_accepts_assertion_with_uv() {
    // flags: UP | UV
    assert!(authenticate(Some(UserVerificationRequired), 0x05).is_ok());
}

#[test]
fn test_cred_protect_lower_levels_accept_assertion_without_uv() {
    for cred_protect in [
        None,
        Some(UserVerificationOptional),
        Some(UserVerificationOptionalWithCredentialIdList),
    ] {
        // flags: UP
        assert!(authenticate(cred_protect, 0x01).is_ok());
    }
}
