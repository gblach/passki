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

// ===== Registration challenge serialization =====

#[test]
fn test_cred_props_in_challenge_when_requested() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let (challenge, _) = passki.start_passkey_registration(
        b"user123_16bytes_",
        "alice", "Alice", 60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
        Some(RegistrationExtensions { cred_props: Some(true), ..Default::default() }),
    ).unwrap();

    let json = serde_json::to_value(&challenge).unwrap();
    assert_eq!(json["extensions"]["credProps"], true);
}

#[test]
fn test_cred_props_absent_from_challenge_when_not_requested() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let (challenge, _) = passki.start_passkey_registration(
        b"user123_16bytes_",
        "alice", "Alice", 60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
        None,
    ).unwrap();

    let json = serde_json::to_value(&challenge).unwrap();
    assert!(json.get("extensions").is_none());
}

#[test]
fn test_cred_props_and_prf_can_be_requested_together() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test");
    let (challenge, _) = passki.start_passkey_registration(
        b"user123_16bytes_",
        "alice", "Alice", 60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
        Some(RegistrationExtensions {
            cred_props: Some(true),
            prf: Some(PrfInput { eval: None }),
        }),
    ).unwrap();

    let json = serde_json::to_value(&challenge).unwrap();
    assert_eq!(json["extensions"]["credProps"], true);
    assert!(json["extensions"]["prf"].is_object());
}

// ===== RegistrationResult cred_props_rk extraction =====

fn make_credential(state: &RegistrationState, cred_props: Option<CredPropsResult>) -> RegistrationCredential {
    let attestation_obj = create_test_attestation_object(-7, 0x45);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");
    RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: Some(ClientExtensionResults {
            cred_props,
            prf: None,
        }),
    }
}

#[test]
fn test_cred_props_rk_true_surfaced_in_result() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");
    let (_, state) = passki.start_passkey_registration(
        b"user123_16bytes_",
        "testuser", "Test User", 60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
        Some(RegistrationExtensions { cred_props: Some(true), ..Default::default() }),
    ).unwrap();

    let credential = make_credential(&state, Some(CredPropsResult { rk: Some(true) }));
    let result = passki.finish_passkey_registration(&credential, &state).unwrap();
    assert_eq!(result.rk, Some(true));
}

#[test]
fn test_cred_props_rk_false_surfaced_in_result() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");
    let (_, state) = passki.start_passkey_registration(
        b"user123_16bytes_",
        "testuser", "Test User", 60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
        Some(RegistrationExtensions { cred_props: Some(true), ..Default::default() }),
    ).unwrap();

    let credential = make_credential(&state, Some(CredPropsResult { rk: Some(false) }));
    let result = passki.finish_passkey_registration(&credential, &state).unwrap();
    assert_eq!(result.rk, Some(false));
}

#[test]
fn test_cred_props_rk_none_when_no_extension_results() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");
    let (_, state) = passki.start_passkey_registration(
        b"user123_16bytes_",
        "testuser", "Test User", 60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
        None,
    ).unwrap();

    let attestation_obj = create_test_attestation_object(-7, 0x45);
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");
    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: None,
    };

    let result = passki.finish_passkey_registration(&credential, &state).unwrap();
    assert_eq!(result.rk, None);
}

#[test]
fn test_cred_props_rk_none_when_rk_not_reported() {
    let passki = Passki::new("localhost", "http://localhost:3000", "Test App");
    let (_, state) = passki.start_passkey_registration(
        b"user123_16bytes_",
        "testuser", "Test User", 60000,
        AttestationConveyancePreference::None,
        ResidentKeyRequirement::Preferred,
        UserVerificationRequirement::Preferred,
        None,
        Some(RegistrationExtensions { cred_props: Some(true), ..Default::default() }),
    ).unwrap();

    let credential = make_credential(&state, Some(CredPropsResult { rk: None }));
    let result = passki.finish_passkey_registration(&credential, &state).unwrap();
    assert_eq!(result.rk, None);
}

// ===== CredPropsResult deserialization =====

#[test]
fn test_cred_props_result_deserializes_rk_true() {
    let json = r#"{"rk": true}"#;
    let result: CredPropsResult = serde_json::from_str(json).unwrap();
    assert_eq!(result.rk, Some(true));
}

#[test]
fn test_cred_props_result_deserializes_rk_false() {
    let json = r#"{"rk": false}"#;
    let result: CredPropsResult = serde_json::from_str(json).unwrap();
    assert_eq!(result.rk, Some(false));
}

#[test]
fn test_cred_props_result_deserializes_missing_rk_as_none() {
    let json = r#"{}"#;
    let result: CredPropsResult = serde_json::from_str(json).unwrap();
    assert_eq!(result.rk, None);
}

#[test]
fn test_client_extension_results_deserializes_cred_props() {
    let json = r#"{"credProps": {"rk": true}}"#;
    let result: ClientExtensionResults = serde_json::from_str(json).unwrap();
    assert_eq!(result.cred_props.unwrap().rk, Some(true));
    assert!(result.prf.is_none());
}
