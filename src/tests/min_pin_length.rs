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

use ciborium::Value;

use super::helpers::{
    create_test_attestation_object_with_extensions, create_test_client_data_json,
};
use crate::*;

// flags: AT | UP | UV
const FLAGS: u8 = 0x45;
// flags: AT | UP | UV | ED
const FLAGS_ED: u8 = 0xC5;

fn passki() -> Passki {
    Passki::new("localhost", &["http://localhost:3000"], "Test App")
}

fn start(min_pin_length: Option<bool>) -> (RegistrationChallenge, RegistrationState) {
    passki()
        .start_passkey_registration(
            b"user123_16bytes_",
            "alice",
            "Alice",
            RegistrationOptions {
                extensions: Some(RegistrationExtensions {
                    min_pin_length,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap()
}

/// The authenticator extension block holding `entries`.
fn extension_block(entries: Vec<(&str, Value)>) -> Vec<u8> {
    let map = entries
        .into_iter()
        .map(|(k, v)| (Value::Text(k.to_string()), v))
        .collect();
    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut bytes).unwrap();
    bytes
}

/// Finishes a registration whose authenticator data carries `entries` as its extension outputs,
/// or no extension block at all when `entries` is empty.
fn finish(state: &RegistrationState, entries: Vec<(&str, Value)>) -> Result<StoredPasskey> {
    let attestation_obj = if entries.is_empty() {
        create_test_attestation_object_with_extensions(-7, FLAGS, 0, [0u8; 16], &[])
    } else {
        create_test_attestation_object_with_extensions(
            -7,
            FLAGS_ED,
            0,
            [0u8; 16],
            &extension_block(entries),
        )
    };
    let client_data_json = create_test_client_data_json(&state.challenge, "http://localhost:3000");
    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: None,
        authenticator_attachment: None,
        transports: Vec::new(),
    };

    passki().finish_passkey_registration(&credential, state)
}

fn length(n: i64) -> Vec<(&'static str, Value)> {
    vec![("minPinLength", Value::Integer(n.into()))]
}

// Registration challenge serialization

#[test]
fn test_min_pin_length_in_challenge() {
    let (challenge, _) = start(Some(true));
    let json = serde_json::to_value(&challenge).unwrap();

    assert_eq!(json["extensions"]["minPinLength"], true);
}

#[test]
fn test_min_pin_length_absent_from_challenge_when_not_requested() {
    let (challenge, _) = start(None);
    let json = serde_json::to_value(&challenge).unwrap();

    assert!(json["extensions"].get("minPinLength").is_none());
}

// Reported length surfaced on StoredPasskey

#[test]
fn test_min_pin_length_stored() {
    let (_, state) = start(Some(true));
    let passkey = finish(&state, length(8)).unwrap();

    assert_eq!(passkey.min_pin_length, Some(8));
}

#[test]
fn test_min_pin_length_none_when_not_reported() {
    let (_, state) = start(Some(true));
    let passkey = finish(&state, Vec::new()).unwrap();

    assert_eq!(passkey.min_pin_length, None);
}

#[test]
fn test_min_pin_length_stored_beside_cred_protect() {
    let (_, state) = start(Some(true));
    let passkey = finish(
        &state,
        vec![
            ("credProtect", Value::Integer(2.into())),
            ("minPinLength", Value::Integer(6.into())),
        ],
    )
    .unwrap();

    assert_eq!(passkey.min_pin_length, Some(6));
    assert_eq!(
        passkey.cred_protect,
        Some(CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList)
    );
}

#[test]
fn test_min_pin_length_rejects_a_malformed_value() {
    for entries in [
        length(-1),
        length(256),
        vec![("minPinLength", Value::Text("8".to_string()))],
        vec![("minPinLength", Value::Bool(true))],
    ] {
        let (_, state) = start(Some(true));
        let err = finish(&state, entries).unwrap_err();

        assert!(matches!(err, PasskiError::InvalidAuthenticatorData));
    }
}

// StoredPasskey serialization

#[test]
fn test_stored_passkey_min_pin_length_roundtrip() {
    let (_, state) = start(Some(true));
    let passkey = finish(&state, length(8)).unwrap();

    let json = serde_json::to_value(&passkey).unwrap();
    assert_eq!(json["min_pin_length"], 8);

    let restored: StoredPasskey = serde_json::from_value(json).unwrap();
    assert_eq!(restored.min_pin_length, Some(8));
}

#[test]
fn test_stored_passkey_without_min_pin_length_deserializes() {
    let (_, state) = start(None);
    let passkey = finish(&state, Vec::new()).unwrap();

    let json = serde_json::to_value(&passkey).unwrap();
    assert!(json.get("min_pin_length").is_none());

    let restored: StoredPasskey = serde_json::from_value(json).unwrap();
    assert_eq!(restored.min_pin_length, None);
}
