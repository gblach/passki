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
    create_test_attestation_object, create_test_attestation_object_with_extensions,
};
use crate::*;

// flags: AT | UP | UV
const FLAGS: u8 = 0x45;
// flags: AT | UP | UV | ED
const FLAGS_ED: u8 = 0xC5;

fn passki() -> Passki {
    Passki::new("localhost", &["http://localhost:3000"], "Test App")
}

/// An attestation object whose authenticator data ends with `block`, whatever that is.
fn attestation_object(flags: u8, block: &[u8]) -> Vec<u8> {
    create_test_attestation_object_with_extensions(-7, flags, 0, [0u8; 16], block)
}

/// The CBOR encoding of a value, as an authenticator would write it.
fn encode(value: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    bytes
}

#[test]
fn test_parse_auth_data_reads_extension_outputs() {
    let block = encode(Value::Map(vec![
        (
            Value::Text("credProtect".to_string()),
            Value::Integer(2.into()),
        ),
        (
            Value::Text("minPinLength".to_string()),
            Value::Integer(6.into()),
        ),
    ]));
    let parsed = passki()
        .parse_attestation_object(&attestation_object(FLAGS_ED, &block))
        .unwrap();

    let cred_protect = parsed
        .extensions
        .iter()
        .find(|(k, _)| k.as_text() == Some("credProtect"))
        .and_then(|(_, v)| v.as_integer());
    assert_eq!(cred_protect, Some(2.into()));

    let min_pin_length = parsed
        .extensions
        .iter()
        .find(|(k, _)| k.as_text() == Some("minPinLength"))
        .and_then(|(_, v)| v.as_integer());
    assert_eq!(min_pin_length, Some(6.into()));
}

#[test]
fn test_parse_auth_data_accepts_an_empty_extension_map() {
    let block = encode(Value::Map(Vec::new()));
    let parsed = passki()
        .parse_attestation_object(&attestation_object(FLAGS_ED, &block))
        .unwrap();

    assert!(parsed.extensions.is_empty());
}

#[test]
fn test_parse_auth_data_without_the_ed_flag_has_no_extensions() {
    let parsed = passki()
        .parse_attestation_object(&create_test_attestation_object(-7, FLAGS))
        .unwrap();

    assert!(parsed.extensions.is_empty());
}

#[test]
fn test_parse_auth_data_rejects_extensions_without_the_ed_flag() {
    let block = encode(Value::Map(vec![(
        Value::Text("credProtect".to_string()),
        Value::Integer(2.into()),
    )]));
    let err = passki()
        .parse_attestation_object(&attestation_object(FLAGS, &block))
        .unwrap_err();

    assert!(matches!(err, PasskiError::InvalidAuthenticatorData));
}

#[test]
fn test_parse_auth_data_rejects_a_missing_extension_block() {
    let err = passki()
        .parse_attestation_object(&attestation_object(FLAGS_ED, &[]))
        .unwrap_err();

    assert!(matches!(err, PasskiError::CborDecode(_)));
}

#[test]
fn test_parse_auth_data_rejects_a_truncated_extension_block() {
    // A map header promising one entry, with nothing after it.
    let err = passki()
        .parse_attestation_object(&attestation_object(FLAGS_ED, &[0xa1]))
        .unwrap_err();

    assert!(matches!(err, PasskiError::CborDecode(_)));
}

#[test]
fn test_parse_auth_data_rejects_an_extension_block_that_is_not_a_map() {
    let block = encode(Value::Integer(2.into()));
    let err = passki()
        .parse_attestation_object(&attestation_object(FLAGS_ED, &block))
        .unwrap_err();

    assert!(matches!(err, PasskiError::InvalidAuthenticatorData));
}

#[test]
fn test_parse_auth_data_rejects_bytes_after_the_extension_block() {
    let mut block = encode(Value::Map(vec![(
        Value::Text("credProtect".to_string()),
        Value::Integer(2.into()),
    )]));
    block.push(0x00);

    let err = passki()
        .parse_attestation_object(&attestation_object(FLAGS_ED, &block))
        .unwrap_err();

    assert!(matches!(err, PasskiError::InvalidAuthenticatorData));
}

#[test]
fn test_parse_auth_data_keeps_extension_outputs_out_of_the_public_key() {
    let block = encode(Value::Map(vec![(
        Value::Text("credProtect".to_string()),
        Value::Integer(2.into()),
    )]));
    let with_extensions = passki()
        .parse_attestation_object(&attestation_object(FLAGS_ED, &block))
        .unwrap();
    let without_extensions = passki()
        .parse_attestation_object(&attestation_object(FLAGS, &[]))
        .unwrap();

    assert_eq!(with_extensions.public_key, without_extensions.public_key);
}
