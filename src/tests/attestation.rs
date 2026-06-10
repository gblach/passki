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
    create_test_attestation_object, create_test_attestation_object_with_counter, rp_id_hash,
};
use crate::Passki;

fn passki() -> Passki {
    Passki::new("localhost", "http://localhost:3000", "Test")
}

#[test]
fn test_parse_attestation_object_es256() {
    let attestation_obj = create_test_attestation_object(-7, 0x45);
    let result = passki().parse_attestation_object(&attestation_obj);

    assert!(result.is_ok());
    let (public_key, algorithm, _, _) = result.unwrap();
    assert_eq!(algorithm, -7);
    assert!(!public_key.is_empty());
}

#[test]
fn test_parse_attestation_object_eddsa() {
    let attestation_obj = create_test_attestation_object(-8, 0x45);
    let result = passki().parse_attestation_object(&attestation_obj);

    assert!(result.is_ok());
    let (public_key, algorithm, _, _) = result.unwrap();
    assert_eq!(algorithm, -8);
    assert!(!public_key.is_empty());
}

#[test]
fn test_parse_attestation_object_extracts_counter() {
    let attestation_obj = create_test_attestation_object_with_counter(-7, 0x45, 42);
    let (_, _, _, counter) = passki().parse_attestation_object(&attestation_obj).unwrap();

    assert_eq!(counter, 42);
}

#[test]
fn test_parse_attestation_object_invalid_cbor() {
    let invalid_cbor = vec![0xFF, 0xFE, 0xFD];
    let result = passki().parse_attestation_object(&invalid_cbor);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse attestation object")
    );
}

#[test]
fn test_parse_attestation_object_missing_auth_data() {
    use ciborium::Value;

    let att_obj = vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (Value::Text("attStmt".to_string()), Value::Map(Vec::new())),
    ];

    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut bytes).unwrap();

    let result = passki().parse_attestation_object(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Missing authData"));
}

#[test]
fn test_parse_attestation_object_too_short_auth_data() {
    use ciborium::Value;

    let att_obj = vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(vec![0u8; 36]),
        ),
        (Value::Text("attStmt".to_string()), Value::Map(Vec::new())),
    ];

    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut bytes).unwrap();

    let result = passki().parse_attestation_object(&bytes);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid authenticator data length")
    );
}

#[test]
fn test_parse_attestation_object_no_attested_credential_data() {
    use ciborium::Value;

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash("localhost")); // rpIdHash
    auth_data.push(0x01); // flags: UP=1, UV=0, AT=0 (no attested credential data)
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter

    let att_obj = vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
        (Value::Text("attStmt".to_string()), Value::Map(Vec::new())),
    ];

    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut bytes).unwrap();

    let result = passki().parse_attestation_object(&bytes);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("No attested credential data present")
    );
}

#[test]
fn test_parse_attestation_object_invalid_cose_key() {
    use ciborium::Value;

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash("localhost")); // rpIdHash
    auth_data.push(0x45); // flags: UP=1, UV=0, AT=1
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter
    auth_data.extend_from_slice(&[0u8; 16]); // aaguid
    auth_data.extend_from_slice(&[0, 16]); // credIdLen = 16
    auth_data.extend_from_slice(&[1u8; 16]); // credId

    let cose_key = vec![(Value::Integer(1.into()), Value::Integer(2.into()))]; // kty: EC2 (missing alg)
    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();
    auth_data.extend_from_slice(&cose_key_bytes);

    let att_obj = vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
        (Value::Text("attStmt".to_string()), Value::Map(Vec::new())),
    ];

    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut bytes).unwrap();

    let result = passki().parse_attestation_object(&bytes);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Missing or invalid algorithm")
    );
}

#[test]
fn test_parse_attestation_object_extracts_correct_cose_key() {
    let attestation_obj = create_test_attestation_object(-7, 0x45);
    let (public_key_bytes, algorithm, _, _) =
        passki().parse_attestation_object(&attestation_obj).unwrap();

    assert_eq!(algorithm, -7);

    let cose_key_value: ciborium::Value = ciborium::from_reader(&public_key_bytes[..]).unwrap();
    let cose_map = cose_key_value.as_map().unwrap();

    let alg_value = cose_map
        .iter()
        .find(|(k, _)| k.as_integer() == Some(3.into()))
        .map(|(_, v)| v)
        .unwrap();

    if let ciborium::Value::Integer(i) = alg_value {
        assert_eq!(*i, (-7).into());
    } else {
        panic!("Algorithm is not an integer");
    }

    let x = cose_map
        .iter()
        .find(|(k, _)| k.as_integer() == Some((-2).into()))
        .and_then(|(_, v)| v.as_bytes());
    assert!(x.is_some());
    assert_eq!(x.unwrap().len(), 32);
}
