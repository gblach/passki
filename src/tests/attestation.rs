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

use crate::Passki;
use super::helpers::create_test_attestation_object;

#[test]
fn test_parse_attestation_object_es256() {
    let attestation_obj = create_test_attestation_object(-7);
    let result = Passki::parse_attestation_object(&attestation_obj);

    assert!(result.is_ok());
    let (public_key, algorithm) = result.unwrap();
    assert_eq!(algorithm, -7);
    assert!(!public_key.is_empty());
}

#[test]
fn test_parse_attestation_object_eddsa() {
    let attestation_obj = create_test_attestation_object(-8);
    let result = Passki::parse_attestation_object(&attestation_obj);

    assert!(result.is_ok());
    let (public_key, algorithm) = result.unwrap();
    assert_eq!(algorithm, -8);
    assert!(!public_key.is_empty());
}

#[test]
fn test_parse_attestation_object_invalid_cbor() {
    let invalid_cbor = vec![0xFF, 0xFE, 0xFD];
    let result = Passki::parse_attestation_object(&invalid_cbor);

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

    // Create attestation object without authData
    let mut att_obj = Vec::new();
    att_obj.push((
        Value::Text("fmt".to_string()),
        Value::Text("none".to_string()),
    ));
    att_obj.push((Value::Text("attStmt".to_string()), Value::Map(Vec::new())));

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut result).unwrap();

    let parse_result = Passki::parse_attestation_object(&result);
    assert!(parse_result.is_err());
    assert!(
        parse_result
            .unwrap_err()
            .to_string()
            .contains("Missing authData")
    );
}

#[test]
fn test_parse_attestation_object_too_short_auth_data() {
    use ciborium::Value;

    // Create attestation object with too short authData
    let mut att_obj = Vec::new();
    att_obj.push((
        Value::Text("fmt".to_string()),
        Value::Text("none".to_string()),
    ));
    att_obj.push((
        Value::Text("authData".to_string()),
        Value::Bytes(vec![0u8; 36]),
    )); // Too short
    att_obj.push((Value::Text("attStmt".to_string()), Value::Map(Vec::new())));

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut result).unwrap();

    let parse_result = Passki::parse_attestation_object(&result);
    assert!(parse_result.is_err());
    assert!(
        parse_result
            .unwrap_err()
            .to_string()
            .contains("Invalid authenticator data length")
    );
}

#[test]
fn test_parse_attestation_object_no_attested_credential_data() {
    use ciborium::Value;

    // Create authenticator data without AT flag set
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&[0u8; 32]); // rpIdHash
    auth_data.push(0x01); // flags: UP=1, UV=0, AT=0 (no attested credential data)
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter

    let mut att_obj = Vec::new();
    att_obj.push((
        Value::Text("fmt".to_string()),
        Value::Text("none".to_string()),
    ));
    att_obj.push((Value::Text("authData".to_string()), Value::Bytes(auth_data)));
    att_obj.push((Value::Text("attStmt".to_string()), Value::Map(Vec::new())));

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut result).unwrap();

    let parse_result = Passki::parse_attestation_object(&result);
    assert!(parse_result.is_err());
    assert!(
        parse_result
            .unwrap_err()
            .to_string()
            .contains("No attested credential data present")
    );
}

#[test]
fn test_parse_attestation_object_invalid_cose_key() {
    use ciborium::Value;

    // Create authenticator data with invalid COSE key (missing algorithm)
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&[0u8; 32]); // rpIdHash
    auth_data.push(0x45); // flags: UP=1, UV=0, AT=1
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter
    auth_data.extend_from_slice(&[0u8; 16]); // aaguid
    auth_data.extend_from_slice(&[0, 16]); // credIdLen = 16
    auth_data.extend_from_slice(&[1u8; 16]); // credId

    // Create COSE key without algorithm field
    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(2.into()))); // kty: EC2
    // Missing algorithm field (key 3)

    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();
    auth_data.extend_from_slice(&cose_key_bytes);

    let mut att_obj = Vec::new();
    att_obj.push((
        Value::Text("fmt".to_string()),
        Value::Text("none".to_string()),
    ));
    att_obj.push((Value::Text("authData".to_string()), Value::Bytes(auth_data)));
    att_obj.push((Value::Text("attStmt".to_string()), Value::Map(Vec::new())));

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut result).unwrap();

    let parse_result = Passki::parse_attestation_object(&result);
    assert!(parse_result.is_err());
    assert!(
        parse_result
            .unwrap_err()
            .to_string()
            .contains("Missing or invalid algorithm")
    );
}

#[test]
fn test_parse_attestation_object_extracts_correct_cose_key() {
    let attestation_obj = create_test_attestation_object(-7);
    let (public_key_bytes, algorithm) = Passki::parse_attestation_object(&attestation_obj).unwrap();

    // Verify the returned algorithm matches
    assert_eq!(algorithm, -7);

    // Parse the stored COSE key to verify it contains the expected data
    let cose_key_value: ciborium::Value = ciborium::from_reader(&public_key_bytes[..]).unwrap();
    let cose_map = cose_key_value.as_map().unwrap();

    // Verify algorithm is stored in the COSE key
    let alg_value = cose_map
        .iter()
        .find(|(k, _)| k.as_integer() == Some(3.into()))
        .map(|(_, v)| v)
        .unwrap();

    // Check the algorithm value matches
    if let ciborium::Value::Integer(i) = alg_value {
        assert_eq!(*i, (-7).into());
    } else {
        panic!("Algorithm is not an integer");
    }

    // Verify coordinates are present for ES256
    let x = cose_map
        .iter()
        .find(|(k, _)| k.as_integer() == Some((-2).into()))
        .and_then(|(_, v)| v.as_bytes());
    assert!(x.is_some());
    assert_eq!(x.unwrap().len(), 32);
}
