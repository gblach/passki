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
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use ciborium::Value;

fn passki() -> Passki {
    Passki::new("localhost", "http://localhost:3000", "Test")
}

/// Builds a `packed` self-attestation object signed by a freshly generated ES256 key,
/// returning the CBOR attestation object and the client data hash it was signed over.
fn build_packed_self_attestation(alg: i32) -> (Vec<u8>, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();

    // public_key() is the uncompressed point 0x04 || x || y.
    let point = key_pair.public_key().as_ref();
    let x = &point[1..33];
    let y = &point[33..65];

    let cose_key = vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())), // x
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())), // y
    ];
    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash("localhost"));
    auth_data.push(0x45); // UP + AT
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter
    auth_data.extend_from_slice(&[0u8; 16]); // aaguid
    auth_data.extend_from_slice(&[0, 16]); // credIdLen
    auth_data.extend_from_slice(&[1u8; 16]); // credId
    auth_data.extend_from_slice(&cose_key_bytes);

    let client_data_hash = digest(&SHA256, b"test client data").as_ref().to_vec();

    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_data_hash);
    let signature = key_pair.sign(&rng, &signed).unwrap().as_ref().to_vec();

    let att_stmt = vec![
        (Value::Text("alg".to_string()), Value::Integer(alg.into())),
        (Value::Text("sig".to_string()), Value::Bytes(signature)),
    ];

    let att_obj = vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("packed".to_string()),
        ),
        (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
        (Value::Text("attStmt".to_string()), Value::Map(att_stmt)),
    ];
    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut bytes).unwrap();

    (bytes, client_data_hash)
}

#[test]
fn test_verify_packed_self_attestation() {
    let (bytes, client_data_hash) = build_packed_self_attestation(-7);
    let parsed = passki()
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap();

    assert_eq!(parsed.algorithm, -7);
    assert_eq!(parsed.credential_id, vec![1u8; 16]);
}

#[test]
fn test_verify_packed_self_attestation_tampered_signature() {
    let (mut bytes, client_data_hash) = build_packed_self_attestation(-7);
    // Flip the last byte, which falls inside the CBOR-encoded signature.
    *bytes.last_mut().unwrap() ^= 0xFF;

    assert!(
        passki()
            .verify_attestation(&bytes, &client_data_hash)
            .is_err()
    );
}

#[test]
fn test_verify_packed_self_attestation_wrong_client_data_hash() {
    let (bytes, _) = build_packed_self_attestation(-7);
    let wrong_hash = digest(&SHA256, b"different client data").as_ref().to_vec();

    assert!(passki().verify_attestation(&bytes, &wrong_hash).is_err());
}

#[test]
fn test_verify_packed_self_attestation_algorithm_mismatch() {
    // attStmt advertises EdDSA while the credential key is ES256.
    let (bytes, client_data_hash) = build_packed_self_attestation(-8);
    let err = passki()
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(err.to_string().contains("does not match credential key"));
}

#[test]
fn test_verify_attestation_unsupported_format() {
    let attestation_obj = create_test_attestation_object(-7, 0x45);
    // Rewrite fmt from "none" to an unknown value.
    let mut value: Value = ciborium::from_reader(&attestation_obj[..]).unwrap();
    if let Value::Map(entries) = &mut value {
        for (k, v) in entries.iter_mut() {
            if k.as_text() == Some("fmt") {
                *v = Value::Text("not-a-format".to_string());
            }
        }
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();

    let err = passki().verify_attestation(&bytes, &[0u8; 32]).unwrap_err();
    assert!(err.to_string().contains("Unsupported attestation format"));
}

#[test]
fn test_verify_attestation_none_format_succeeds() {
    let attestation_obj = create_test_attestation_object(-7, 0x45);
    let parsed = passki()
        .verify_attestation(&attestation_obj, &[0u8; 32])
        .unwrap();
    assert_eq!(parsed.algorithm, -7);
}

#[test]
fn test_parse_attestation_object_es256() {
    let attestation_obj = create_test_attestation_object(-7, 0x45);
    let result = passki().parse_attestation_object(&attestation_obj);

    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.algorithm, -7);
    assert!(!parsed.public_key.is_empty());
}

#[test]
fn test_parse_attestation_object_eddsa() {
    let attestation_obj = create_test_attestation_object(-8, 0x45);
    let result = passki().parse_attestation_object(&attestation_obj);

    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.algorithm, -8);
    assert!(!parsed.public_key.is_empty());
}

#[test]
fn test_parse_attestation_object_extracts_counter() {
    let attestation_obj = create_test_attestation_object_with_counter(-7, 0x45, 42);
    let parsed = passki().parse_attestation_object(&attestation_obj).unwrap();

    assert_eq!(parsed.counter, 42);
}

#[test]
fn test_parse_attestation_object_excludes_trailing_extension_data() {
    use ciborium::Value;

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash("localhost")); // rpIdHash
    auth_data.push(0xC5); // flags: UP=1, UV=1, AT=1, ED=1
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter
    auth_data.extend_from_slice(&[0u8; 16]); // aaguid
    auth_data.extend_from_slice(&[0, 16]); // credIdLen = 16
    auth_data.extend_from_slice(&[1u8; 16]); // credId

    let cose_key = vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
        (Value::Integer((-2).into()), Value::Bytes(vec![2u8; 32])), // x
        (Value::Integer((-3).into()), Value::Bytes(vec![3u8; 32])), // y
    ];
    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();
    auth_data.extend_from_slice(&cose_key_bytes);

    // Extension data (ED flag) follows the COSE key in authData
    let extensions = vec![(
        Value::Text("credProtect".to_string()),
        Value::Integer(2.into()),
    )];
    let mut extension_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(extensions), &mut extension_bytes).unwrap();
    auth_data.extend_from_slice(&extension_bytes);

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

    let parsed = passki().parse_attestation_object(&bytes).unwrap();

    assert_eq!(
        parsed.public_key, cose_key_bytes,
        "stored public key must contain only the COSE key, not trailing extension data"
    );
}

#[test]
fn test_parse_attestation_object_extracts_credential_id() {
    // The test helper writes credId = [1u8; 16] into the attested credential data
    let attestation_obj = create_test_attestation_object(-7, 0x45);
    let parsed = passki().parse_attestation_object(&attestation_obj).unwrap();

    assert_eq!(parsed.credential_id, vec![1u8; 16]);
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
    let parsed = passki().parse_attestation_object(&attestation_obj).unwrap();

    assert_eq!(parsed.algorithm, -7);

    let cose_key_value: ciborium::Value = ciborium::from_reader(&parsed.public_key[..]).unwrap();
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
