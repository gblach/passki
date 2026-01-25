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
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair, RsaKeyPair};

/// Helper function to create a minimal valid attestation object
pub fn create_test_attestation_object(algorithm: i32) -> Vec<u8> {
    use ciborium::Value;

    // Create a minimal authenticator data
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&[0u8; 32]); // rpIdHash
    auth_data.push(0x45); // flags: UP=1, UV=0, AT=1
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter
    auth_data.extend_from_slice(&[0u8; 16]); // aaguid
    auth_data.extend_from_slice(&[0, 16]); // credIdLen = 16
    auth_data.extend_from_slice(&[1u8; 16]); // credId

    // Create a minimal COSE key based on algorithm
    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(2.into()))); // kty: EC2
    cose_key.push((Value::Integer(3.into()), Value::Integer(algorithm.into()))); // alg

    if algorithm == -7 {
        // ES256: P-256 curve
        cose_key.push((Value::Integer((-1).into()), Value::Integer(1.into()))); // crv: P-256
        cose_key.push((Value::Integer((-2).into()), Value::Bytes(vec![2u8; 32]))); // x
        cose_key.push((Value::Integer((-3).into()), Value::Bytes(vec![3u8; 32]))); // y
    } else if algorithm == -8 {
        // EdDSA: Ed25519
        cose_key.push((Value::Integer((-1).into()), Value::Integer(6.into()))); // crv: Ed25519
        cose_key.push((Value::Integer((-2).into()), Value::Bytes(vec![4u8; 32]))); // x
    }

    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();
    auth_data.extend_from_slice(&cose_key_bytes);

    // Create attestation object
    let mut att_obj = Vec::new();
    att_obj.push((
        Value::Text("fmt".to_string()),
        Value::Text("none".to_string()),
    ));
    att_obj.push((Value::Text("authData".to_string()), Value::Bytes(auth_data)));
    att_obj.push((Value::Text("attStmt".to_string()), Value::Map(Vec::new())));

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut result).unwrap();
    result
}

/// Helper function to create valid client data JSON for registration
pub fn create_test_client_data_json(challenge: &[u8], origin: &str) -> Vec<u8> {
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(challenge),
        "origin": origin,
        "crossOrigin": false
    });
    serde_json::to_vec(&client_data).unwrap()
}

/// Helper function to create valid authenticator data for authentication
pub fn create_test_authenticator_data(counter: u32) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&[0u8; 32]); // rpIdHash
    auth_data.push(0x01); // flags: UP=1
    auth_data.extend_from_slice(&counter.to_be_bytes()); // counter
    auth_data
}

/// Helper function to create client data JSON for authentication
pub fn create_test_auth_client_data_json(challenge: &[u8], origin: &str) -> Vec<u8> {
    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": Passki::base64_encode(challenge),
        "origin": origin,
        "crossOrigin": false
    });
    serde_json::to_vec(&client_data).unwrap()
}

/// Helper function to create a valid EdDSA COSE key
pub fn create_eddsa_cose_key(public_key: &[u8; 32]) -> Vec<u8> {
    use ciborium::Value;

    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(1.into()))); // kty: OKP
    cose_key.push((Value::Integer(3.into()), Value::Integer((-8).into()))); // alg: EdDSA
    cose_key.push((Value::Integer((-1).into()), Value::Integer(6.into()))); // crv: Ed25519
    cose_key.push((
        Value::Integer((-2).into()),
        Value::Bytes(public_key.to_vec()),
    )); // x coordinate

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut result).unwrap();
    result
}

/// Helper function to create a valid ES256 COSE key
pub fn create_es256_cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    use ciborium::Value;

    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(2.into()))); // kty: EC2
    cose_key.push((Value::Integer(3.into()), Value::Integer((-7).into()))); // alg: ES256
    cose_key.push((Value::Integer((-1).into()), Value::Integer(1.into()))); // crv: P-256
    cose_key.push((Value::Integer((-2).into()), Value::Bytes(x.to_vec()))); // x coordinate
    cose_key.push((Value::Integer((-3).into()), Value::Bytes(y.to_vec()))); // y coordinate

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut result).unwrap();
    result
}

/// Helper function to create a valid RS256 COSE key
pub fn create_rs256_cose_key(n: &[u8], e: &[u8]) -> Vec<u8> {
    use ciborium::Value;

    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(3.into()))); // kty: RSA
    cose_key.push((Value::Integer(3.into()), Value::Integer((-257).into()))); // alg: RS256
    cose_key.push((Value::Integer((-1).into()), Value::Bytes(n.to_vec()))); // n (modulus)
    cose_key.push((Value::Integer((-2).into()), Value::Bytes(e.to_vec()))); // e (exponent)

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut result).unwrap();
    result
}

/// Helper to create a test RSA key pair and return (key_pair, n, e)
pub fn create_test_rsa_keypair() -> (RsaKeyPair, Vec<u8>, Vec<u8>) {
    let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();

    // Extract public key components from the PKCS#8 structure
    // The public key is in SubjectPublicKeyInfo format
    let pub_key = key_pair.public_key();
    let pub_key_bytes = pub_key.as_ref();

    // Parse the RSA public key to extract n and e
    // RSA public key format: SEQUENCE { n INTEGER, e INTEGER }
    // Skip the outer SEQUENCE tag and length
    let (n, e) = parse_rsa_public_key(pub_key_bytes);

    (key_pair, n, e)
}

/// Parse RSA public key bytes to extract n (modulus) and e (exponent)
fn parse_rsa_public_key(pub_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // RSA public key is DER encoded: SEQUENCE { INTEGER n, INTEGER e }
    let mut pos = 0;

    // Skip SEQUENCE tag (0x30) and read length
    assert_eq!(pub_key_bytes[pos], 0x30);
    pos += 1;
    let (_, len_bytes) = read_der_length(&pub_key_bytes[pos..]);
    pos += len_bytes;

    // Read n (INTEGER)
    assert_eq!(pub_key_bytes[pos], 0x02);
    pos += 1;
    let (n_len, len_bytes) = read_der_length(&pub_key_bytes[pos..]);
    pos += len_bytes;
    let mut n = pub_key_bytes[pos..pos + n_len].to_vec();
    // Remove leading zero if present (used for positive sign in DER)
    if !n.is_empty() && n[0] == 0x00 {
        n.remove(0);
    }
    pos += n_len;

    // Read e (INTEGER)
    assert_eq!(pub_key_bytes[pos], 0x02);
    pos += 1;
    let (e_len, len_bytes) = read_der_length(&pub_key_bytes[pos..]);
    pos += len_bytes;
    let mut e = pub_key_bytes[pos..pos + e_len].to_vec();
    if !e.is_empty() && e[0] == 0x00 {
        e.remove(0);
    }

    (n, e)
}

/// Read DER length encoding, returns (length, bytes_consumed)
fn read_der_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        (len, 1 + num_bytes)
    }
}
