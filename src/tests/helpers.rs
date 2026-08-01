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
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair, RsaKeyPair};

pub fn rp_id_hash(rp_id: &str) -> Vec<u8> {
    digest::digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec()
}

/// A minimal attestation object with `fmt` `none` and no counter.
pub fn create_test_attestation_object(algorithm: i32, flags: u8) -> Vec<u8> {
    create_test_attestation_object_with_counter(algorithm, flags, 0)
}

/// As above, with a chosen signature counter.
pub fn create_test_attestation_object_with_counter(
    algorithm: i32,
    flags: u8,
    counter: u32,
) -> Vec<u8> {
    create_test_attestation_object_with_aaguid(algorithm, flags, counter, [0u8; 16])
}

/// As above, with a chosen AAGUID.
pub fn create_test_attestation_object_with_aaguid(
    algorithm: i32,
    flags: u8,
    counter: u32,
    aaguid: [u8; 16],
) -> Vec<u8> {
    use ciborium::Value;

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash("localhost")); // rpIdHash
    auth_data.push(flags);
    auth_data.extend_from_slice(&counter.to_be_bytes()); // counter
    auth_data.extend_from_slice(&aaguid); // aaguid
    auth_data.extend_from_slice(&[0, 16]); // credIdLen = 16
    auth_data.extend_from_slice(&[1u8; 16]); // credId

    // The public key, in whatever shape the algorithm calls for.
    let mut cose_key = vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer(algorithm.into())), // alg
    ];

    if algorithm == -7 {
        cose_key.push((Value::Integer((-1).into()), Value::Integer(1.into()))); // crv: P-256
        cose_key.push((Value::Integer((-2).into()), Value::Bytes(vec![2u8; 32]))); // x
        cose_key.push((Value::Integer((-3).into()), Value::Bytes(vec![3u8; 32]))); // y
    } else if algorithm == -8 {
        cose_key.push((Value::Integer((-1).into()), Value::Integer(6.into()))); // crv: Ed25519
        cose_key.push((Value::Integer((-2).into()), Value::Bytes(vec![4u8; 32]))); // x
    }

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

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut result).unwrap();
    result
}

/// Client data JSON as the browser would build it for a registration.
pub fn create_test_client_data_json(challenge: &[u8], origin: &str) -> Vec<u8> {
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": Passki::base64_encode(challenge),
        "origin": origin,
        "crossOrigin": false
    });
    serde_json::to_vec(&client_data).unwrap()
}

/// Authenticator data for an authentication: the 37-byte header alone, with
/// no attested credential data after it.
pub fn create_test_authenticator_data(counter: u32, flags: u8) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash("localhost")); // rpIdHash
    auth_data.push(flags);
    auth_data.extend_from_slice(&counter.to_be_bytes()); // counter
    auth_data
}

/// Client data JSON as the browser would build it for an authentication.
pub fn create_test_auth_client_data_json(challenge: &[u8], origin: &str) -> Vec<u8> {
    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": Passki::base64_encode(challenge),
        "origin": origin,
        "crossOrigin": false
    });
    serde_json::to_vec(&client_data).unwrap()
}

/// An EdDSA COSE key.
pub fn create_eddsa_cose_key(public_key: &[u8; 32]) -> Vec<u8> {
    use ciborium::Value;

    let cose_key = vec![
        (Value::Integer(1.into()), Value::Integer(1.into())), // kty: OKP
        (Value::Integer(3.into()), Value::Integer((-8).into())), // alg: EdDSA
        (Value::Integer((-1).into()), Value::Integer(6.into())), // crv: Ed25519
        (
            Value::Integer((-2).into()),
            Value::Bytes(public_key.to_vec()),
        ), // x coordinate
    ];

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut result).unwrap();
    result
}

/// An ES256 COSE key.
pub fn create_es256_cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    use ciborium::Value;

    let cose_key = vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())), // x coordinate
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())), // y coordinate
    ];

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut result).unwrap();
    result
}

/// An ES384 COSE key.
pub fn create_es384_cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    use ciborium::Value;

    let cose_key = vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer((-35).into())), // alg: ES384
        (Value::Integer((-1).into()), Value::Integer(2.into())), // crv: P-384
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())), // x coordinate
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())), // y coordinate
    ];

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut result).unwrap();
    result
}

/// An RS256 COSE key.
pub fn create_rs256_cose_key(n: &[u8], e: &[u8]) -> Vec<u8> {
    use ciborium::Value;

    let cose_key = vec![
        (Value::Integer(1.into()), Value::Integer(3.into())), // kty: RSA
        (Value::Integer(3.into()), Value::Integer((-257).into())), // alg: RS256
        (Value::Integer((-1).into()), Value::Bytes(n.to_vec())), // n (modulus)
        (Value::Integer((-2).into()), Value::Bytes(e.to_vec())), // e (exponent)
    ];

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut result).unwrap();
    result
}

/// An RS384 COSE key.
pub fn create_rs384_cose_key(n: &[u8], e: &[u8]) -> Vec<u8> {
    use ciborium::Value;

    let cose_key = vec![
        (Value::Integer(1.into()), Value::Integer(3.into())), // kty: RSA
        (Value::Integer(3.into()), Value::Integer((-258).into())), // alg: RS384
        (Value::Integer((-1).into()), Value::Bytes(n.to_vec())), // n (modulus)
        (Value::Integer((-2).into()), Value::Bytes(e.to_vec())), // e (exponent)
    ];

    let mut result = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut result).unwrap();
    result
}

/// A fresh RSA key pair, with its modulus and exponent split out.
pub fn create_test_rsa_keypair() -> (RsaKeyPair, Vec<u8>, Vec<u8>) {
    let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();

    let pub_key = key_pair.public_key();
    let (n, e) = parse_rsa_public_key(pub_key.as_ref());

    (key_pair, n, e)
}

/// Splits a DER `SEQUENCE { n INTEGER, e INTEGER }` into its two integers.
fn parse_rsa_public_key(pub_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pos = 0;

    assert_eq!(pub_key_bytes[pos], 0x30);
    pos += 1;
    let (_, len_bytes) = read_der_length(&pub_key_bytes[pos..]);
    pos += len_bytes;

    assert_eq!(pub_key_bytes[pos], 0x02);
    pos += 1;
    let (n_len, len_bytes) = read_der_length(&pub_key_bytes[pos..]);
    pos += len_bytes;
    let mut n = pub_key_bytes[pos..pos + n_len].to_vec();
    // DER pads with a zero byte to keep the integer positive.
    if !n.is_empty() && n[0] == 0x00 {
        n.remove(0);
    }
    pos += n_len;

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

/// Reads a DER length, returning it with the number of bytes it occupied.
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
