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
use super::helpers::{create_eddsa_cose_key, create_es256_cose_key, create_rs256_cose_key, create_test_rsa_keypair};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING,
    RSA_PKCS1_SHA256,
};

// ===== EdDSA signature tests =====

#[test]
fn test_verify_eddsa_valid_signature() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let message = b"test message for EdDSA";
    let signature = key_pair.sign(message);

    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cose_key_bytes = create_eddsa_cose_key(pub_key);

    let result = Passki::verify_eddsa(&cose_key_bytes, message, signature.as_ref());

    assert!(
        result.is_ok(),
        "Valid EdDSA signature should verify successfully"
    );
}

#[test]
fn test_verify_eddsa_invalid_signature() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let message = b"test message";
    let signature = key_pair.sign(message);

    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cose_key_bytes = create_eddsa_cose_key(pub_key);

    // Try to verify with different message
    let wrong_message = b"different message";
    let result = Passki::verify_eddsa(
        &cose_key_bytes,
        wrong_message,
        signature.as_ref(),
    );

    assert!(
        result.is_err(),
        "Invalid EdDSA signature should fail verification"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("EdDSA signature verification failed")
    );
}

#[test]
fn test_verify_eddsa_corrupted_signature() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let message = b"test message";
    let sig = key_pair.sign(message);
    let mut signature = sig.as_ref().to_vec();

    // Corrupt the signature
    signature[0] ^= 0xFF;

    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cose_key_bytes = create_eddsa_cose_key(pub_key);

    let result = Passki::verify_eddsa(&cose_key_bytes, message, &signature);

    assert!(
        result.is_err(),
        "Corrupted signature should fail verification"
    );
}

#[test]
fn test_verify_eddsa_invalid_public_key() {
    let invalid_key = [0xFF; 32]; // Invalid public key
    let cose_key_bytes = create_eddsa_cose_key(&invalid_key);

    let message = b"test message";
    let signature = [0u8; 64];

    let result = Passki::verify_eddsa(&cose_key_bytes, message, &signature);

    assert!(result.is_err(), "Invalid public key should fail");
    // The error could be about invalid key or signature verification failure
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("Invalid Ed25519 public key")
            || error.contains("EdDSA signature verification failed"),
        "Error was: {}",
        error
    );
}

#[test]
fn test_verify_eddsa_wrong_key_length() {
    use ciborium::Value;

    // Create COSE key with wrong x coordinate length
    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(1.into())));
    cose_key.push((Value::Integer(3.into()), Value::Integer((-8).into())));
    cose_key.push((Value::Integer((-1).into()), Value::Integer(6.into())));
    cose_key.push((Value::Integer((-2).into()), Value::Bytes(vec![0u8; 16]))); // Wrong length

    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();

    let message = b"test";
    let signature = [0u8; 64];

    let result = Passki::verify_eddsa(&cose_key_bytes, message, &signature);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid Ed25519 public key length")
    );
}

#[test]
fn test_verify_eddsa_missing_x_coordinate() {
    use ciborium::Value;

    // Create COSE key without x coordinate
    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(1.into())));
    cose_key.push((Value::Integer(3.into()), Value::Integer((-8).into())));
    cose_key.push((Value::Integer((-1).into()), Value::Integer(6.into())));
    // Missing x coordinate (label -2)

    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();

    let message = b"test";
    let signature = [0u8; 64];

    let result = Passki::verify_eddsa(&cose_key_bytes, message, &signature);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Missing x coordinate")
    );
}

#[test]
fn test_verify_eddsa_invalid_cbor() {
    let invalid_cbor = vec![0xFF, 0xFE, 0xFD];
    let message = b"test";
    let signature = [0u8; 64];

    let result = Passki::verify_eddsa(&invalid_cbor, message, &signature);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse COSE key")
    );
}

#[test]
fn test_verify_eddsa_cose_key_not_map() {
    use ciborium::Value;

    // Create COSE key that's not a map (it's an array)
    let cose_key = Value::Array(vec![Value::Integer(1.into())]);
    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&cose_key, &mut cose_key_bytes).unwrap();

    let message = b"test";
    let signature = [0u8; 64];

    let result = Passki::verify_eddsa(&cose_key_bytes, message, &signature);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("COSE key is not a map")
    );
}

// ===== ES256 signature tests =====

#[test]
fn test_verify_es256_valid_signature() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref()).unwrap();

    let message = b"test message for ES256";
    let signature = key_pair.sign(&rng, message).unwrap();

    // Extract x and y coordinates from public key (uncompressed SEC1 format: 0x04 || x || y)
    let public_key_bytes = key_pair.public_key().as_ref();
    let x = &public_key_bytes[1..33];
    let y = &public_key_bytes[33..65];

    let cose_key_bytes = create_es256_cose_key(x, y);

    let result = Passki::verify_es256(&cose_key_bytes, message, signature.as_ref());

    assert!(
        result.is_ok(),
        "Valid ES256 signature should verify successfully"
    );
}

#[test]
fn test_verify_es256_invalid_signature() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref()).unwrap();

    let message = b"test message";
    let signature = key_pair.sign(&rng, message).unwrap();

    let public_key_bytes = key_pair.public_key().as_ref();
    let x = &public_key_bytes[1..33];
    let y = &public_key_bytes[33..65];

    let cose_key_bytes = create_es256_cose_key(x, y);

    // Try to verify with different message
    let wrong_message = b"different message";
    let result = Passki::verify_es256(
        &cose_key_bytes,
        wrong_message,
        signature.as_ref(),
    );

    assert!(
        result.is_err(),
        "Invalid ES256 signature should fail verification"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("ES256 signature verification failed")
    );
}

#[test]
fn test_verify_es256_corrupted_signature() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref()).unwrap();

    let message = b"test message";
    let signature = key_pair.sign(&rng, message).unwrap();

    let public_key_bytes = key_pair.public_key().as_ref();
    let x = &public_key_bytes[1..33];
    let y = &public_key_bytes[33..65];

    let cose_key_bytes = create_es256_cose_key(x, y);

    // Corrupt the signature
    let mut corrupted_sig = signature.as_ref().to_vec();
    corrupted_sig[8] ^= 0xFF; // Corrupt a byte in the DER-encoded signature

    let result = Passki::verify_es256(&cose_key_bytes, message, &corrupted_sig);

    assert!(
        result.is_err(),
        "Corrupted signature should fail verification"
    );
}

#[test]
fn test_verify_es256_missing_x_coordinate() {
    use ciborium::Value;

    // Create COSE key without x coordinate
    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(2.into())));
    cose_key.push((Value::Integer(3.into()), Value::Integer((-7).into())));
    cose_key.push((Value::Integer((-1).into()), Value::Integer(1.into())));
    cose_key.push((Value::Integer((-3).into()), Value::Bytes(vec![0u8; 32]))); // y only

    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();

    let message = b"test";
    let signature = [0u8; 64];

    let result = Passki::verify_es256(&cose_key_bytes, message, &signature);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Missing x coordinate")
    );
}

#[test]
fn test_verify_es256_missing_y_coordinate() {
    use ciborium::Value;

    // Create COSE key without y coordinate
    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(2.into())));
    cose_key.push((Value::Integer(3.into()), Value::Integer((-7).into())));
    cose_key.push((Value::Integer((-1).into()), Value::Integer(1.into())));
    cose_key.push((Value::Integer((-2).into()), Value::Bytes(vec![0u8; 32]))); // x only

    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();

    let message = b"test";
    let signature = [0u8; 64];

    let result = Passki::verify_es256(&cose_key_bytes, message, &signature);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Missing y coordinate")
    );
}

#[test]
fn test_verify_es256_invalid_public_key() {
    // Use invalid coordinates that don't form a valid point on the curve
    let invalid_x = vec![0xFF; 32];
    let invalid_y = vec![0xFF; 32];

    let cose_key_bytes = create_es256_cose_key(&invalid_x, &invalid_y);

    let message = b"test";
    let signature = [0u8; 64];

    let result = Passki::verify_es256(&cose_key_bytes, message, &signature);

    // Invalid public key or signature format causes verification to fail
    assert!(result.is_err());
}

// ===== RS256 signature tests =====

#[test]
fn test_verify_rs256_valid_signature() {
    let rng = SystemRandom::new();
    let (key_pair, n, e) = create_test_rsa_keypair();

    let message = b"test message for RS256";

    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    key_pair.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature).unwrap();

    let cose_key_bytes = create_rs256_cose_key(&n, &e);

    let result = Passki::verify_rs256(&cose_key_bytes, message, &signature);

    assert!(
        result.is_ok(),
        "Valid RS256 signature should verify successfully: {:?}",
        result.err()
    );
}

#[test]
fn test_verify_rs256_invalid_signature() {
    let rng = SystemRandom::new();
    let (key_pair, n, e) = create_test_rsa_keypair();

    let message = b"test message";

    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    key_pair.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature).unwrap();

    let cose_key_bytes = create_rs256_cose_key(&n, &e);

    // Try to verify with different message
    let wrong_message = b"different message";
    let result = Passki::verify_rs256(&cose_key_bytes, wrong_message, &signature);

    assert!(
        result.is_err(),
        "Invalid RS256 signature should fail verification"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("RS256 signature verification failed")
    );
}

#[test]
fn test_verify_rs256_corrupted_signature() {
    let rng = SystemRandom::new();
    let (key_pair, n, e) = create_test_rsa_keypair();

    let message = b"test message";

    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    key_pair.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature).unwrap();

    // Corrupt the signature
    signature[0] ^= 0xFF;

    let cose_key_bytes = create_rs256_cose_key(&n, &e);

    let result = Passki::verify_rs256(&cose_key_bytes, message, &signature);

    assert!(
        result.is_err(),
        "Corrupted signature should fail verification"
    );
}

#[test]
fn test_verify_rs256_missing_modulus() {
    use ciborium::Value;

    // Create COSE key without n (modulus)
    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(3.into())));
    cose_key.push((Value::Integer(3.into()), Value::Integer((-257).into())));
    cose_key.push((Value::Integer((-2).into()), Value::Bytes(vec![1, 0, 1]))); // e only

    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();

    let message = b"test";
    let signature = vec![0u8; 256];

    let result = Passki::verify_rs256(&cose_key_bytes, message, &signature);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Missing n (modulus)")
    );
}

#[test]
fn test_verify_rs256_missing_exponent() {
    use ciborium::Value;

    // Create COSE key without e (exponent)
    let mut cose_key = Vec::new();
    cose_key.push((Value::Integer(1.into()), Value::Integer(3.into())));
    cose_key.push((Value::Integer(3.into()), Value::Integer((-257).into())));
    cose_key.push((Value::Integer((-1).into()), Value::Bytes(vec![0u8; 256]))); // n only

    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();

    let message = b"test";
    let signature = vec![0u8; 256];

    let result = Passki::verify_rs256(&cose_key_bytes, message, &signature);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Missing e (exponent)")
    );
}

#[test]
fn test_verify_rs256_invalid_public_key() {
    // Create invalid RSA key (modulus too small)
    let n = vec![1u8; 32]; // Too small for RSA
    let e = vec![1, 0, 1]; // Standard exponent 65537

    let cose_key_bytes = create_rs256_cose_key(&n, &e);

    let message = b"test";
    let signature = vec![0u8; 32];

    let result = Passki::verify_rs256(&cose_key_bytes, message, &signature);

    assert!(result.is_err(), "Invalid public key should fail");
    // The error could be about invalid key or signature verification failure
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("Invalid RSA public key")
            || error.contains("RS256 signature verification failed"),
        "Error was: {}",
        error
    );
}

// ===== verify_signature dispatch tests =====

#[test]
fn test_verify_signature_eddsa_dispatch() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let message = b"test message";
    let signature = key_pair.sign(message);

    let pub_key: &[u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
    let cose_key_bytes = create_eddsa_cose_key(pub_key);

    let result = Passki::verify_signature(
        &cose_key_bytes,
        -8, // EdDSA algorithm
        message,
        signature.as_ref(),
    );

    assert!(
        result.is_ok(),
        "verify_signature should dispatch to EdDSA correctly"
    );
}

#[test]
fn test_verify_signature_es256_dispatch() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref()).unwrap();

    let message = b"test message";
    let signature = key_pair.sign(&rng, message).unwrap();

    let public_key_bytes = key_pair.public_key().as_ref();
    let x = &public_key_bytes[1..33];
    let y = &public_key_bytes[33..65];

    let cose_key_bytes = create_es256_cose_key(x, y);

    let result = Passki::verify_signature(
        &cose_key_bytes,
        -7, // ES256 algorithm
        message,
        signature.as_ref(),
    );

    assert!(
        result.is_ok(),
        "verify_signature should dispatch to ES256 correctly"
    );
}

#[test]
fn test_verify_signature_rs256_dispatch() {
    let rng = SystemRandom::new();
    let (key_pair, n, e) = create_test_rsa_keypair();

    let message = b"test message";

    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    key_pair.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature).unwrap();

    let cose_key_bytes = create_rs256_cose_key(&n, &e);

    let result = Passki::verify_signature(
        &cose_key_bytes,
        -257, // RS256 algorithm
        message,
        &signature,
    );

    assert!(
        result.is_ok(),
        "verify_signature should dispatch to RS256 correctly: {:?}",
        result.err()
    );
}

#[test]
fn test_verify_signature_unsupported_algorithm() {
    let message = b"test message";
    let signature = [0u8; 64];
    let cose_key_bytes = vec![0u8; 32];

    let result = Passki::verify_signature(
        &cose_key_bytes,
        -999, // Unsupported algorithm
        message,
        &signature,
    );

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Unsupported algorithm: -999")
    );
}

#[test]
fn test_verify_signature_all_supported_algorithms() {
    let algorithms = vec![-8, -7, -257];

    for alg in algorithms {
        let message = b"test";
        let signature = vec![0u8; 64];
        let cose_key_bytes = vec![0u8; 32];

        let result = Passki::verify_signature(&cose_key_bytes, alg, message, &signature);

        // Should not return "Unsupported algorithm" error
        if let Err(e) = result {
            assert!(
                !e.to_string().contains("Unsupported algorithm"),
                "Algorithm {} should be supported",
                alg
            );
        }
    }
}
