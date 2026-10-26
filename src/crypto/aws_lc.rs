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

//! The aws-lc-rs backend.

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RsaPublicKeyComponents, UnparsedPublicKey,
};

use crate::types::*;

/// Verifies a DER-encoded ECDSA P-256 signature against a SEC1-encoded point.
pub(crate) fn verify_es256(key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
        .verify(signed_data, signature)
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}

/// Verifies a DER-encoded ECDSA P-384 signature against a SEC1-encoded point.
pub(crate) fn verify_es384(key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, key)
        .verify(signed_data, signature)
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}

/// Verifies an Ed25519 signature against a 32-byte public key.
pub(crate) fn verify_ed25519(key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    UnparsedPublicKey::new(&ED25519, key)
        .verify(signed_data, signature)
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}

/// Verifies an RSA PKCS#1 v1.5 signature (RS256 or RS384) given the big-endian modulus and
/// exponent. Moduli outside 2048 to 8192 bits are rejected.
pub(crate) fn verify_rsa(
    alg: i32,
    n: &[u8],
    e: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<()> {
    let params = match alg {
        ALG_RS256 => &RSA_PKCS1_2048_8192_SHA256,
        ALG_RS384 => &RSA_PKCS1_2048_8192_SHA384,
        _ => return Err(PasskiError::UnsupportedAlgorithm(alg)),
    };
    RsaPublicKeyComponents { n, e }
        .verify(params, signed_data, signature)
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}
