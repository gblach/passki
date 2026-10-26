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

//! The RustCrypto backend.

use p256::ecdsa::signature::Verifier;
use rsa::BoxedUint;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256, Sha384};
use x509_cert::der::oid::AssociatedOid;

use crate::types::*;

/// Verifies a DER-encoded ECDSA P-256 signature against a SEC1-encoded point. High-S signatures
/// are accepted, as authenticators are not required to produce low-S ones.
pub(crate) fn verify_es256(key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    let signature = p256::ecdsa::Signature::from_der(signature)
        .map_err(|_| PasskiError::SignatureVerificationFailed)?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
        .and_then(|key| key.verify(signed_data, &signature))
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}

/// Verifies a DER-encoded ECDSA P-384 signature against a SEC1-encoded point.
pub(crate) fn verify_es384(key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    let signature = p384::ecdsa::Signature::from_der(signature)
        .map_err(|_| PasskiError::SignatureVerificationFailed)?;
    p384::ecdsa::VerifyingKey::from_sec1_bytes(key)
        .and_then(|key| key.verify(signed_data, &signature))
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}

/// Verifies an Ed25519 signature against a 32-byte public key.
pub(crate) fn verify_ed25519(key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    let key: &[u8; 32] = key
        .try_into()
        .map_err(|_| PasskiError::SignatureVerificationFailed)?;
    let signature = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| PasskiError::SignatureVerificationFailed)?;
    ed25519_dalek::VerifyingKey::from_bytes(key)
        .and_then(|key| key.verify(signed_data, &signature))
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}

fn verify_rsa_with<D: Digest + AssociatedOid>(
    n: &[u8],
    e: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<()> {
    let n = BoxedUint::from_be_slice_vartime(n);
    let e = BoxedUint::from_be_slice_vartime(e);
    let key = rsa::RsaPublicKey::new(n, e).map_err(|_| PasskiError::SignatureVerificationFailed)?;
    // The upper bound of 8192 bits is enforced by RsaPublicKey::new, the lower one is not.
    if key.n().bits() < 2048 {
        return Err(PasskiError::SignatureVerificationFailed);
    }
    let signature =
        RsaSignature::try_from(signature).map_err(|_| PasskiError::SignatureVerificationFailed)?;
    RsaVerifyingKey::<D>::new(key)
        .verify(signed_data, &signature)
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
    match alg {
        ALG_RS256 => verify_rsa_with::<Sha256>(n, e, signed_data, signature),
        ALG_RS384 => verify_rsa_with::<Sha384>(n, e, signed_data, signature),
        _ => Err(PasskiError::UnsupportedAlgorithm(alg)),
    }
}
