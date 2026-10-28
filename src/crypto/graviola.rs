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

//! The graviola backend.

use graviola::hashing::{Sha256, Sha384};
use graviola::signing::ecdsa::{P256, P384, VerifyingKey as EcdsaVerifyingKey};
use graviola::signing::eddsa::Ed25519VerifyingKey;
use graviola::signing::rsa::VerifyingKey as RsaVerifyingKey;
use x509_cert::der::asn1::UintRef;
use x509_cert::der::{Encode, Header, Tag};

use crate::types::*;

/// Verifies a DER-encoded ECDSA P-256 signature against an uncompressed SEC1 point.
pub(crate) fn verify_es256(key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    EcdsaVerifyingKey::<P256>::from_x962_uncompressed(key)
        .and_then(|key| key.verify_asn1::<Sha256>(&[signed_data], signature))
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}

/// Verifies a DER-encoded ECDSA P-384 signature against an uncompressed SEC1 point.
pub(crate) fn verify_es384(key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    EcdsaVerifyingKey::<P384>::from_x962_uncompressed(key)
        .and_then(|key| key.verify_asn1::<Sha384>(&[signed_data], signature))
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}

/// Verifies an Ed25519 signature against a 32-byte public key.
pub(crate) fn verify_ed25519(key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    Ed25519VerifyingKey::from_bytes(key)
        .and_then(|key| key.verify(signature, signed_data))
        .map_err(|_| PasskiError::SignatureVerificationFailed)
}

/// graviola only builds RSA keys from PKCS#1 DER, so the modulus and exponent are re-encoded as
/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
fn rsa_key_to_pkcs1(n: &[u8], e: &[u8]) -> x509_cert::der::Result<Vec<u8>> {
    let n = UintRef::new(n)?;
    let e = UintRef::new(e)?;
    let mut der = Header::new(Tag::Sequence, (n.encoded_len()? + e.encoded_len()?)?).to_der()?;
    n.encode_to_vec(&mut der)?;
    e.encode_to_vec(&mut der)?;
    Ok(der)
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
    if alg != ALG_RS256 && alg != ALG_RS384 {
        return Err(PasskiError::UnsupportedAlgorithm(alg));
    }
    let der = rsa_key_to_pkcs1(n, e).map_err(|_| PasskiError::SignatureVerificationFailed)?;
    let key = RsaVerifyingKey::from_pkcs1_der(&der)
        .map_err(|_| PasskiError::SignatureVerificationFailed)?;
    match alg {
        ALG_RS256 => key.verify_pkcs1_sha256(signature, signed_data),
        _ => key.verify_pkcs1_sha384(signature, signed_data),
    }
    .map_err(|_| PasskiError::SignatureVerificationFailed)
}
