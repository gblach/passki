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

//! Attestation statement verification.
//!
//! Verifies the `attStmt` of an attestation object for the `packed`, `fido-u2f`,
//! `android-key`, and `tpm` formats. This covers the statement's signature and the
//! structural requirements on the attestation certificate. It does not assess
//! attestation trustworthiness by chaining the certificate up to a trusted root,
//! which is a relying party policy decision.

use aws_lc_rs::digest::{self, SHA256, SHA384};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RsaPublicKeyComponents, UnparsedPublicKey,
};
use ciborium::Value;
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::der::Decode;
use x509_cert::der::asn1::OctetString;
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage};

use crate::Passki;
use crate::registration::ParsedAttestation;
use crate::types::*;

/// id-fido-gen-ce-aaguid: the AAGUID extension carried by attestation certificates.
const OID_FIDO_AAGUID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");
/// Android Keystore key attestation extension.
const OID_ANDROID_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
/// id-ce-subjectAltName.
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
/// tcg-kp-AIKCertificate extended key usage, required of TPM attestation certificates.
const OID_TCG_KP_AIK: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.8.3");

/// A public key extracted from a COSE key or an attestation certificate, used to
/// check that the attestation key matches the credential key.
enum PublicKey {
    Ec { x: Vec<u8>, y: Vec<u8> },
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

impl Passki {
    /// Parses an attestation object, extracts the attested credential data, and
    /// verifies the attestation statement according to its format.
    pub(crate) fn verify_attestation(
        &self,
        attestation_bytes: &[u8],
        client_data_hash: &[u8],
    ) -> Result<ParsedAttestation> {
        let (fmt, auth_data, att_stmt) = Self::split_attestation_object(attestation_bytes)?;
        let parsed = self.parse_auth_data(&auth_data)?;
        let fmt = fmt.ok_or_else(|| PasskiError::new("Missing fmt in attestation"))?;

        match fmt.as_str() {
            "none" => {}
            "packed" => verify_packed(&att_stmt, &auth_data, &parsed, client_data_hash)?,
            "fido-u2f" => verify_fido_u2f(&att_stmt, &auth_data, &parsed, client_data_hash)?,
            "android-key" => verify_android_key(&att_stmt, &auth_data, &parsed, client_data_hash)?,
            "tpm" => verify_tpm(&att_stmt, &auth_data, &parsed, client_data_hash)?,
            other => {
                return Err(Box::new(PasskiError::new(format!(
                    "Unsupported attestation format: {}",
                    other
                ))));
            }
        }

        Ok(parsed)
    }
}

/// Verifies a `packed` attestation statement (full or self attestation).
fn verify_packed(
    att_stmt: &Value,
    auth_data: &[u8],
    parsed: &ParsedAttestation,
    client_data_hash: &[u8],
) -> Result<()> {
    let map = att_map(att_stmt)?;
    let alg = att_int(map, "alg")? as i32;
    let sig = att_bytes(map, "sig")?;

    let mut signed_data = auth_data.to_vec();
    signed_data.extend_from_slice(client_data_hash);

    match att_x5c(map)? {
        Some(x5c) => {
            let cert = parse_cert(&x5c[0])?;
            verify_cert_signature(&cert, alg, &signed_data, sig)?;
            check_cert_version_3(&cert)?;
            check_not_ca(&cert)?;
            check_aaguid_extension(&cert, &parsed.aaguid)?;
        }
        None => {
            // Self attestation: the credential key signs, and the statement's alg
            // must match the credential key's alg.
            if alg != parsed.algorithm {
                return Err(Box::new(PasskiError::new(
                    "packed self-attestation algorithm does not match credential key",
                )));
            }
            Passki::verify_signature(&parsed.public_key, alg, &signed_data, sig)?;
        }
    }

    Ok(())
}

/// Verifies a `fido-u2f` attestation statement.
fn verify_fido_u2f(
    att_stmt: &Value,
    auth_data: &[u8],
    parsed: &ParsedAttestation,
    client_data_hash: &[u8],
) -> Result<()> {
    let map = att_map(att_stmt)?;
    let sig = att_bytes(map, "sig")?;
    let x5c =
        att_x5c(map)?.ok_or_else(|| PasskiError::new("fido-u2f attestation is missing x5c"))?;
    if x5c.len() != 1 {
        return Err(Box::new(PasskiError::new(
            "fido-u2f attestation must contain exactly one certificate",
        )));
    }
    let cert = parse_cert(&x5c[0])?;

    let (x, y) = match cose_public_key(&parsed.public_key)? {
        PublicKey::Ec { x, y } => (x, y),
        PublicKey::Rsa { .. } => {
            return Err(Box::new(PasskiError::new(
                "fido-u2f credential key must be an EC key",
            )));
        }
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(Box::new(PasskiError::new(
            "fido-u2f requires 32-byte P-256 coordinates",
        )));
    }

    // publicKeyU2F = 0x04 || x || y
    let mut public_key_u2f = Vec::with_capacity(65);
    public_key_u2f.push(0x04);
    public_key_u2f.extend_from_slice(&x);
    public_key_u2f.extend_from_slice(&y);

    // verificationData = 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
    let mut verification_data = Vec::new();
    verification_data.push(0x00);
    verification_data.extend_from_slice(&auth_data[..32]);
    verification_data.extend_from_slice(client_data_hash);
    verification_data.extend_from_slice(&parsed.credential_id);
    verification_data.extend_from_slice(&public_key_u2f);

    // fido-u2f signatures are always ES256.
    verify_cert_signature(&cert, ALG_ES256, &verification_data, sig)
}

/// Verifies an `android-key` attestation statement.
fn verify_android_key(
    att_stmt: &Value,
    auth_data: &[u8],
    parsed: &ParsedAttestation,
    client_data_hash: &[u8],
) -> Result<()> {
    let map = att_map(att_stmt)?;
    let alg = att_int(map, "alg")? as i32;
    let sig = att_bytes(map, "sig")?;
    let x5c =
        att_x5c(map)?.ok_or_else(|| PasskiError::new("android-key attestation is missing x5c"))?;
    let cert = parse_cert(&x5c[0])?;

    let mut signed_data = auth_data.to_vec();
    signed_data.extend_from_slice(client_data_hash);
    verify_cert_signature(&cert, alg, &signed_data, sig)?;

    // The certificate's public key must match the credential public key.
    if !cert_key_matches(&cert, &cose_public_key(&parsed.public_key)?)? {
        return Err(Box::new(PasskiError::new(
            "android-key certificate public key does not match credential key",
        )));
    }

    let extension = cert_extension(&cert, &OID_ANDROID_KEY).ok_or_else(|| {
        PasskiError::new(
            "android-key attestation certificate is missing the key attestation extension",
        )
    })?;
    verify_android_key_description(extension, client_data_hash)
}

/// Verifies a `tpm` attestation statement.
fn verify_tpm(
    att_stmt: &Value,
    auth_data: &[u8],
    parsed: &ParsedAttestation,
    client_data_hash: &[u8],
) -> Result<()> {
    let map = att_map(att_stmt)?;
    if att_text(map, "ver")? != "2.0" {
        return Err(Box::new(PasskiError::new("Unsupported TPM version")));
    }
    let alg = att_int(map, "alg")? as i32;
    let sig = att_bytes(map, "sig")?;
    let cert_info = att_bytes(map, "certInfo")?;
    let pub_area = att_bytes(map, "pubArea")?;
    let x5c = att_x5c(map)?.ok_or_else(|| PasskiError::new("tpm attestation is missing x5c"))?;

    // The key in pubArea must match the credential public key.
    let (name_alg, tpm_key) = parse_tpmt_public(pub_area)?;
    if !public_keys_match(&tpm_key, &cose_public_key(&parsed.public_key)?) {
        return Err(Box::new(PasskiError::new(
            "tpm pubArea key does not match credential key",
        )));
    }

    let (magic, attest_type, extra_data, attested_name) = parse_tpms_attest(cert_info)?;
    if magic != 0xff54_4347 {
        return Err(Box::new(PasskiError::new("Invalid TPM_GENERATED_VALUE")));
    }
    if attest_type != 0x8017 {
        return Err(Box::new(PasskiError::new(
            "certInfo is not a TPM_ST_ATTEST_CERTIFY",
        )));
    }

    // extraData must be the hash of (authData || clientDataHash).
    let mut att_to_be_signed = auth_data.to_vec();
    att_to_be_signed.extend_from_slice(client_data_hash);
    if extra_data != digest_for_alg(alg, &att_to_be_signed)? {
        return Err(Box::new(PasskiError::new("certInfo extraData mismatch")));
    }

    // The attested name must be nameAlg || H_nameAlg(pubArea).
    if attested_name != tpm_name(name_alg, pub_area)? {
        return Err(Box::new(PasskiError::new(
            "certInfo attested name mismatch",
        )));
    }

    let cert = parse_cert(&x5c[0])?;
    verify_cert_signature(&cert, alg, cert_info, sig)?;

    check_cert_version_3(&cert)?;
    if !cert.tbs_certificate.subject.0.is_empty() {
        return Err(Box::new(PasskiError::new(
            "tpm certificate subject must be empty",
        )));
    }
    if cert_extension(&cert, &OID_SUBJECT_ALT_NAME).is_none() {
        return Err(Box::new(PasskiError::new(
            "tpm certificate is missing subjectAltName",
        )));
    }
    check_eku_contains(&cert, &OID_TCG_KP_AIK)?;
    check_not_ca(&cert)?;
    check_aaguid_extension(&cert, &parsed.aaguid)?;

    Ok(())
}

// attStmt accessors

/// Returns the entries of an `attStmt` CBOR map.
fn att_map(att_stmt: &Value) -> Result<&Vec<(Value, Value)>> {
    att_stmt
        .as_map()
        .ok_or_else(|| PasskiError::new("attStmt is not a map").into())
}

/// Looks up a text-keyed byte-string field in an `attStmt` map.
fn att_bytes<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a [u8]> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_bytes())
        .map(Vec::as_slice)
        .ok_or_else(|| PasskiError::new(format!("Missing {} in attStmt", key)).into())
}

/// Looks up a text-keyed integer field in an `attStmt` map.
fn att_int(map: &[(Value, Value)], key: &str) -> Result<i64> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| i.try_into().ok())
        .ok_or_else(|| PasskiError::new(format!("Missing {} in attStmt", key)).into())
}

/// Looks up a text-keyed text field in an `attStmt` map.
fn att_text<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_text())
        .ok_or_else(|| PasskiError::new(format!("Missing {} in attStmt", key)).into())
}

/// Returns the `x5c` certificate chain from an `attStmt` map, if present and non-empty.
fn att_x5c(map: &[(Value, Value)]) -> Result<Option<Vec<Vec<u8>>>> {
    let array = match map.iter().find(|(k, _)| k.as_text() == Some("x5c")) {
        Some((_, v)) => v
            .as_array()
            .ok_or_else(|| PasskiError::new("x5c is not an array"))?,
        None => return Ok(None),
    };

    if array.is_empty() {
        return Ok(None);
    }

    let chain = array
        .iter()
        .map(|v| {
            v.as_bytes()
                .cloned()
                .ok_or_else(|| PasskiError::new("x5c entry is not a byte string").into())
        })
        .collect::<Result<Vec<Vec<u8>>>>()?;

    Ok(Some(chain))
}

// Certificate helpers

/// Parses a DER-encoded X.509 certificate.
fn parse_cert(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der)
        .map_err(|e| PasskiError::new(format!("Failed to parse certificate: {}", e)).into())
}

/// Returns the value bytes of the extension with the given OID, if present.
fn cert_extension<'a>(cert: &'a Certificate, oid: &ObjectIdentifier) -> Option<&'a [u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|ext| &ext.extn_id == oid)
        .map(|ext| ext.extn_value.as_bytes())
}

/// Verifies a signature over `signed_data` using the certificate's public key and
/// the given COSE algorithm.
fn verify_cert_signature(
    cert: &Certificate,
    alg: i32,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<()> {
    let key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| PasskiError::new("Invalid certificate public key encoding"))?;
    verify_with_key(alg, key, signed_data, signature)
}

/// Verifies a signature given a raw public key as encoded in a `SubjectPublicKeyInfo`.
fn verify_with_key(alg: i32, key: &[u8], signed_data: &[u8], signature: &[u8]) -> Result<()> {
    match alg {
        ALG_ES256 => UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
            .verify(signed_data, signature)
            .map_err(|_| PasskiError::new("Attestation signature verification failed").into()),
        ALG_ES384 => UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, key)
            .verify(signed_data, signature)
            .map_err(|_| PasskiError::new("Attestation signature verification failed").into()),
        ALG_EDDSA => UnparsedPublicKey::new(&ED25519, key)
            .verify(signed_data, signature)
            .map_err(|_| PasskiError::new("Attestation signature verification failed").into()),
        ALG_RS256 => {
            let (n, e) = parse_rsa_public_key(key)?;
            RsaPublicKeyComponents { n: &n, e: &e }
                .verify(&RSA_PKCS1_2048_8192_SHA256, signed_data, signature)
                .map_err(|_| PasskiError::new("Attestation signature verification failed").into())
        }
        ALG_RS384 => {
            let (n, e) = parse_rsa_public_key(key)?;
            RsaPublicKeyComponents { n: &n, e: &e }
                .verify(&RSA_PKCS1_2048_8192_SHA384, signed_data, signature)
                .map_err(|_| PasskiError::new("Attestation signature verification failed").into())
        }
        _ => Err(Box::new(PasskiError::new(format!(
            "Unsupported attestation algorithm: {}",
            alg
        )))),
    }
}

/// Returns an error unless the certificate is X.509 v3.
fn check_cert_version_3(cert: &Certificate) -> Result<()> {
    if cert.tbs_certificate.version != Version::V3 {
        return Err(Box::new(PasskiError::new(
            "Attestation certificate is not version 3",
        )));
    }
    Ok(())
}

/// Returns an error if the certificate's Basic Constraints mark it as a CA.
fn check_not_ca(cert: &Certificate) -> Result<()> {
    if let Some(value) = cert_extension(cert, &BasicConstraints::OID) {
        let bc = BasicConstraints::from_der(value)
            .map_err(|e| PasskiError::new(format!("Invalid Basic Constraints: {}", e)))?;
        if bc.ca {
            return Err(Box::new(PasskiError::new(
                "Attestation certificate must not be a CA",
            )));
        }
    }
    Ok(())
}

/// Returns an error unless the certificate's extended key usage contains `oid`.
fn check_eku_contains(cert: &Certificate, oid: &ObjectIdentifier) -> Result<()> {
    let value = cert_extension(cert, &ExtendedKeyUsage::OID)
        .ok_or_else(|| PasskiError::new("Attestation certificate is missing extended key usage"))?;
    let eku = ExtendedKeyUsage::from_der(value)
        .map_err(|e| PasskiError::new(format!("Invalid extended key usage: {}", e)))?;
    if !eku.0.contains(oid) {
        return Err(Box::new(PasskiError::new(
            "Attestation certificate has wrong extended key usage",
        )));
    }
    Ok(())
}

/// If the certificate carries the AAGUID extension, verifies it matches `aaguid`.
fn check_aaguid_extension(cert: &Certificate, aaguid: &[u8; 16]) -> Result<()> {
    if let Some(value) = cert_extension(cert, &OID_FIDO_AAGUID) {
        // The extension value is a DER OCTET STRING wrapping the 16-byte AAGUID.
        let wrapped = OctetString::from_der(value)
            .map_err(|e| PasskiError::new(format!("Invalid AAGUID extension: {}", e)))?;
        if wrapped.as_bytes() != aaguid {
            return Err(Box::new(PasskiError::new(
                "Attestation certificate AAGUID does not match authenticator data",
            )));
        }
    }
    Ok(())
}

/// Returns whether the certificate's public key matches the given key.
fn cert_key_matches(cert: &Certificate, key: &PublicKey) -> Result<bool> {
    let cert_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| PasskiError::new("Invalid certificate public key encoding"))?;

    Ok(match key {
        PublicKey::Ec { x, y } => {
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            cert_key == point
        }
        PublicKey::Rsa { n, e } => {
            let (cn, ce) = parse_rsa_public_key(cert_key)?;
            be_eq(&cn, n) && be_eq(&ce, e)
        }
    })
}

// COSE / public key helpers

/// Extracts the public key parameters from a COSE key.
fn cose_public_key(cose_key_bytes: &[u8]) -> Result<PublicKey> {
    let map = Passki::cose_parse(cose_key_bytes)?;
    let kty = map
        .iter()
        .find(|(k, _)| k.as_integer() == Some(1.into()))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| i.try_into().ok())
        .ok_or_else(|| PasskiError::new("Missing kty in COSE key"))?;

    match kty {
        KTY_EC2 => Ok(PublicKey::Ec {
            x: Passki::cose_field(&map, -2, "x coordinate")?.to_vec(),
            y: Passki::cose_field(&map, -3, "y coordinate")?.to_vec(),
        }),
        KTY_RSA => Ok(PublicKey::Rsa {
            n: Passki::cose_field(&map, -1, "n (modulus)")?.to_vec(),
            e: Passki::cose_field(&map, -2, "e (exponent)")?.to_vec(),
        }),
        _ => Err(Box::new(PasskiError::new(
            "Unsupported COSE key type for attestation key matching",
        ))),
    }
}

/// Returns whether a TPM key matches a COSE public key.
fn public_keys_match(tpm_key: &PublicKey, cose_key: &PublicKey) -> bool {
    match (tpm_key, cose_key) {
        (PublicKey::Rsa { n, e }, PublicKey::Rsa { n: cn, e: ce }) => be_eq(n, cn) && be_eq(e, ce),
        (PublicKey::Ec { x, y }, PublicKey::Ec { x: cx, y: cy }) => be_eq(x, cx) && be_eq(y, cy),
        _ => false,
    }
}

/// Computes the digest of `data` using the hash paired with the given COSE algorithm.
fn digest_for_alg(alg: i32, data: &[u8]) -> Result<Vec<u8>> {
    let algorithm = match alg {
        ALG_ES256 | ALG_RS256 => &SHA256,
        ALG_ES384 | ALG_RS384 => &SHA384,
        _ => {
            return Err(Box::new(PasskiError::new(format!(
                "Unsupported attestation algorithm: {}",
                alg
            ))));
        }
    };
    Ok(digest::digest(algorithm, data).as_ref().to_vec())
}

/// Compares two big-endian integers for equality, ignoring leading zero bytes.
fn be_eq(a: &[u8], b: &[u8]) -> bool {
    strip_leading_zeros(a) == strip_leading_zeros(b)
}

/// Strips leading zero bytes from a big-endian integer.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().take_while(|&&b| b == 0).count();
    &bytes[start..]
}

/// Parses a DER `RSAPublicKey` (`SEQUENCE { modulus INTEGER, publicExponent INTEGER }`).
fn parse_rsa_public_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut seq = DerReader::new(der).read_sequence()?;
    let n = seq.read_integer()?;
    let e = seq.read_integer()?;
    Ok((
        strip_leading_zeros(n).to_vec(),
        strip_leading_zeros(e).to_vec(),
    ))
}

/// Verifies the Android key attestation extension (`KeyDescription`).
fn verify_android_key_description(extension: &[u8], client_data_hash: &[u8]) -> Result<()> {
    let mut kd = DerReader::new(extension).read_sequence()?;
    kd.skip()?; // attestationVersion
    kd.skip()?; // attestationSecurityLevel
    kd.skip()?; // keymasterVersion
    kd.skip()?; // keymasterSecurityLevel
    let challenge = kd.read_octet_string()?;
    if challenge != client_data_hash {
        return Err(Box::new(PasskiError::new(
            "android-key attestation challenge does not match client data hash",
        )));
    }
    kd.skip()?; // uniqueId
    let software_enforced = kd.read_sequence_bytes()?;
    let tee_enforced = kd.read_sequence_bytes()?;

    // allApplications must not appear in either list: the key must be bound to this RP.
    if authz_has_all_applications(software_enforced)? || authz_has_all_applications(tee_enforced)? {
        return Err(Box::new(PasskiError::new(
            "android-key attestation must not allow all applications",
        )));
    }

    // origin must be KM_ORIGIN_GENERATED and purpose must contain KM_PURPOSE_SIGN.
    if !authz_origin_and_purpose_ok(tee_enforced)?
        && !authz_origin_and_purpose_ok(software_enforced)?
    {
        return Err(Box::new(PasskiError::new(
            "android-key attestation has wrong key origin or purpose",
        )));
    }

    Ok(())
}

/// AuthorizationList tag for the `allApplications` field.
const KM_TAG_ALL_APPLICATIONS: u32 = 600;
/// AuthorizationList tag for the `origin` field.
const KM_TAG_ORIGIN: u32 = 702;
/// AuthorizationList tag for the `purpose` field.
const KM_TAG_PURPOSE: u32 = 1;
/// KM_ORIGIN_GENERATED: the key was generated in the secure environment.
const KM_ORIGIN_GENERATED: i64 = 0;
/// KM_PURPOSE_SIGN.
const KM_PURPOSE_SIGN: i64 = 2;

/// Returns whether an AuthorizationList contains the `allApplications` field.
fn authz_has_all_applications(list: &[u8]) -> Result<bool> {
    let mut reader = DerReader::new(list);
    while let Some((tag, _)) = reader.next_context_field()? {
        if tag == KM_TAG_ALL_APPLICATIONS {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Returns whether an AuthorizationList has origin KM_ORIGIN_GENERATED and a purpose
/// set that contains KM_PURPOSE_SIGN.
fn authz_origin_and_purpose_ok(list: &[u8]) -> Result<bool> {
    let mut origin_ok = false;
    let mut purpose_ok = false;

    let mut reader = DerReader::new(list);
    while let Some((tag, value)) = reader.next_context_field()? {
        if tag == KM_TAG_ORIGIN {
            // Explicitly tagged INTEGER.
            let origin = DerReader::new(value).read_integer_value()?;
            origin_ok = origin == KM_ORIGIN_GENERATED;
        } else if tag == KM_TAG_PURPOSE {
            // Explicitly tagged SET OF INTEGER.
            let mut set = DerReader::new(value).read_set()?;
            while let Some(int) = set.next_integer_value()? {
                if int == KM_PURPOSE_SIGN {
                    purpose_ok = true;
                }
            }
        }
    }

    Ok(origin_ok && purpose_ok)
}

// TPM structure parsing

/// Parses a `TPMT_PUBLIC`, returning the name algorithm id and the public key.
fn parse_tpmt_public(pub_area: &[u8]) -> Result<(u16, PublicKey)> {
    let mut reader = BeReader::new(pub_area);
    let key_type = reader.u16()?;
    let name_alg = reader.u16()?;
    reader.u32()?; // objectAttributes
    reader.sized_u16()?; // authPolicy

    let key = match key_type {
        0x0001 => {
            // TPMS_RSA_PARMS
            reader.u16()?; // symmetric
            reader.u16()?; // scheme
            reader.u16()?; // keyBits
            let exponent = reader.u32()?;
            let modulus = reader.sized_u16()?;
            let exponent = if exponent == 0 { 65537 } else { exponent };
            PublicKey::Rsa {
                n: modulus.to_vec(),
                e: strip_leading_zeros(&exponent.to_be_bytes()).to_vec(),
            }
        }
        0x0023 => {
            // TPMS_ECC_PARMS
            reader.u16()?; // symmetric
            reader.u16()?; // scheme
            reader.u16()?; // curveID
            reader.u16()?; // kdf
            let x = reader.sized_u16()?.to_vec();
            let y = reader.sized_u16()?.to_vec();
            PublicKey::Ec { x, y }
        }
        _ => {
            return Err(Box::new(PasskiError::new("Unsupported TPM key type")));
        }
    };

    Ok((name_alg, key))
}

/// Parses a `TPMS_ATTEST`, returning `(magic, type, extraData, attested name)`.
fn parse_tpms_attest(cert_info: &[u8]) -> Result<(u32, u16, Vec<u8>, Vec<u8>)> {
    let mut reader = BeReader::new(cert_info);
    let magic = reader.u32()?;
    let attest_type = reader.u16()?;
    reader.sized_u16()?; // qualifiedSigner
    let extra_data = reader.sized_u16()?.to_vec();
    reader.take(17)?; // TPMS_CLOCK_INFO (8 + 4 + 4 + 1)
    reader.take(8)?; // firmwareVersion
    let name = reader.sized_u16()?.to_vec(); // attested TPMS_CERTIFY_INFO name
    Ok((magic, attest_type, extra_data, name))
}

/// Computes the TPM Name of `pub_area`: the 2-byte name algorithm id followed by the
/// digest of `pub_area` under that algorithm.
fn tpm_name(name_alg: u16, pub_area: &[u8]) -> Result<Vec<u8>> {
    let algorithm = match name_alg {
        0x000B => &SHA256,
        0x000C => &SHA384,
        _ => return Err(Box::new(PasskiError::new("Unsupported TPM name algorithm"))),
    };
    let mut name = name_alg.to_be_bytes().to_vec();
    name.extend_from_slice(digest::digest(algorithm, pub_area).as_ref());
    Ok(name)
}

/// A cursor over big-endian TPM structures.
struct BeReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> BeReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.bytes.len())
            .ok_or_else(|| PasskiError::new("Truncated TPM structure"))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a `u16` length followed by that many bytes (a TPM2B buffer).
    fn sized_u16(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }
}

// Minimal DER reader for the structures not covered by the typed x509-cert API.

/// A cursor over a sequence of DER TLV elements.
struct DerReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Reads one TLV element, returning `(class, constructed, tag number, content)`.
    fn read_tlv(&mut self) -> Result<(u8, bool, u32, &'a [u8])> {
        let first = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| PasskiError::new("Truncated DER element"))?;
        self.pos += 1;
        let class = first & 0xC0;
        let constructed = first & 0x20 != 0;

        let mut tag_number = (first & 0x1F) as u32;
        if tag_number == 0x1F {
            // High-tag-number form: base-128 with continuation bits.
            tag_number = 0;
            loop {
                let byte = *self
                    .bytes
                    .get(self.pos)
                    .ok_or_else(|| PasskiError::new("Truncated DER tag"))?;
                self.pos += 1;
                tag_number = (tag_number << 7) | (byte & 0x7F) as u32;
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }

        let first_len = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| PasskiError::new("Truncated DER length"))?;
        self.pos += 1;
        let len = if first_len & 0x80 == 0 {
            first_len as usize
        } else {
            let count = (first_len & 0x7F) as usize;
            let mut len = 0usize;
            for _ in 0..count {
                let byte = *self
                    .bytes
                    .get(self.pos)
                    .ok_or_else(|| PasskiError::new("Truncated DER length"))?;
                self.pos += 1;
                len = (len << 8) | byte as usize;
            }
            len
        };

        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.bytes.len())
            .ok_or_else(|| PasskiError::new("DER length exceeds buffer"))?;
        let content = &self.bytes[self.pos..end];
        self.pos = end;
        Ok((class, constructed, tag_number, content))
    }

    /// Reads a `SEQUENCE` and returns a reader over its content.
    fn read_sequence(&mut self) -> Result<DerReader<'a>> {
        Ok(DerReader::new(self.read_sequence_bytes()?))
    }

    /// Reads a `SEQUENCE` and returns its content bytes.
    fn read_sequence_bytes(&mut self) -> Result<&'a [u8]> {
        let (class, constructed, tag, content) = self.read_tlv()?;
        if class != 0x00 || !constructed || tag != 0x10 {
            return Err(Box::new(PasskiError::new("Expected DER SEQUENCE")));
        }
        Ok(content)
    }

    /// Reads a `SET` and returns a reader over its content.
    fn read_set(&mut self) -> Result<DerReader<'a>> {
        let (class, constructed, tag, content) = self.read_tlv()?;
        if class != 0x00 || !constructed || tag != 0x11 {
            return Err(Box::new(PasskiError::new("Expected DER SET")));
        }
        Ok(DerReader::new(content))
    }

    /// Reads an `INTEGER` and returns its raw content bytes.
    fn read_integer(&mut self) -> Result<&'a [u8]> {
        let (class, constructed, tag, content) = self.read_tlv()?;
        if class != 0x00 || constructed || tag != 0x02 {
            return Err(Box::new(PasskiError::new("Expected DER INTEGER")));
        }
        Ok(content)
    }

    /// Reads an `INTEGER` and returns its value as an `i64`.
    fn read_integer_value(&mut self) -> Result<i64> {
        let content = self.read_integer()?;
        if content.is_empty() || content.len() > 8 {
            return Err(Box::new(PasskiError::new("Unsupported DER INTEGER width")));
        }
        let mut value = if content[0] & 0x80 != 0 { -1i64 } else { 0i64 };
        for &byte in content {
            value = (value << 8) | byte as i64;
        }
        Ok(value)
    }

    /// Reads an `OCTET STRING` and returns its content bytes.
    fn read_octet_string(&mut self) -> Result<&'a [u8]> {
        let (class, constructed, tag, content) = self.read_tlv()?;
        if class != 0x00 || constructed || tag != 0x04 {
            return Err(Box::new(PasskiError::new("Expected DER OCTET STRING")));
        }
        Ok(content)
    }

    /// Skips the next TLV element.
    fn skip(&mut self) -> Result<()> {
        self.read_tlv()?;
        Ok(())
    }

    /// Returns the next context-tagged field as `(tag number, content)`, skipping any
    /// non-context elements. Returns `None` at the end of the buffer.
    fn next_context_field(&mut self) -> Result<Option<(u32, &'a [u8])>> {
        while self.pos < self.bytes.len() {
            let (class, _, tag, content) = self.read_tlv()?;
            if class == 0x80 {
                return Ok(Some((tag, content)));
            }
        }
        Ok(None)
    }

    /// Returns the next `INTEGER` value in the buffer, or `None` at the end.
    fn next_integer_value(&mut self) -> Result<Option<i64>> {
        if self.pos >= self.bytes.len() {
            return Ok(None);
        }
        Ok(Some(self.read_integer_value()?))
    }
}
