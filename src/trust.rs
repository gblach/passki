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

//! Attestation certificate trust path validation.
//!
//! Decides whether the certificate chain of an attestation statement leads back
//! to a root the relying party installed with
//! [`crate::Passki::with_attestation_trust`]. Without that link, a statement
//! proves only that it is internally consistent, and a client can mint its own
//! certificate claiming any hardware model it likes.
//!
//! Deliberately a small subset of RFC 5280 path validation: name chaining,
//! signature links, validity periods and the CA constraints. Name constraints,
//! policy mapping and revocation are left out, since attestation chains are
//! short, vendor-controlled, and have no revocation service to consult.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

use crate::attestation::{cert_extension, parse_cert, tbs_der, verify_with_key};
use crate::types::*;

/// ecdsa-with-SHA256.
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// ecdsa-with-SHA384.
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// sha256WithRSAEncryption.
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// sha384WithRSAEncryption.
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
/// id-Ed25519.
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Maps an X.509 signature algorithm OID to the equivalent COSE identifier, so
/// certificate signatures can reuse the attestation statement verifier.
///
/// RSASSA-PSS is deliberately absent: its hash and salt length live in the
/// algorithm parameters, which a plain identifier cannot carry.
fn cose_alg_for_signature_oid(oid: &ObjectIdentifier) -> Result<i32> {
    match *oid {
        OID_ECDSA_SHA256 => Ok(ALG_ES256),
        OID_ECDSA_SHA384 => Ok(ALG_ES384),
        OID_RSA_SHA256 => Ok(ALG_RS256),
        OID_RSA_SHA384 => Ok(ALG_RS384),
        OID_ED25519 => Ok(ALG_EDDSA),
        _ => Err(PasskiError::InvalidCertificateChain(format!(
            "unsupported signature algorithm {}",
            oid
        ))),
    }
}

/// Returns a certificate's public key as encoded in its `SubjectPublicKeyInfo`.
fn spki_bytes(cert: &Certificate) -> Result<&[u8]> {
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| {
            PasskiError::InvalidCertificateChain(
                "issuer public key is not byte-aligned".to_string(),
            )
        })
}

/// Verifies that `cert`, whose original encoding is `der`, names `issuer` and
/// carries a signature made with the issuer's key.
fn check_issued_by(der: &[u8], cert: &Certificate, issuer: &Certificate) -> Result<()> {
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(PasskiError::InvalidCertificateChain(
            "issuer name does not match the subject of the next certificate".to_string(),
        ));
    }

    let alg = cose_alg_for_signature_oid(&cert.signature_algorithm.oid)?;
    let signature = cert.signature.as_bytes().ok_or_else(|| {
        PasskiError::InvalidCertificateChain("signature is not byte-aligned".to_string())
    })?;

    verify_with_key(alg, spki_bytes(issuer)?, tbs_der(der)?, signature)
        .map_err(|_| PasskiError::InvalidCertificateChain("broken signature link".to_string()))
}

/// Returns an error unless `now` falls inside the certificate's validity period.
fn check_validity(cert: &Certificate, now: Duration) -> Result<()> {
    let validity = &cert.tbs_certificate.validity;

    if now < validity.not_before.to_unix_duration() {
        return Err(PasskiError::InvalidCertificateChain(
            "certificate is not valid yet".to_string(),
        ));
    }
    if now > validity.not_after.to_unix_duration() {
        return Err(PasskiError::InvalidCertificateChain(
            "certificate has expired".to_string(),
        ));
    }

    Ok(())
}

/// Returns an error unless the certificate is allowed to issue the one below it.
///
/// `intermediates_below` is how many CA certificates sit between this one and
/// the leaf, which is what a certificate's `pathLenConstraint` caps.
fn check_can_issue(cert: &Certificate, intermediates_below: usize) -> Result<()> {
    let value = cert_extension(cert, &BasicConstraints::OID).ok_or_else(|| {
        PasskiError::InvalidCertificateChain(
            "issuing certificate has no Basic Constraints".to_string(),
        )
    })?;
    let basic_constraints = BasicConstraints::from_der(value).map_err(|e| {
        PasskiError::InvalidCertificateChain(format!("Invalid Basic Constraints: {}", e))
    })?;

    if !basic_constraints.ca {
        return Err(PasskiError::InvalidCertificateChain(
            "issuing certificate is not a CA".to_string(),
        ));
    }
    if let Some(max) = basic_constraints.path_len_constraint
        && intermediates_below > max as usize
    {
        return Err(PasskiError::InvalidCertificateChain(
            "path length constraint exceeded".to_string(),
        ));
    }

    // Key usage is optional, but a CA that states one must have listed
    // certificate signing among the uses it allows.
    if let Some(value) = cert_extension(cert, &KeyUsage::OID) {
        let key_usage = KeyUsage::from_der(value).map_err(|e| {
            PasskiError::InvalidCertificateChain(format!("Invalid key usage: {}", e))
        })?;
        if !key_usage.key_cert_sign() {
            return Err(PasskiError::InvalidCertificateChain(
                "issuing certificate may not sign certificates".to_string(),
            ));
        }
    }

    Ok(())
}

/// The current time as a duration since the Unix epoch.
fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Validates an attestation certificate chain against the installed roots.
///
/// `chain` is DER-encoded and ordered leaf first, as `x5c` requires. Some
/// authenticators append the root and some do not; either way it counts only
/// because it matches an installed one.
pub(crate) fn validate_trust_path(chain: &[Vec<u8>], anchors: &[Certificate]) -> Result<()> {
    if anchors.is_empty() {
        return Err(PasskiError::UntrustedAttestation);
    }

    let mut certificates = chain
        .iter()
        .map(|der| parse_cert(der))
        .collect::<Result<Vec<_>>>()?;

    // An appended root carries no more authority than our own copy of it, so
    // drop it and let the search below decide.
    let root_included = certificates.len() > 1
        && certificates
            .last()
            .is_some_and(|last| anchors.contains(last));
    if root_included {
        certificates.pop();
    }

    let deadline = now();
    for certificate in &certificates {
        check_validity(certificate, deadline)?;
    }

    // Walk upwards: the certificate at i + 1 issued the one at i, and has i
    // intermediates below it, indices 1 through i, since index 0 is the leaf.
    for (i, link) in certificates.windows(2).enumerate() {
        check_issued_by(&chain[i], &link[0], &link[1])?;
        check_can_issue(&link[1], i)?;
    }

    let last = certificates.last().ok_or_else(|| {
        PasskiError::InvalidCertificateChain("chain contains no certificates".to_string())
    })?;
    let intermediates_below = certificates.len() - 1;

    // Name and signature pick out which root was meant. Whether that root was
    // allowed to issue the chain is asked separately below, so a misconfigured
    // root does not report as "no root matched".
    let anchor = anchors
        .iter()
        .find(|anchor| check_issued_by(&chain[intermediates_below], last, anchor).is_ok())
        .ok_or(PasskiError::UntrustedAttestation)?;

    // A root is trusted by configuration, so its validity period and
    // self-signature are not re-checked, only its authority to issue.
    check_can_issue(anchor, intermediates_below)
}
