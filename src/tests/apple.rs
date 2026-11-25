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

use super::helpers::{create_es256_cose_key, rp_id_hash};
use super::trust_path::{
    Certificate, OID_ECDSA_SHA256, TbsCertificate, TestCert, current, passki, passki_trusting, spki,
};
use crate::{AttestationTrustPolicy, AttestationType, PasskiError};
use ciborium::Value;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::Generate;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use x509_cert::Version;
use x509_cert::der::Encode;
use x509_cert::der::asn1::{BitString, OctetString};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

const OID_APPLE_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113635.100.8.2");

/// Authenticator data registering `credential_key`.
fn auth_data(credential_key: &SigningKey) -> Vec<u8> {
    let point = credential_key.verifying_key().to_sec1_point(false);
    let point = point.as_bytes();

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash("localhost"));
    auth_data.push(0x45); // UP + AT
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter
    auth_data.extend_from_slice(&[0u8; 16]); // aaguid
    auth_data.extend_from_slice(&[0, 16]); // credIdLen
    auth_data.extend_from_slice(&[1u8; 16]); // credId
    auth_data.extend_from_slice(&create_es256_cose_key(&point[1..33], &point[33..65]));
    auth_data
}

/// `SEQUENCE { [1] EXPLICIT OCTET STRING nonce }`
fn nonce_extension(nonce: &[u8]) -> Extension {
    let mut value = vec![
        0x30,
        nonce.len() as u8 + 4,
        0xA1,
        nonce.len() as u8 + 2,
        0x04,
    ];
    value.push(nonce.len() as u8);
    value.extend_from_slice(nonce);

    Extension {
        extn_id: OID_APPLE_NONCE,
        critical: false,
        extn_value: OctetString::new(value).unwrap(),
    }
}

/// A credential certificate for `subject_key`, issued by `root`.
fn credential_cert(
    root: &TestCert,
    subject_key: &SigningKey,
    extensions: Vec<Extension>,
) -> Vec<u8> {
    let signature_algorithm = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA256,
        parameters: None,
    };

    let tbs_certificate = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[0x01]).unwrap(),
        signature: signature_algorithm.clone(),
        issuer: root.name.clone(),
        validity: current(),
        subject: Name::from_str("CN=Passki Apple Credential").unwrap(),
        subject_public_key_info: spki(subject_key, false),
        extensions: Some(extensions),
    };

    let signature: p256::ecdsa::DerSignature =
        root.key_pair.sign(&tbs_certificate.to_der().unwrap());

    Certificate {
        tbs_certificate,
        signature_algorithm,
        signature: BitString::from_bytes(signature.as_ref()).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn attestation_object(fmt: &str, auth_data: Vec<u8>, att_stmt: Vec<(Value, Value)>) -> Vec<u8> {
    let att_obj = vec![
        (Value::Text("fmt".to_string()), Value::Text(fmt.to_string())),
        (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
        (Value::Text("attStmt".to_string()), Value::Map(att_stmt)),
    ];
    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Map(att_obj), &mut bytes).unwrap();
    bytes
}

fn x5c(cert: Vec<u8>) -> Vec<(Value, Value)> {
    vec![(
        Value::Text("x5c".to_string()),
        Value::Array(vec![Value::Bytes(cert)]),
    )]
}

/// An `apple` attestation object for a fresh credential key, with the certificate's nonce
/// computed the way the authenticator does. Returns it with the client data hash and the root.
fn apple_attestation() -> (Vec<u8>, Vec<u8>, TestCert) {
    let root = TestCert::root("Passki Apple Root");
    let credential_key = SigningKey::generate();
    let auth_data = auth_data(&credential_key);
    let client_data_hash = Sha256::digest(b"apple client data").to_vec();

    let mut nonce_to_hash = auth_data.clone();
    nonce_to_hash.extend_from_slice(&client_data_hash);
    let nonce = Sha256::digest(&nonce_to_hash);

    let cert = credential_cert(&root, &credential_key, vec![nonce_extension(&nonce)]);
    let bytes = attestation_object("apple", auth_data, x5c(cert));

    (bytes, client_data_hash, root)
}

fn assert_invalid_attestation<T>(result: crate::Result<T>, message: &str) {
    match result {
        Err(PasskiError::InvalidAttestation(m)) => assert!(m.contains(message), "{m}"),
        Err(e) => panic!("expected InvalidAttestation({message}), got {e:?}"),
        Ok(_) => panic!("expected InvalidAttestation({message}), got Ok"),
    }
}

#[test]
fn test_apple_chain_to_installed_root_is_anon_ca() {
    let (bytes, client_data_hash, root) = apple_attestation();

    let parsed = passki_trusting(&[&root], AttestationTrustPolicy::Required)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap();

    assert_eq!(parsed.attestation_type, AttestationType::AnonCa);
}

#[test]
fn test_apple_default_policy_is_unverified() {
    let (bytes, client_data_hash, _) = apple_attestation();

    let parsed = passki()
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap();

    assert_eq!(parsed.attestation_type, AttestationType::Unverified);
}

#[test]
fn test_apple_from_a_foreign_root_is_rejected() {
    let (bytes, client_data_hash, _) = apple_attestation();
    let other = TestCert::root("Passki Other Root");

    let result = passki_trusting(&[&other], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash);

    assert!(matches!(result, Err(PasskiError::UntrustedAttestation)));
}

#[test]
fn test_apple_nonce_for_other_client_data_is_rejected() {
    let (bytes, _, _) = apple_attestation();
    let other_hash = Sha256::digest(b"other client data").to_vec();

    assert_invalid_attestation(
        passki().verify_attestation(&bytes, &other_hash),
        "nonce does not match",
    );
}

#[test]
fn test_apple_certificate_for_another_key_is_rejected() {
    let root = TestCert::root("Passki Apple Root");
    let auth_data = auth_data(&SigningKey::generate());
    let client_data_hash = Sha256::digest(b"apple client data").to_vec();

    let mut nonce_to_hash = auth_data.clone();
    nonce_to_hash.extend_from_slice(&client_data_hash);
    let nonce = Sha256::digest(&nonce_to_hash);

    let cert = credential_cert(
        &root,
        &SigningKey::generate(),
        vec![nonce_extension(&nonce)],
    );
    let bytes = attestation_object("apple", auth_data, x5c(cert));

    assert_invalid_attestation(
        passki().verify_attestation(&bytes, &client_data_hash),
        "does not match credential key",
    );
}

#[test]
fn test_apple_certificate_without_nonce_is_rejected() {
    let root = TestCert::root("Passki Apple Root");
    let credential_key = SigningKey::generate();
    let cert = credential_cert(&root, &credential_key, Vec::new());
    let bytes = attestation_object("apple", auth_data(&credential_key), x5c(cert));

    let result = passki().verify_attestation(&bytes, &[0u8; 32]);

    assert!(matches!(result, Err(PasskiError::InvalidCertificate(m)) if m.contains("nonce")));
}

#[test]
fn test_apple_without_x5c_is_rejected() {
    let bytes = attestation_object("apple", auth_data(&SigningKey::generate()), Vec::new());

    assert_invalid_attestation(
        passki().verify_attestation(&bytes, &[0u8; 32]),
        "missing x5c",
    );
}
