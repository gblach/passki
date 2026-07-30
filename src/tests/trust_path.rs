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

use super::helpers::rp_id_hash;
use crate::{AttestationTrustPolicy, AttestationType, Passki, PasskiError};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use ciborium::Value;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use x509_cert::der::Encode;
use x509_cert::der::asn1::{Any, BitString, OctetString};
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

/// id-ecPublicKey.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// prime256v1 (P-256).
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// ecdsa-with-SHA256.
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// How a freshly issued certificate is allowed to be used.
#[derive(Clone, Copy)]
enum Role {
    /// A CA, optionally limited in how many intermediates may sit below it.
    Ca(Option<u8>),
    /// An end entity, which is what an attestation certificate is.
    Leaf,
}

/// An ES256 key pair together with the certificate that carries its public key.
struct TestCert {
    key_pair: EcdsaKeyPair,
    name: Name,
    der: Vec<u8>,
}

/// Generates a fresh ES256 key pair.
fn generate_key() -> EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap()
}

/// The `SubjectPublicKeyInfo` for an ES256 key pair.
fn spki(key_pair: &EcdsaKeyPair) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: OID_EC_PUBLIC_KEY,
            parameters: Some(Any::from(OID_PRIME256V1)),
        },
        subject_public_key: BitString::from_bytes(key_pair.public_key().as_ref()).unwrap(),
    }
}

/// The Basic Constraints extension matching a role.
fn basic_constraints(role: Role) -> Extension {
    let constraints = match role {
        Role::Ca(path_len_constraint) => BasicConstraints {
            ca: true,
            path_len_constraint,
        },
        Role::Leaf => BasicConstraints {
            ca: false,
            path_len_constraint: None,
        },
    };

    Extension {
        extn_id: BasicConstraints::OID,
        critical: true,
        extn_value: OctetString::new(constraints.to_der().unwrap()).unwrap(),
    }
}

/// A validity period between two absolute instants.
fn validity(not_before: SystemTime, not_after: SystemTime) -> Validity {
    Validity {
        not_before: Time::try_from(not_before).unwrap(),
        not_after: Time::try_from(not_after).unwrap(),
    }
}

/// A validity period covering the present.
fn current() -> Validity {
    let now = SystemTime::now();
    validity(
        now - Duration::from_secs(3600),
        now + Duration::from_secs(3600),
    )
}

/// A validity period that ended an hour ago.
fn expired() -> Validity {
    let now = SystemTime::now();
    validity(
        now - Duration::from_secs(7200),
        now - Duration::from_secs(3600),
    )
}

/// A validity period that starts an hour from now.
fn not_yet_valid() -> Validity {
    let now = SystemTime::now();
    validity(
        now + Duration::from_secs(3600),
        now + Duration::from_secs(7200),
    )
}

/// Assembles and signs a certificate for `subject_key`, issued by `issuer_key`
/// under `issuer_name`.
fn issue_certificate(
    issuer_key: &EcdsaKeyPair,
    issuer_name: &Name,
    subject_key: &EcdsaKeyPair,
    subject_name: &Name,
    role: Role,
    validity: Validity,
) -> Vec<u8> {
    let signature_algorithm = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA256,
        parameters: None,
    };

    let tbs_certificate = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        signature: signature_algorithm.clone(),
        issuer: issuer_name.clone(),
        validity,
        subject: subject_name.clone(),
        subject_public_key_info: spki(subject_key),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![basic_constraints(role)]),
    };

    let rng = SystemRandom::new();
    let signature = issuer_key
        .sign(&rng, &tbs_certificate.to_der().unwrap())
        .unwrap();

    Certificate {
        tbs_certificate,
        signature_algorithm,
        signature: BitString::from_bytes(signature.as_ref()).unwrap(),
    }
    .to_der()
    .unwrap()
}

impl TestCert {
    /// Creates a self-signed root CA.
    fn root(common_name: &str) -> Self {
        Self::root_with(common_name, Role::Ca(None), current())
    }

    /// Creates a self-signed root CA with a specific role and validity period.
    fn root_with(common_name: &str, role: Role, validity: Validity) -> Self {
        let key_pair = generate_key();
        let name = Name::from_str(&format!("CN={}", common_name)).unwrap();
        let der = issue_certificate(&key_pair, &name, &key_pair, &name, role, validity);

        Self {
            key_pair,
            name,
            der,
        }
    }

    /// Issues a certificate below this one.
    fn issue(&self, common_name: &str, role: Role, validity: Validity) -> Self {
        let key_pair = generate_key();
        let name = Name::from_str(&format!("CN={}", common_name)).unwrap();
        let der = issue_certificate(&self.key_pair, &self.name, &key_pair, &name, role, validity);

        Self {
            key_pair,
            name,
            der,
        }
    }

    /// Issues an intermediate CA below this one.
    fn ca(&self, common_name: &str) -> Self {
        self.issue(common_name, Role::Ca(None), current())
    }

    /// Issues an attestation certificate below this one.
    fn leaf(&self, common_name: &str) -> Self {
        self.issue(common_name, Role::Leaf, current())
    }
}

/// Builds a `packed` full-attestation object whose statement is signed by the
/// first certificate of `chain` and commits to `client_data_hash`.
fn packed_attestation_over(chain: &[&TestCert], client_data_hash: &[u8]) -> Vec<u8> {
    let cose_key = vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
        (Value::Integer((-2).into()), Value::Bytes(vec![2u8; 32])), // x
        (Value::Integer((-3).into()), Value::Bytes(vec![3u8; 32])), // y
    ];
    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(cose_key), &mut cose_key_bytes).unwrap();

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash("localhost"));
    auth_data.push(0x45); // UP + AT
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter
    auth_data.extend_from_slice(&[7u8; 16]); // aaguid
    auth_data.extend_from_slice(&[0, 16]); // credIdLen
    auth_data.extend_from_slice(&[1u8; 16]); // credId
    auth_data.extend_from_slice(&cose_key_bytes);

    // In full attestation the attestation key signs, not the credential key.
    let mut signed = auth_data.clone();
    signed.extend_from_slice(client_data_hash);
    let rng = SystemRandom::new();
    let signature = chain[0].key_pair.sign(&rng, &signed).unwrap();

    let att_stmt = vec![
        (Value::Text("alg".to_string()), Value::Integer((-7).into())),
        (
            Value::Text("sig".to_string()),
            Value::Bytes(signature.as_ref().to_vec()),
        ),
        (
            Value::Text("x5c".to_string()),
            Value::Array(
                chain
                    .iter()
                    .map(|cert| Value::Bytes(cert.der.clone()))
                    .collect(),
            ),
        ),
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

    bytes
}

/// Builds a `packed` full-attestation object over a fixed client data hash, and
/// returns both so the caller can hand them to `verify_attestation`.
fn packed_attestation(chain: &[&TestCert]) -> (Vec<u8>, Vec<u8>) {
    let client_data_hash = digest(&SHA256, b"trust path client data").as_ref().to_vec();
    let bytes = packed_attestation_over(chain, &client_data_hash);

    (bytes, client_data_hash)
}

/// A relying party that ignores trust paths, which is the default.
fn passki() -> Passki {
    Passki::new("localhost", &["http://localhost:3000"], "Test")
}

/// A relying party anchored on `roots`.
fn passki_trusting(roots: &[&TestCert], policy: AttestationTrustPolicy) -> Passki {
    let ders: Vec<&[u8]> = roots.iter().map(|root| root.der.as_slice()).collect();
    passki().with_attestation_trust(&ders, policy).unwrap()
}

#[test]
fn test_default_policy_leaves_a_chain_unverified() {
    let foreign = TestCert::root("Passki Foreign Root");
    let leaf = foreign.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf]);

    // No anchors installed, so a chain from anywhere at all still registers.
    let parsed = passki()
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap();

    assert_eq!(parsed.attestation_type, AttestationType::Unverified);
}

#[test]
fn test_chain_to_installed_root_is_basic() {
    let root = TestCert::root("Passki Test Root");
    let leaf = root.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf]);

    let parsed = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap();

    assert_eq!(parsed.attestation_type, AttestationType::Basic);
    assert_eq!(parsed.aaguid, [7u8; 16]);
}

#[test]
fn test_chain_through_an_intermediate_is_accepted() {
    let root = TestCert::root("Passki Test Root");
    let intermediate = root.ca("Passki Test Intermediate");
    let leaf = intermediate.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf, &intermediate]);

    let parsed = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap();

    assert_eq!(parsed.attestation_type, AttestationType::Basic);
}

#[test]
fn test_root_included_in_x5c_is_accepted() {
    // Authenticators may append the root to x5c. It carries no more authority
    // than the installed copy, and must not short-circuit the anchor check.
    let root = TestCert::root("Passki Test Root");
    let leaf = root.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf, &root]);

    let parsed = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap();

    assert_eq!(parsed.attestation_type, AttestationType::Basic);
}

#[test]
fn test_self_signed_root_in_x5c_without_an_anchor_is_rejected() {
    let foreign = TestCert::root("Passki Foreign Root");
    let leaf = foreign.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf, &foreign]);

    let root = TestCert::root("Passki Test Root");
    let err = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(matches!(err, PasskiError::UntrustedAttestation));
}

#[test]
fn test_certificate_from_a_foreign_root_is_rejected() {
    let foreign = TestCert::root("Passki Foreign Root");
    let leaf = foreign.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf]);

    let root = TestCert::root("Passki Test Root");
    let err = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(matches!(err, PasskiError::UntrustedAttestation));
}

#[test]
fn test_anchor_with_the_same_name_but_a_different_key_is_rejected() {
    // The anchor's subject name matches the leaf's issuer, so only its key
    // separates it from the real root. Copying a root's name must not be enough.
    let root = TestCert::root("Passki Test Root");
    let leaf = root.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf]);

    let impostor = TestCert::root("Passki Test Root");
    let err = passki_trusting(&[&impostor], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(matches!(err, PasskiError::UntrustedAttestation));
}

#[test]
fn test_broken_signature_link_inside_the_chain_is_rejected() {
    let root = TestCert::root("Passki Test Root");
    let signing = root.ca("Passki Test Intermediate");
    // A second intermediate with the same subject name but a different key, so
    // name chaining passes and only the signature link fails.
    let decoy = root.ca("Passki Test Intermediate");
    let leaf = signing.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf, &decoy]);

    let err = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(
        matches!(&err, PasskiError::InvalidCertificateChain(m) if m.contains("broken signature link")),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_wrong_issuer_name_is_rejected() {
    let root = TestCert::root("Passki Test Root");
    let intermediate = root.ca("Passki Test Intermediate");
    let other = root.ca("Passki Other Intermediate");
    let leaf = intermediate.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf, &other]);

    let err = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(
        matches!(&err, PasskiError::InvalidCertificateChain(m) if m.contains("issuer name")),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_expired_certificate_is_rejected() {
    let root = TestCert::root("Passki Test Root");
    let leaf = root.issue("Passki Attestation", Role::Leaf, expired());
    let (bytes, client_data_hash) = packed_attestation(&[&leaf]);

    let err = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(
        matches!(&err, PasskiError::InvalidCertificateChain(m) if m.contains("expired")),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_not_yet_valid_certificate_is_rejected() {
    let root = TestCert::root("Passki Test Root");
    let leaf = root.issue("Passki Attestation", Role::Leaf, not_yet_valid());
    let (bytes, client_data_hash) = packed_attestation(&[&leaf]);

    let err = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(
        matches!(&err, PasskiError::InvalidCertificateChain(m) if m.contains("not valid yet")),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_expired_anchor_still_anchors() {
    // A trust anchor is trusted by configuration, so its own validity period is
    // not what decides the outcome.
    let root = TestCert::root_with("Passki Test Root", Role::Ca(None), expired());
    let leaf = root.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf]);

    let parsed = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap();

    assert_eq!(parsed.attestation_type, AttestationType::Basic);
}

#[test]
fn test_non_ca_issuer_is_rejected() {
    let root = TestCert::root("Passki Test Root");
    let impostor = root.leaf("Passki Not A CA");
    let leaf = impostor.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf, &impostor]);

    let err = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(
        matches!(&err, PasskiError::InvalidCertificateChain(m) if m.contains("not a CA")),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_path_length_constraint_is_enforced() {
    // pathLenConstraint 0 permits a leaf directly below, but no intermediate.
    let root = TestCert::root_with("Passki Test Root", Role::Ca(Some(0)), current());
    let intermediate = root.ca("Passki Test Intermediate");
    let leaf = intermediate.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf, &intermediate]);

    let err = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(
        matches!(&err, PasskiError::InvalidCertificateChain(m) if m.contains("path length")),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_chain_without_any_anchor_installed_is_rejected() {
    let root = TestCert::root("Passki Test Root");
    let leaf = root.leaf("Passki Attestation");
    let (bytes, client_data_hash) = packed_attestation(&[&leaf]);

    let passki = passki()
        .with_attestation_trust(&[] as &[&[u8]], AttestationTrustPolicy::VerifyWhenPresent)
        .unwrap();
    let err = passki
        .verify_attestation(&bytes, &client_data_hash)
        .unwrap_err();

    assert!(matches!(err, PasskiError::UntrustedAttestation));
}

#[test]
fn test_unparsable_anchor_is_rejected() {
    let result = passki().with_attestation_trust(
        &[&[0xFF, 0xFE, 0xFD][..]],
        AttestationTrustPolicy::VerifyWhenPresent,
    );

    // Passki is not Debug, so unwrap_err is not available here.
    assert!(matches!(
        result.err(),
        Some(PasskiError::InvalidCertificate(_))
    ));
}

#[test]
fn test_none_format_reports_no_attestation() {
    let attestation_obj = super::helpers::create_test_attestation_object(-7, 0x45);
    let parsed = passki()
        .verify_attestation(&attestation_obj, &[0u8; 32])
        .unwrap();

    assert_eq!(parsed.attestation_type, AttestationType::None);
}

#[test]
fn test_required_policy_rejects_a_statement_without_certificates() {
    let root = TestCert::root("Passki Test Root");
    let attestation_obj = super::helpers::create_test_attestation_object(-7, 0x45);

    let err = passki_trusting(&[&root], AttestationTrustPolicy::Required)
        .verify_attestation(&attestation_obj, &[0u8; 32])
        .unwrap_err();

    assert!(matches!(err, PasskiError::MissingAttestationChain));
}

#[test]
fn test_verify_when_present_accepts_a_statement_without_certificates() {
    let root = TestCert::root("Passki Test Root");
    let attestation_obj = super::helpers::create_test_attestation_object(-7, 0x45);

    let parsed = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent)
        .verify_attestation(&attestation_obj, &[0u8; 32])
        .unwrap();

    assert_eq!(parsed.attestation_type, AttestationType::None);
}

#[test]
fn test_registration_stores_the_attestation_type() {
    use crate::{RegistrationCredential, RegistrationOptions};

    let root = TestCert::root("Passki Test Root");
    let leaf = root.leaf("Passki Attestation");
    let passki = passki_trusting(&[&root], AttestationTrustPolicy::VerifyWhenPresent);

    let (_, state) = passki
        .start_passkey_registration(
            b"test_user_id_1234567890",
            "alice@example.com",
            "Alice",
            RegistrationOptions::default(),
        )
        .unwrap();

    // The statement has to commit to the hash of the real client data JSON.
    let client_data_json =
        super::helpers::create_test_client_data_json(&state.challenge, "http://localhost:3000");
    let client_data_hash = digest(&SHA256, &client_data_json).as_ref().to_vec();
    let attestation_obj = packed_attestation_over(&[&leaf], &client_data_hash);

    let credential = RegistrationCredential {
        credential_id: Passki::base64_encode(&[1u8; 16]),
        public_key: Passki::base64_encode(&attestation_obj),
        client_data_json: Passki::base64_encode(&client_data_json),
        client_extension_results: None,
        authenticator_attachment: None,
    };

    let stored = passki
        .finish_passkey_registration(&credential, &state)
        .unwrap();

    assert_eq!(stored.attestation_type, AttestationType::Basic);
    assert_eq!(stored.aaguid, [7u8; 16]);
}

#[test]
fn test_attestation_type_round_trips_through_json() {
    let stored = crate::StoredPasskey {
        credential_id: vec![1u8; 16],
        public_key: vec![2u8; 32],
        counter: 0,
        algorithm: -7,
        aaguid: [7u8; 16],
        attestation_type: AttestationType::AttCa,
        rk: None,
        be: false,
        bs: false,
    };

    let json = serde_json::to_string(&stored).unwrap();
    assert!(json.contains(r#""attestation_type":"att-ca""#));

    let decoded: crate::StoredPasskey = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.attestation_type, AttestationType::AttCa);
}

#[test]
fn test_stored_passkey_without_attestation_type_deserializes() {
    let json = r#"{
        "credential_id": [1],
        "public_key": [2],
        "counter": 0,
        "algorithm": -7
    }"#;

    let decoded: crate::StoredPasskey = serde_json::from_str(json).unwrap();
    assert_eq!(decoded.attestation_type, AttestationType::None);
}
