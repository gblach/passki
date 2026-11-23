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

use crate::PasskiError;
use crate::attestation::{PublicKey, parse_tpms_attest, parse_tpmt_public, public_keys_match};

const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_ECDAA: u16 = 0x001A;
const TPM_ALG_KDF1_SP800_56A: u16 = 0x0020;
const TPM_ECC_NIST_P256: u16 = 0x0003;
const TPM_ECC_NIST_P384: u16 = 0x0004;

fn sized(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn header(key_type: u16) -> Vec<u8> {
    let mut out = key_type.to_be_bytes().to_vec();
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.extend_from_slice(&0x0004_0072u32.to_be_bytes()); // objectAttributes
    out.extend_from_slice(&sized(&[])); // authPolicy
    out
}

/// Builds a `TPMT_PUBLIC` for an ECC key. `symmetric`, `scheme` and `kdf` are the encoded
/// algorithm id followed by its details.
fn ecc_pub_area(symmetric: &[u8], scheme: &[u8], curve_id: u16, kdf: &[u8]) -> Vec<u8> {
    let mut out = header(0x0023);
    out.extend_from_slice(symmetric);
    out.extend_from_slice(scheme);
    out.extend_from_slice(&curve_id.to_be_bytes());
    out.extend_from_slice(kdf);
    out.extend_from_slice(&sized(&[0x11; 32]));
    out.extend_from_slice(&sized(&[0x22; 32]));
    out
}

fn rsa_pub_area(symmetric: &[u8], scheme: &[u8]) -> Vec<u8> {
    let mut out = header(0x0001);
    out.extend_from_slice(symmetric);
    out.extend_from_slice(scheme);
    out.extend_from_slice(&2048u16.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // exponent: 0 means 65537
    out.extend_from_slice(&sized(&[0xC3; 256]));
    out
}

fn alg(id: u16, details: &[u16]) -> Vec<u8> {
    let mut out = id.to_be_bytes().to_vec();
    for detail in details {
        out.extend_from_slice(&detail.to_be_bytes());
    }
    out
}

fn null() -> Vec<u8> {
    alg(TPM_ALG_NULL, &[])
}

fn cert_info(qualified_name: &[u8]) -> Vec<u8> {
    let mut out = 0xff54_4347u32.to_be_bytes().to_vec();
    out.extend_from_slice(&0x8017u16.to_be_bytes());
    out.extend_from_slice(&sized(&[0xAA; 34])); // qualifiedSigner
    out.extend_from_slice(&sized(&[0xBB; 32])); // extraData
    out.extend_from_slice(&[0; 17]); // clockInfo
    out.extend_from_slice(&[0; 8]); // firmwareVersion
    out.extend_from_slice(&sized(&[0xCC; 34])); // name
    out.extend_from_slice(&sized(qualified_name));
    out
}

fn assert_invalid_attestation<T>(result: crate::Result<T>, message: &str) {
    match result {
        Err(PasskiError::InvalidAttestation(m)) => assert_eq!(m, message),
        Err(e) => panic!("expected InvalidAttestation({message}), got {e:?}"),
        Ok(_) => panic!("expected InvalidAttestation({message}), got Ok"),
    }
}

#[test]
fn test_tpmt_public_ecc_with_null_parameters() {
    let pub_area = ecc_pub_area(&null(), &null(), TPM_ECC_NIST_P256, &null());

    let (name_alg, key) = parse_tpmt_public(&pub_area).unwrap();

    assert_eq!(name_alg, TPM_ALG_SHA256);
    assert!(matches!(
        key,
        PublicKey::Ec { crv: 1, x, y } if x == [0x11; 32] && y == [0x22; 32]
    ));
}

#[test]
fn test_tpmt_public_ecc_with_ecdsa_scheme() {
    let scheme = alg(TPM_ALG_ECDSA, &[TPM_ALG_SHA256]);
    let pub_area = ecc_pub_area(&null(), &scheme, TPM_ECC_NIST_P256, &null());

    let (_, key) = parse_tpmt_public(&pub_area).unwrap();

    assert!(matches!(
        key,
        PublicKey::Ec { crv: 1, x, y } if x == [0x11; 32] && y == [0x22; 32]
    ));
}

#[test]
fn test_tpmt_public_ecc_with_ecdaa_scheme_symmetric_and_kdf() {
    let symmetric = alg(TPM_ALG_AES, &[128, TPM_ALG_CFB]);
    let scheme = alg(TPM_ALG_ECDAA, &[TPM_ALG_SHA256, 1]);
    let kdf = alg(TPM_ALG_KDF1_SP800_56A, &[TPM_ALG_SHA256]);
    let pub_area = ecc_pub_area(&symmetric, &scheme, TPM_ECC_NIST_P384, &kdf);

    let (_, key) = parse_tpmt_public(&pub_area).unwrap();

    assert!(matches!(
        key,
        PublicKey::Ec { crv: 2, x, y } if x == [0x11; 32] && y == [0x22; 32]
    ));
}

#[test]
fn test_tpmt_public_rsa_with_rsassa_scheme() {
    let scheme = alg(TPM_ALG_RSASSA, &[TPM_ALG_SHA256]);
    let pub_area = rsa_pub_area(&null(), &scheme);

    let (_, key) = parse_tpmt_public(&pub_area).unwrap();

    assert!(matches!(
        key,
        PublicKey::Rsa { n, e } if n == [0xC3; 256] && e == [0x01, 0x00, 0x01]
    ));
}

#[test]
fn test_tpmt_public_rejects_unknown_scheme() {
    let scheme = alg(0x7777, &[TPM_ALG_SHA256]);
    let pub_area = ecc_pub_area(&null(), &scheme, TPM_ECC_NIST_P256, &null());

    assert_invalid_attestation(parse_tpmt_public(&pub_area), "Unsupported TPM key scheme");
}

#[test]
fn test_tpmt_public_rejects_unknown_curve() {
    let pub_area = ecc_pub_area(&null(), &null(), 0x0010, &null());

    assert_invalid_attestation(parse_tpmt_public(&pub_area), "Unsupported TPM curve");
}

#[test]
fn test_tpmt_public_rejects_trailing_bytes() {
    let mut pub_area = ecc_pub_area(&null(), &null(), TPM_ECC_NIST_P256, &null());
    pub_area.push(0);

    assert_invalid_attestation(
        parse_tpmt_public(&pub_area),
        "Trailing bytes after TPM structure",
    );
}

#[test]
fn test_tpm_and_cose_keys_with_different_curves_do_not_match() {
    let tpm_key = PublicKey::Ec {
        crv: 1,
        x: vec![0x11; 32],
        y: vec![0x22; 32],
    };
    let same_curve = PublicKey::Ec {
        crv: 1,
        x: vec![0x11; 32],
        y: vec![0x22; 32],
    };
    let other_curve = PublicKey::Ec {
        crv: 2,
        x: vec![0x11; 32],
        y: vec![0x22; 32],
    };

    assert!(public_keys_match(&tpm_key, &same_curve));
    assert!(!public_keys_match(&tpm_key, &other_curve));
}

#[test]
fn test_tpms_attest_reads_certify_info() {
    let (magic, attest_type, extra_data, name) =
        parse_tpms_attest(&cert_info(&[0xDD; 34])).unwrap();

    assert_eq!(magic, 0xff54_4347);
    assert_eq!(attest_type, 0x8017);
    assert_eq!(extra_data, [0xBB; 32]);
    assert_eq!(name, [0xCC; 34]);
}

#[test]
fn test_tpms_attest_rejects_trailing_bytes() {
    let mut info = cert_info(&[0xDD; 34]);
    info.push(0);

    assert_invalid_attestation(
        parse_tpms_attest(&info),
        "Trailing bytes after TPM structure",
    );
}

#[test]
fn test_tpms_attest_rejects_missing_qualified_name() {
    let mut info = cert_info(&[]);
    info.truncate(info.len() - 2);

    assert_invalid_attestation(parse_tpms_attest(&info), "Truncated TPM structure");
}
