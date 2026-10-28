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

//! Benchmarks the authentication ceremony on whichever crypto backend the features select.
//!
//! Only one backend is compiled in per build, so compare them through Criterion baselines:
//!
//! ```sh
//! cargo bench --bench backends -- --save-baseline rust-crypto
//! cargo bench --bench backends --no-default-features --features aws-lc-rs -- \
//!     --baseline rust-crypto
//! cargo bench --bench backends --no-default-features --features graviola -- \
//!     --baseline rust-crypto
//! ```
//!
//! The later runs report each benchmark's change against the first.

use ciborium::Value;
use criterion::{Criterion, criterion_group, criterion_main};
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use p256::ecdsa::signature::{SignatureEncoding, Signer};
use p256::elliptic_curve::Generate;
use passki::{
    AuthenticationCredential, AuthenticationOptions, AuthenticationState, Passki, StoredPasskey,
};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256, Sha384};
use std::hint::black_box;

const ORIGIN: &str = "http://localhost:3000";
const CREDENTIAL_ID: [u8; 16] = [1u8; 16];

type SignFn = Box<dyn Fn(&[u8]) -> Vec<u8>>;

fn cose_key(entries: Vec<(i64, Value)>) -> Vec<u8> {
    let map = entries
        .into_iter()
        .map(|(label, value)| (Value::Integer(label.into()), value))
        .collect();
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

/// A fresh key for `alg`, as a COSE public key and a function signing with the private half.
/// Signing uses RustCrypto whatever the backend, since only verification is measured.
fn generate_key(alg: i32) -> (Vec<u8>, SignFn) {
    match alg {
        -8 => {
            let key = ed25519_dalek::SigningKey::generate(&mut UnwrapErr(SysRng));
            let x = key.verifying_key().to_bytes().to_vec();
            let cose = cose_key(vec![
                (1, int(1)),
                (3, int(-8)),
                (-1, int(6)),
                (-2, Value::Bytes(x)),
            ]);
            (cose, Box::new(move |m| key.sign(m).to_bytes().to_vec()))
        }
        -7 => {
            let key = p256::ecdsa::SigningKey::generate();
            let point = key.verifying_key().to_sec1_point(false);
            let point = point.as_bytes();
            let cose = cose_key(vec![
                (1, int(2)),
                (3, int(-7)),
                (-1, int(1)),
                (-2, Value::Bytes(point[1..33].to_vec())),
                (-3, Value::Bytes(point[33..65].to_vec())),
            ]);
            let sign = move |m: &[u8]| {
                let signature: p256::ecdsa::DerSignature = key.sign(m);
                signature.as_bytes().to_vec()
            };
            (cose, Box::new(sign))
        }
        -35 => {
            let key = p384::ecdsa::SigningKey::generate();
            let point = key.verifying_key().to_sec1_point(false);
            let point = point.as_bytes();
            let cose = cose_key(vec![
                (1, int(2)),
                (3, int(-35)),
                (-1, int(2)),
                (-2, Value::Bytes(point[1..49].to_vec())),
                (-3, Value::Bytes(point[49..97].to_vec())),
            ]);
            let sign = move |m: &[u8]| {
                let signature: p384::ecdsa::DerSignature = key.sign(m);
                signature.as_bytes().to_vec()
            };
            (cose, Box::new(sign))
        }
        -257 | -258 => {
            let key = rsa::RsaPrivateKey::new(&mut UnwrapErr(SysRng), 2048).unwrap();
            let n = strip_leading_zeros(&key.n().to_be_bytes());
            let e = strip_leading_zeros(&key.e().to_be_bytes());
            let cose = cose_key(vec![
                (1, int(3)),
                (3, int(alg.into())),
                (-1, Value::Bytes(n)),
                (-2, Value::Bytes(e)),
            ]);
            let sign: SignFn = if alg == -257 {
                let key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
                Box::new(move |m| key.sign(m).to_vec())
            } else {
                let key = rsa::pkcs1v15::SigningKey::<Sha384>::new(key);
                Box::new(move |m| key.sign(m).to_vec())
            };
            (cose, sign)
        }
        _ => unreachable!("no benchmark for algorithm {alg}"),
    }
}

/// A signed assertion for a fresh `alg` key, ready to be verified over and over.
fn create_assertion(
    passki: &Passki,
    alg: i32,
) -> (AuthenticationCredential, AuthenticationState, StoredPasskey) {
    let (public_key, sign) = generate_key(alg);

    let mut passkey = StoredPasskey::default();
    passkey.credential_id = CREDENTIAL_ID.to_vec();
    passkey.public_key = public_key;
    passkey.algorithm = alg;

    let (challenge, state) = passki
        .start_passkey_authentication(
            std::slice::from_ref(&passkey),
            AuthenticationOptions::default(),
        )
        .unwrap();

    let client_data_json = serde_json::to_vec(&serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge.challenge,
        "origin": ORIGIN,
        "crossOrigin": false,
    }))
    .unwrap();

    // A zero counter is never checked for growth, so the same assertion verifies every iteration.
    let mut auth_data = Sha256::digest(b"localhost").to_vec();
    auth_data.push(0x05); // UP + UV
    auth_data.extend_from_slice(&0u32.to_be_bytes());

    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature = sign(&signed_data);

    let credential: AuthenticationCredential = serde_json::from_value(serde_json::json!({
        "id": Passki::base64_encode(&CREDENTIAL_ID),
        "rawId": Passki::base64_encode(&CREDENTIAL_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": Passki::base64_encode(&client_data_json),
            "authenticatorData": Passki::base64_encode(&auth_data),
            "signature": Passki::base64_encode(&signature),
        },
    }))
    .unwrap();

    (credential, state, passkey)
}

fn bench_authentication(c: &mut Criterion) {
    let passki = Passki::new("localhost", &[ORIGIN], "Bench");

    let passkeys = [StoredPasskey::default()];
    c.bench_function("start_authentication", |b| {
        b.iter(|| {
            passki
                .start_passkey_authentication(
                    black_box(&passkeys),
                    AuthenticationOptions::default(),
                )
                .unwrap()
        })
    });

    let algorithms = [
        ("EdDSA", -8),
        ("ES256", -7),
        ("ES384", -35),
        ("RS256", -257),
        ("RS384", -258),
    ];
    for (name, alg) in algorithms {
        let (credential, state, passkey) = create_assertion(&passki, alg);
        c.bench_function(&format!("finish_authentication/{name}"), |b| {
            b.iter(|| {
                passki
                    .finish_passkey_authentication(
                        black_box(&credential),
                        black_box(&state),
                        black_box(&passkey),
                    )
                    .unwrap()
            })
        });
    }
}

criterion_group!(benches, bench_authentication);
criterion_main!(benches);
