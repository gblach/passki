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

use crate::*;

fn passki() -> Passki {
    Passki::new("localhost", &["http://localhost:3000"], "Test App")
}

fn start_registration(hints: Vec<PublicKeyCredentialHint>) -> serde_json::Value {
    let (challenge, _) = passki()
        .start_passkey_registration(
            b"user123_16bytes_",
            "testuser",
            "Test User",
            RegistrationOptions {
                hints,
                ..Default::default()
            },
        )
        .unwrap();

    serde_json::to_value(&challenge).unwrap()
}

fn start_authentication(hints: Vec<PublicKeyCredentialHint>) -> serde_json::Value {
    let (challenge, _) = passki().start_passkey_authentication(
        &[],
        AuthenticationOptions {
            hints,
            ..Default::default()
        },
    );

    serde_json::to_value(&challenge).unwrap()
}

#[test]
fn test_registration_challenge_carries_hints() {
    let json = start_registration(vec![PublicKeyCredentialHint::SecurityKey]);

    assert_eq!(json["hints"], serde_json::json!(["security-key"]));
}

#[test]
fn test_authentication_challenge_carries_hints() {
    let json = start_authentication(vec![PublicKeyCredentialHint::SecurityKey]);

    assert_eq!(json["hints"], serde_json::json!(["security-key"]));
}

#[test]
fn test_hints_keep_the_requested_order() {
    let json = start_registration(vec![
        PublicKeyCredentialHint::Hybrid,
        PublicKeyCredentialHint::ClientDevice,
    ]);

    // The list is a preference order, so it must not be sorted or deduplicated on the way out.
    assert_eq!(
        json["hints"],
        serde_json::json!(["hybrid", "client-device"])
    );
}

#[test]
fn test_every_hint_uses_its_webauthn_spelling() {
    let json = start_registration(vec![
        PublicKeyCredentialHint::SecurityKey,
        PublicKeyCredentialHint::ClientDevice,
        PublicKeyCredentialHint::Hybrid,
    ]);

    assert_eq!(
        json["hints"],
        serde_json::json!(["security-key", "client-device", "hybrid"])
    );
}

#[test]
fn test_challenges_omit_hints_by_default() {
    // An absent member means "no preference"; an empty array would tell a client that every
    // modality was ruled out.
    assert!(start_registration(vec![]).get("hints").is_none());
    assert!(start_authentication(vec![]).get("hints").is_none());
}

#[test]
fn test_hints_do_not_touch_authenticator_selection() {
    let json = start_registration(vec![PublicKeyCredentialHint::SecurityKey]);

    // Hints are advisory; only authenticatorSelection filters, and passki leaves it alone.
    assert!(
        json["authenticatorSelection"]
            .get("authenticatorAttachment")
            .is_none()
    );
}
