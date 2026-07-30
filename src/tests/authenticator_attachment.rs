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

fn start(attachment: Option<AuthenticatorAttachment>) -> serde_json::Value {
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Test App");
    let (challenge, _) = passki
        .start_passkey_registration(
            b"user123_16bytes_",
            "testuser",
            "Test User",
            RegistrationOptions {
                authenticator_attachment: attachment,
                ..Default::default()
            },
        )
        .unwrap();

    serde_json::to_value(&challenge).unwrap()
}

#[test]
fn test_challenge_carries_platform_attachment() {
    let json = start(Some(AuthenticatorAttachment::Platform));

    assert_eq!(
        json["authenticatorSelection"]["authenticatorAttachment"],
        "platform"
    );
}

#[test]
fn test_challenge_carries_cross_platform_attachment() {
    let json = start(Some(AuthenticatorAttachment::CrossPlatform));

    // The WebAuthn value is hyphenated, not camelCase.
    assert_eq!(
        json["authenticatorSelection"]["authenticatorAttachment"],
        "cross-platform"
    );
}

#[test]
fn test_challenge_omits_attachment_by_default() {
    let json = start(None);

    // An absent member lets the client offer both modalities; an explicit null
    // would be a validation error in the browser.
    assert!(
        json["authenticatorSelection"]
            .get("authenticatorAttachment")
            .is_none()
    );
    assert!(json["authenticatorSelection"]["residentKey"].is_string());
}

#[test]
fn test_registration_credential_captures_reported_attachment() {
    let json = serde_json::json!({
        "credential_id": "AAAA",
        "public_key": "AAAA",
        "client_data_json": "AAAA",
        "authenticator_attachment": "cross-platform"
    });

    let credential: RegistrationCredential = serde_json::from_value(json).unwrap();
    assert_eq!(
        credential.authenticator_attachment,
        Some(AuthenticatorAttachment::CrossPlatform)
    );
}

#[test]
fn test_registration_credential_without_reported_attachment() {
    let json = serde_json::json!({
        "credential_id": "AAAA",
        "public_key": "AAAA",
        "client_data_json": "AAAA"
    });

    let credential: RegistrationCredential = serde_json::from_value(json).unwrap();
    assert_eq!(credential.authenticator_attachment, None);
}

#[test]
fn test_authentication_credential_captures_reported_attachment() {
    let json = serde_json::json!({
        "credential_id": "AAAA",
        "authenticator_data": "AAAA",
        "client_data_json": "AAAA",
        "signature": "AAAA",
        "authenticator_attachment": "platform"
    });

    let credential: AuthenticationCredential = serde_json::from_value(json).unwrap();
    assert_eq!(
        credential.authenticator_attachment,
        Some(AuthenticatorAttachment::Platform)
    );
}

#[test]
fn test_authentication_credential_without_reported_attachment() {
    let json = serde_json::json!({
        "credential_id": "AAAA",
        "authenticator_data": "AAAA",
        "client_data_json": "AAAA",
        "signature": "AAAA"
    });

    let credential: AuthenticationCredential = serde_json::from_value(json).unwrap();
    assert_eq!(credential.authenticator_attachment, None);
}
