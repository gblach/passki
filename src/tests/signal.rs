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

const USER_ID: &[u8] = b"user123_16bytes_";

fn passki() -> Passki {
    Passki::new("example.com", &["https://example.com"], "Example Corp")
}

fn passkey(credential_id: Vec<u8>) -> StoredPasskey {
    StoredPasskey {
        credential_id,
        public_key: vec![2u8; 64],
        counter: 0,
        algorithm: -7,
        aaguid: [0u8; 16],
        attestation_type: AttestationType::None,
        transports: Vec::new(),
        rk: None,
        large_blob_supported: None,
        cred_protect: None,
        min_pin_length: None,
        be: false,
        bs: false,
    }
}

#[test]
fn test_unknown_credential_signal_shape() {
    let json = serde_json::to_string(&passki().signal_unknown_credential(&[1, 2, 3])).unwrap();

    assert_eq!(json, r#"{"rpId":"example.com","credentialId":"AQID"}"#);
}

#[test]
fn test_all_accepted_credentials_signal_shape() {
    let passkeys = [passkey(vec![1, 2, 3]), passkey(vec![4, 5, 6])];
    let signal = passki().signal_all_accepted_credentials(USER_ID, &passkeys);
    let json = serde_json::to_value(&signal).unwrap();

    assert_eq!(json["rpId"], "example.com");
    assert_eq!(json["userId"], Passki::base64_encode(USER_ID));
    assert_eq!(json["allAcceptedCredentialIds"][0], "AQID");
    assert_eq!(json["allAcceptedCredentialIds"][1], "BAUG");
}

#[test]
fn test_all_accepted_credentials_signal_with_no_passkeys_left() {
    let signal = passki().signal_all_accepted_credentials(USER_ID, &[]);

    // An empty list is what a user with no passkeys left signals; it hides every passkey
    // the client holds for them.
    assert!(signal.all_accepted_credential_ids.is_empty());
}

#[test]
fn test_current_user_details_signal_shape() {
    let signal = passki().signal_current_user_details(USER_ID, "alice@example.com", "Alice Smith");
    let json = serde_json::to_value(&signal).unwrap();

    assert_eq!(json["rpId"], "example.com");
    assert_eq!(json["userId"], Passki::base64_encode(USER_ID));
    assert_eq!(json["name"], "alice@example.com");
    assert_eq!(json["displayName"], "Alice Smith");
}

#[test]
fn test_signals_carry_the_configured_rp_id() {
    let passki = Passki::new("other.example", &["https://other.example"], "Other");

    assert_eq!(
        passki.signal_unknown_credential(&[1]).rp_id,
        "other.example"
    );
    assert_eq!(
        passki.signal_all_accepted_credentials(USER_ID, &[]).rp_id,
        "other.example"
    );
    assert_eq!(
        passki
            .signal_current_user_details(USER_ID, "alice", "Alice")
            .rp_id,
        "other.example"
    );
}

#[test]
fn test_signal_user_id_matches_the_registration_user_handle() {
    let passki = passki();
    let (challenge, _) = passki
        .start_passkey_registration(USER_ID, "alice", "Alice", RegistrationOptions::default())
        .unwrap();

    let signal = passki.signal_all_accepted_credentials(USER_ID, &[]);

    assert_eq!(signal.user_id, challenge.user.id);
}
