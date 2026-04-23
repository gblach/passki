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

#[test]
fn test_registration_state_roundtrip() {
    let state = RegistrationState {
        challenge: vec![1, 2, 3, 4, 5, 6, 7, 8],
        user: UserInfo {
            id: "dXNlcl9pZA".to_string(),
            name: "alice@example.com".to_string(),
            display_name: "Alice Smith".to_string(),
        },
    };

    let json = serde_json::to_string(&state).unwrap();
    let restored: RegistrationState = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.challenge, state.challenge);
    assert_eq!(restored.user.id, state.user.id);
    assert_eq!(restored.user.name, state.user.name);
    assert_eq!(restored.user.display_name, state.user.display_name);
}

#[test]
fn test_registration_state_json_shape() {
    let state = RegistrationState {
        challenge: vec![0xde, 0xad, 0xbe, 0xef],
        user: UserInfo {
            id: "abc123".to_string(),
            name: "bob".to_string(),
            display_name: "Bob".to_string(),
        },
    };

    let value: serde_json::Value = serde_json::to_value(&state).unwrap();

    assert!(value["challenge"].is_array());
    assert_eq!(value["challenge"][0], 0xde);
    assert_eq!(value["user"]["name"], "bob");
    assert_eq!(value["user"]["displayName"], "Bob");
}

#[test]
fn test_authentication_state_roundtrip() {
    let state = AuthenticationState {
        challenge: vec![9, 10, 11, 12, 13, 14, 15, 16],
        allowed_credentials: vec![
            vec![1u8; 16],
            vec![2u8; 16],
        ],
    };

    let json = serde_json::to_string(&state).unwrap();
    let restored: AuthenticationState = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.challenge, state.challenge);
    assert_eq!(restored.allowed_credentials, state.allowed_credentials);
}

#[test]
fn test_authentication_state_empty_credentials_roundtrip() {
    let state = AuthenticationState {
        challenge: vec![0u8; 32],
        allowed_credentials: vec![],
    };

    let json = serde_json::to_string(&state).unwrap();
    let restored: AuthenticationState = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.challenge, state.challenge);
    assert!(restored.allowed_credentials.is_empty());
}

#[test]
fn test_authentication_state_json_shape() {
    let state = AuthenticationState {
        challenge: vec![0xff, 0x00],
        allowed_credentials: vec![vec![0xaa, 0xbb]],
    };

    let value: serde_json::Value = serde_json::to_value(&state).unwrap();

    assert!(value["challenge"].is_array());
    assert_eq!(value["challenge"][0], 0xff);
    assert!(value["allowed_credentials"].is_array());
    assert_eq!(value["allowed_credentials"][0][0], 0xaa);
}
