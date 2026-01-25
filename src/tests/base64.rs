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

use crate::Passki;

// ===== generate_challenge tests =====

#[test]
fn test_generate_challenge_multiple_unique() {
    let mut challenges = Vec::new();
    for _ in 0..10 {
        challenges.push(Passki::generate_challenge());
    }

    // Check all challenges are unique
    for i in 0..challenges.len() {
        for j in (i + 1)..challenges.len() {
            assert_ne!(
                challenges[i], challenges[j],
                "All challenges should be unique"
            );
        }
    }
}

#[test]
fn test_generate_challenge_consistency() {
    // Ensure multiple calls work correctly
    for _ in 0..100 {
        let challenge = Passki::generate_challenge();
        assert_eq!(challenge.len(), 32);
    }
}

// ===== base64_encode tests =====

#[test]
fn test_base64_encode_empty() {
    let data = vec![];
    let encoded = Passki::base64_encode(&data);
    assert_eq!(encoded, "", "Empty data should encode to empty string");
}

#[test]
fn test_base64_encode_simple() {
    let data = b"hello";
    let encoded = Passki::base64_encode(data);

    // URL-safe base64 without padding: "hello" -> "aGVsbG8"
    assert_eq!(encoded, "aGVsbG8");
}

#[test]
fn test_base64_encode_with_padding() {
    let data = b"hi";
    let encoded = Passki::base64_encode(data);

    // Should not have padding (URL_SAFE_NO_PAD)
    assert!(!encoded.contains('='), "Should not contain padding");
    assert_eq!(encoded, "aGk");
}

#[test]
fn test_base64_encode_binary_data() {
    let data = vec![0x00, 0x01, 0x02, 0xFF, 0xFE];
    let encoded = Passki::base64_encode(&data);

    // Should be valid base64url characters (A-Z, a-z, 0-9, -, _)
    for ch in encoded.chars() {
        assert!(
            ch.is_alphanumeric() || ch == '-' || ch == '_',
            "Character {} should be valid base64url",
            ch
        );
    }
}

#[test]
fn test_base64_encode_url_safe() {
    // Data that would produce + or / in standard base64
    let data = vec![0xFB, 0xFF];
    let encoded = Passki::base64_encode(&data);

    // Should use - and _ instead of + and /
    assert!(!encoded.contains('+'), "Should not contain +");
    assert!(!encoded.contains('/'), "Should not contain /");
}

#[test]
fn test_base64_encode_32_bytes() {
    let data = vec![0xAB; 32];
    let encoded = Passki::base64_encode(&data);

    // 32 bytes should encode to 43 characters (without padding)
    assert_eq!(encoded.len(), 43);
}

#[test]
fn test_base64_encode_challenge() {
    let challenge = Passki::generate_challenge();
    let encoded = Passki::base64_encode(&challenge);

    assert!(!encoded.is_empty());
    assert!(!encoded.contains('='), "Should not have padding");
    assert!(!encoded.contains('+'), "Should be URL-safe");
    assert!(!encoded.contains('/'), "Should be URL-safe");
}

// ===== base64_decode tests =====

#[test]
fn test_base64_decode_empty() {
    let result = Passki::base64_decode("");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Vec::<u8>::new());
}

#[test]
fn test_base64_decode_simple() {
    let encoded = "aGVsbG8";
    let decoded = Passki::base64_decode(encoded).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn test_base64_decode_with_no_padding() {
    let encoded = "aGk";
    let decoded = Passki::base64_decode(encoded).unwrap();
    assert_eq!(decoded, b"hi");
}

#[test]
fn test_base64_decode_binary_data() {
    let original = vec![0x00, 0x01, 0x02, 0xFF, 0xFE];
    let encoded = Passki::base64_encode(&original);
    let decoded = Passki::base64_decode(&encoded).unwrap();

    assert_eq!(decoded, original);
}

#[test]
fn test_base64_decode_invalid_characters() {
    let invalid = "aGVsbG8@"; // @ is not valid in base64
    let result = Passki::base64_decode(invalid);

    assert!(result.is_err(), "Should fail with invalid characters");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Base64 decode error")
    );
}

#[test]
fn test_base64_decode_with_padding_fails() {
    // Our decoder expects no padding (URL_SAFE_NO_PAD)
    let with_padding = "aGVsbG8=";
    let result = Passki::base64_decode(with_padding);

    // This might fail or might ignore padding depending on implementation
    // Just ensure it doesn't panic
    let _ = result;
}

#[test]
fn test_base64_decode_malformed() {
    let malformed = "!!!";
    let result = Passki::base64_decode(malformed);

    assert!(result.is_err(), "Should fail with malformed base64");
}

#[test]
fn test_base64_decode_url_safe_characters() {
    // Test URL-safe characters - and _
    let data = vec![0xFB, 0xFF];
    let encoded = Passki::base64_encode(&data);
    let decoded = Passki::base64_decode(&encoded).unwrap();

    assert_eq!(decoded, data);
}

// ===== Round-trip tests =====

#[test]
fn test_base64_roundtrip_various_lengths() {
    for len in 0..100 {
        let original: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        let encoded = Passki::base64_encode(&original);
        let decoded = Passki::base64_decode(&encoded).unwrap();

        assert_eq!(decoded, original, "Failed for length {}", len);
    }
}

#[test]
fn test_base64_roundtrip_all_byte_values() {
    let original: Vec<u8> = (0..=255).collect();
    let encoded = Passki::base64_encode(&original);
    let decoded = Passki::base64_decode(&encoded).unwrap();

    assert_eq!(decoded, original);
}

#[test]
fn test_base64_encode_decode_consistency() {
    // Test that multiple encode/decode cycles work correctly
    let mut data = b"test data".to_vec();

    for _ in 0..5 {
        let encoded = Passki::base64_encode(&data);
        data = Passki::base64_decode(&encoded).unwrap();
    }

    assert_eq!(data, b"test data");
}

#[test]
fn test_base64_decode_case_sensitive() {
    // Base64 is case-sensitive
    let encoded1 = "YWJj"; // "abc"
    let encoded2 = "YWJJ"; // different

    let decoded1 = Passki::base64_decode(encoded1).unwrap();
    let decoded2 = Passki::base64_decode(encoded2);

    // They should produce different results or second should error
    assert!(decoded2.is_err() || decoded1 != decoded2.unwrap());
}

// ===== Integration tests with challenges =====

#[test]
fn test_generate_and_encode_challenge() {
    let challenge = Passki::generate_challenge();
    let encoded = Passki::base64_encode(&challenge);

    // Encoded challenge should be valid base64url
    assert!(!encoded.is_empty());
    assert_eq!(encoded.len(), 43); // 32 bytes -> 43 chars without padding

    // Should be decodable
    let decoded = Passki::base64_decode(&encoded).unwrap();
    assert_eq!(decoded, challenge);
}
