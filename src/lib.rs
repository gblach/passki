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

//! Passki - A WebAuthn/Passkey implementation for Rust
//!
//! Passki provides a simple and secure way to implement passkey-based authentication
//! in your Rust applications. It handles the WebAuthn protocol for both registration
//! and authentication ceremonies.
//!
//! # Features
//!
//! - Support for multiple cryptographic algorithms (EdDSA/Ed25519, ES256/P-256, RS256/RSA)
//! - Full WebAuthn Level 2 compliance
//! - Replay attack protection via signature counters
//! - Flexible authenticator selection and user verification options
//! - Credential exclusion to prevent duplicate registrations
//! - Type-safe API with comprehensive error handling
//!
//! # Example
//!
//! ```rust
//! use passki::{
//!     Passki, AttestationConveyancePreference, ResidentKeyRequirement,
//!     UserVerificationRequirement, StoredPasskey,
//! };
//!
//! // Initialize Passki with your relying party information
//! let passki = Passki::new(
//!     "example.com",              // Relying Party ID (domain)
//!     "https://example.com",      // Relying Party Origin
//!     "Example Corp"              // Relying Party Name
//! );
//!
//! // Registration flow
//! // Step 1: Start registration and send challenge to client
//! # let user_existing_passkeys: Vec<StoredPasskey> = vec![];
//! let user_id = b"unique_user_identifier_12345"; // At least 16 bytes
//! let (registration_challenge, registration_state) = passki.start_passkey_registration(
//!     user_id,                                        // User ID (bytes)
//!     "alice@example.com",                            // Username
//!     "Alice Smith",                                  // Display name
//!     60000,                                          // Timeout (ms)
//!     AttestationConveyancePreference::None,          // Attestation
//!     ResidentKeyRequirement::Preferred,              // Resident key
//!     UserVerificationRequirement::Preferred,         // User verification
//!     None,                                           // Exclude existing credentials
//! ).expect("user_id must be at least 16 bytes");
//!
//! // Send registration_challenge to client (as JSON)
//! // Client uses WebAuthn API to create credential
//!
//! // Step 2: Receive credential from client and complete registration
//! # /*
//! let stored_passkey = passki.finish_passkey_registration(
//!     &registration_credential,  // Credential from client
//!     &registration_state,       // State from step 1
//! )?;
//! # */
//!
//! // Save stored_passkey to your database associated with the user
//!
//! // Authentication flow
//! // Step 1: Start authentication and send challenge to client
//! # let user_passkeys: Vec<StoredPasskey> = vec![];
//! let (authentication_challenge, authentication_state) = passki.start_passkey_authentication(
//!     &user_passkeys,                            // User's stored passkeys
//!     60000,                                     // Timeout (ms)
//!     UserVerificationRequirement::Preferred,    // User verification
//! );
//!
//! // Send authentication_challenge to client (as JSON)
//! // Client uses WebAuthn API to sign the challenge
//!
//! // Step 2: Receive credential from client and verify authentication
//! # /*
//! let result = passki.finish_passkey_authentication(
//!     &authentication_credential,  // Credential from client
//!     &authentication_state,       // State from step 1
//!     &stored_passkey,             // User's passkey from database
//! )?;
//!
//! // Update the counter in your database to prevent replay attacks
//! stored_passkey.counter = result.counter;
//! # */
//! ```
//!
//! # Security Considerations
//!
//! - Always verify that the origin matches your expected domain
//! - Store and check signature counters to detect cloned authenticators
//! - Use HTTPS in production to prevent man-in-the-middle attacks
//! - Store passkeys securely in your database (the public keys are not secret,
//!   but credential IDs should be treated as sensitive)
//! - Use credential exclusion during registration to prevent duplicate credentials
//! - User IDs must be at least 16 bytes for security (recommended: use UUIDs or random bytes)

mod authentication;
mod client_data;
mod registration;
mod types;

#[cfg(test)]
mod tests;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use std::error::Error as StdError;

// Re-export public types
pub use authentication::{
    AuthenticationChallenge, AuthenticationCredential, AuthenticationResult, AuthenticationState,
};
pub use client_data::{ClientData, ClientDataType};
pub use registration::{RegistrationChallenge, RegistrationCredential, RegistrationState};
pub use types::*;

/// Main Passki struct for managing passkey registration and authentication.
///
/// This struct holds the relying party configuration and provides methods
/// to start and finish passkey operations.
pub struct Passki {
    /// The relying party identifier (typically the domain).
    pub rp_id: String,

    /// The relying party origin (e.g., `https://example.com`).
    pub rp_origin: String,

    /// The human-readable relying party name.
    pub rp_name: String,
}

impl Passki {
    /// Creates a new Passki instance.
    ///
    /// # Arguments
    ///
    /// * `rp_id` - The relying party identifier (typically the domain, e.g., "example.com")
    /// * `rp_origin` - The relying party origin (e.g., `https://example.com`)
    /// * `rp_name` - The human-readable relying party name (e.g., "Example Corp")
    ///
    /// # Example
    ///
    /// ```
    /// # use passki::Passki;
    /// let passki = Passki::new("example.com", "https://example.com", "Example Corp");
    /// ```
    pub fn new(rp_id: &str, rp_origin: &str, rp_name: &str) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            rp_origin: rp_origin.to_string(),
            rp_name: rp_name.to_string(),
        }
    }

    /// Generates a cryptographically secure random challenge.
    pub(crate) fn generate_challenge() -> Vec<u8> {
        let rng = SystemRandom::new();
        let mut challenge = vec![0u8; 32];
        rng.fill(&mut challenge)
            .expect("Failed to generate random challenge");
        challenge
    }

    /// Encodes binary data as base64url (without padding).
    ///
    /// # Arguments
    ///
    /// * `data` - The binary data to encode
    ///
    /// # Returns
    ///
    /// A base64url-encoded string without padding.
    #[inline] pub fn base64_encode(data: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.encode(data)
    }

    /// Decodes a base64url-encoded string (without padding).
    ///
    /// # Arguments
    ///
    /// * `s` - The base64url-encoded string
    ///
    /// # Returns
    ///
    /// The decoded binary data.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not valid base64url.
    #[inline] pub fn base64_decode(s: &str) -> types::Result<Vec<u8>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.decode(s).map_err(|e| {
            Box::new(types::PasskiError::new(format!("Base64 decode error: {}", e)))
                as Box<dyn StdError>
        })
    }
}
