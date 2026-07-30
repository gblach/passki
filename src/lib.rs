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
//! - Replay attack protection via signature counters
//! - Flexible authenticator selection and user verification options
//! - Credential exclusion to prevent duplicate registrations
//! - Type-safe API with comprehensive error handling
//!
//! # Example
//!
//! ```rust
//! use passki::{AuthenticationOptions, Passki, RegistrationOptions, StoredPasskey};
//!
//! // Initialize Passki with your relying party information
//! let passki = Passki::new(
//!     "example.com",              // Relying Party ID (domain)
//!     &["https://example.com"],   // Accepted Relying Party Origins
//!     "Example Corp"              // Relying Party Name
//! );
//!
//! // Registration flow
//! // Step 1: Start registration and send challenge to client
//! # let user_existing_passkeys: Vec<StoredPasskey> = vec![];
//! let user_id = b"unique_user_identifier_12345"; // At least 16 bytes
//! let (registration_challenge, registration_state) = passki.start_passkey_registration(
//!     user_id,                        // User ID (bytes)
//!     "alice@example.com",            // Username
//!     "Alice Smith",                  // Display name
//!     RegistrationOptions::default(), // Timeout, attestation, resident key, UV, exclusions, extensions
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
//!     &user_passkeys,                   // User's stored passkeys
//!     AuthenticationOptions::default(), // Timeout, user verification, extensions
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

mod attestation;
mod authentication;
mod client_data;
mod registration;
mod trust;
mod types;

#[cfg(test)]
mod tests;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use x509_cert::Certificate;

pub use authentication::{
    AuthenticationChallenge, AuthenticationCredential, AuthenticationOptions, AuthenticationResult,
    AuthenticationState,
};
pub use client_data::{ClientData, ClientDataType};
pub use registration::{
    RegistrationChallenge, RegistrationCredential, RegistrationOptions, RegistrationState,
};
pub use types::*;

/// Main Passki struct for managing passkey registration and authentication.
///
/// This struct holds the relying party configuration and provides methods
/// to start and finish passkey operations.
pub struct Passki {
    /// The relying party identifier (typically the domain).
    pub rp_id: String,

    /// The accepted relying party origins (e.g., `https://example.com`).
    pub rp_origins: Vec<String>,

    /// The human-readable relying party name.
    pub rp_name: String,

    /// Root certificates that attestation chains are validated against. Kept
    /// private so that later additions to the trust configuration do not break
    /// callers; install them with [`Passki::with_attestation_trust`].
    pub(crate) attestation_anchors: Vec<Certificate>,

    /// What to do about the trust path of an attestation certificate chain.
    pub(crate) attestation_policy: AttestationTrustPolicy,
}

impl Passki {
    /// Creates a new Passki instance.
    ///
    /// # Arguments
    ///
    /// * `rp_id` - The relying party identifier (typically the domain, e.g., "example.com")
    /// * `rp_origins` - The accepted relying party origins (e.g., `https://example.com`)
    /// * `rp_name` - The human-readable relying party name (e.g., "Example Corp")
    ///
    /// # Example
    ///
    /// ```
    /// # use passki::Passki;
    /// let passki = Passki::new(
    ///     "example.com",
    ///     &["https://example.com", "https://www.example.com"],
    ///     "Example Corp",
    /// );
    /// ```
    pub fn new(rp_id: &str, rp_origins: &[impl AsRef<str>], rp_name: &str) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            rp_origins: rp_origins.iter().map(|o| o.as_ref().to_string()).collect(),
            rp_name: rp_name.to_string(),
            attestation_anchors: Vec::new(),
            attestation_policy: AttestationTrustPolicy::Ignore,
        }
    }

    /// Installs the trust anchors that attestation certificate chains are
    /// validated against, together with the policy that decides what happens
    /// when a chain does not reach one.
    ///
    /// Without this, and by default, attestation statements are only checked for
    /// internal consistency: the signature is verified against the certificate
    /// the statement itself supplies, which a malicious client can mint while
    /// claiming any AAGUID it likes. Trust anchors are what turn
    /// [`StoredPasskey::aaguid`] from a self-asserted value into an attested
    /// one, so a relying party that wants a usable AAGUID sets
    /// [`AttestationConveyancePreference::Direct`] on the registration *and*
    /// installs anchors here. One without the other buys nothing.
    ///
    /// The anchors are the vendor root CA certificates for the authenticators
    /// being accepted, in DER form. passki does not bundle them and does not
    /// fetch the FIDO Metadata Service: that means a network round trip and JWT
    /// verification on a schedule the relying party controls, not this crate.
    ///
    /// # Arguments
    ///
    /// * `roots` - DER-encoded root certificates
    /// * `policy` - How strictly the trust path is enforced
    ///
    /// # Errors
    ///
    /// Returns [`PasskiError::InvalidCertificate`] if a root cannot be parsed.
    ///
    /// # Example
    ///
    /// ```
    /// # use passki::{AttestationTrustPolicy, Passki, PasskiError};
    /// # fn build(yubico_root_der: &[u8]) -> Result<Passki, PasskiError> {
    /// let passki = Passki::new("example.com", &["https://example.com"], "Example Corp")
    ///     .with_attestation_trust(&[yubico_root_der], AttestationTrustPolicy::VerifyWhenPresent)?;
    /// # Ok(passki)
    /// # }
    /// ```
    pub fn with_attestation_trust(
        mut self,
        roots: &[impl AsRef<[u8]>],
        policy: AttestationTrustPolicy,
    ) -> types::Result<Self> {
        self.attestation_anchors = roots
            .iter()
            .map(|root| attestation::parse_cert(root.as_ref()))
            .collect::<types::Result<Vec<_>>>()?;
        self.attestation_policy = policy;
        Ok(self)
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
    #[inline]
    pub fn base64_encode(data: &[u8]) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        Base64UrlUnpadded::encode_string(data)
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
    #[inline]
    pub fn base64_decode(s: &str) -> types::Result<Vec<u8>> {
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        Ok(Base64UrlUnpadded::decode_vec(s)?)
    }
}
