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
//! Passki implements the server half of the WebAuthn protocol: the browser holds
//! a private key and signs a challenge with it, this crate issues the challenge
//! and verifies the response.
//!
//! Registration and authentication are both two-step ceremonies. The first step
//! returns a challenge to send to the browser plus a state value the second step
//! needs; keep that state in a session or cache in between.
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
//! let passki = Passki::new(
//!     "example.com",              // relying party ID (the domain)
//!     &["https://example.com"],   // accepted origins
//!     "Example Corp"              // name shown in the browser prompt
//! );
//!
//! // Registration step 1: issue a challenge
//! # let user_existing_passkeys: Vec<StoredPasskey> = vec![];
//! let user_id = b"unique_user_identifier_12345"; // at least 16 bytes
//! let (registration_challenge, registration_state) = passki.start_passkey_registration(
//!     user_id,
//!     "alice@example.com",            // username
//!     "Alice Smith",                  // display name
//!     RegistrationOptions::default(),
//! ).expect("user_id must be at least 16 bytes");
//!
//! // Send registration_challenge to the client as JSON, keep registration_state.
//!
//! // Registration step 2: verify the credential the client created
//! # /*
//! let stored_passkey = passki.finish_passkey_registration(
//!     &registration_credential,
//!     &registration_state,
//! )?;
//! # */
//!
//! // Save stored_passkey in your database, associated with the user.
//!
//! // Authentication step 1: issue a challenge
//! # let user_passkeys: Vec<StoredPasskey> = vec![];
//! let (authentication_challenge, authentication_state) = passki.start_passkey_authentication(
//!     &user_passkeys,
//!     AuthenticationOptions::default(),
//! );
//!
//! // Authentication step 2: verify the signature
//! # /*
//! let result = passki.finish_passkey_authentication(
//!     &authentication_credential,
//!     &authentication_state,
//!     &stored_passkey,
//! )?;
//!
//! // Persist the new counter, or replay detection has nothing to compare against.
//! stored_passkey.counter = result.counter;
//! # */
//! ```
//!
//! # Security Considerations
//!
//! - Serve over HTTPS; browsers refuse WebAuthn on insecure origins
//! - Store the counter returned by each authentication to detect cloned authenticators
//! - Public keys are not secret, but treat credential IDs as sensitive
//! - Pass existing passkeys as exclusions so a user cannot register the same one twice
//! - User IDs must be at least 16 bytes (a UUID or random bytes)

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

/// Entry point of the crate: holds the relying party configuration and starts
/// and finishes both ceremonies.
///
/// The relying party is the site the passkeys belong to.
pub struct Passki {
    /// The relying party identifier (typically the domain).
    pub rp_id: String,

    /// The accepted relying party origins (e.g., `https://example.com`).
    pub rp_origins: Vec<String>,

    /// The human-readable relying party name.
    pub rp_name: String,

    /// Root certificates that attestation chains are validated against. Private
    /// so that later additions to the trust configuration do not break callers;
    /// install them with [`Passki::with_attestation_trust`].
    pub(crate) attestation_anchors: Vec<Certificate>,

    /// How strictly attestation certificate chains are checked.
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

    /// Installs the root certificates that attestation certificate chains are
    /// validated against, plus the policy for chains that do not reach one.
    ///
    /// By default no chain is validated, so the certificate an authenticator
    /// sends proves only that it signed its own statement. A client can mint one
    /// claiming to be any hardware model it likes. Anchors are what make
    /// [`StoredPasskey::aaguid`] - the authenticator model identifier - worth
    /// trusting, so ask for [`AttestationConveyancePreference::Direct`] at
    /// registration *and* install anchors here; either one alone buys nothing.
    ///
    /// The anchors are the vendor root CA certificates of the authenticators
    /// being accepted, in DER form. passki neither bundles them nor fetches the
    /// FIDO Metadata Service, which would mean a network round trip and JWT
    /// verification on a schedule the relying party should control.
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

    /// Encodes binary data as base64url without padding, the encoding WebAuthn
    /// uses for every binary value on the wire.
    #[inline]
    pub fn base64_encode(data: &[u8]) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        Base64UrlUnpadded::encode_string(data)
    }

    /// Decodes a base64url string without padding.
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
