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
//! Passki implements the server half of the WebAuthn protocol: the browser holds a private
//! key and signs a challenge with it, this crate issues the challenge and verifies the response.
//!
//! Registration and authentication are both two-step ceremonies. The first step returns a challenge
//! to send to the browser plus a state value the second step needs; keep that state in a session
//! or cache in between.
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

/// Entry point of the crate: holds the relying party configuration and starts and finishes both
/// ceremonies.
///
/// The relying party is the site the passkeys belong to.
pub struct Passki {
    /// The relying party identifier (typically the domain).
    pub rp_id: String,

    /// The accepted relying party origins (e.g., `https://example.com`).
    pub rp_origins: Vec<String>,

    /// The human-readable relying party name.
    pub rp_name: String,

    /// Root certificates that attestation chains are validated against. Private so that later
    /// additions to the trust configuration do not break callers; install them with
    /// [`Passki::with_attestation_trust`].
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

    /// Installs the root certificates that attestation certificate chains are validated against,
    /// plus the policy for chains that do not reach one.
    ///
    /// By default no chain is validated, so the certificate an authenticator sends proves only that
    /// it signed its own statement. A client can mint one claiming to be any hardware model
    /// it likes. Anchors are what make [`StoredPasskey::aaguid`] - the authenticator model
    /// identifier - worth trusting, so ask for [`AttestationConveyancePreference::Direct`]
    /// at registration *and* install anchors here; either one alone buys nothing.
    ///
    /// The anchors are the vendor root CA certificates of the authenticators being accepted,
    /// in DER form. passki neither bundles them nor fetches the FIDO Metadata Service, which would
    /// mean a network round trip and JWT verification on a schedule the relying party should
    /// control.
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

    /// Whether an origin is already usable under `rp_id` alone, because its host is the `rp_id`
    /// or a subdomain of it. Such an origin needs no entry in the well-known file.
    fn covered_by_rp_id(&self, origin: &str) -> bool {
        let host = origin.split_once("://").map_or(origin, |(_, rest)| rest);
        let host = host.split(['/', ':']).next().unwrap_or(host);

        host == self.rp_id || host.ends_with(&format!(".{}", self.rp_id))
    }

    /// Builds the `/.well-known/webauthn` payload that authorizes this relying party's related
    /// origins, serialized as `{"origins": ["https://example.co.uk", ...]}`.
    ///
    /// Serve it with content type `application/json` from `https://<rp_id>/.well-known/webauthn`
    /// when passkeys for one `rp_id` are used from more than one domain, such as a brand with
    /// country-specific domains. Without the file a browser refuses a ceremony whose calling origin
    /// does not match the `rp_id`; with it, the origins listed here share one credential.
    ///
    /// Every origin passed to [`Passki::new`] is listed except those already reachable under
    /// the `rp_id` itself, which the specification says to leave out. That can leave the list
    /// empty, in which case there is nothing to serve.
    ///
    /// Browsers honour at most five distinct *labels* - the name before the effective top level
    /// domain - so `example.com`, `example.co.uk` and `example.de` together cost one of the five,
    /// while five unrelated brand names exhaust them. Build a [`RelatedOrigins`] directly
    /// to publish a list narrower than the origins this crate accepts.
    ///
    /// # Example
    ///
    /// ```
    /// # use passki::Passki;
    /// let passki = Passki::new(
    ///     "example.com",
    ///     &["https://example.com", "https://example.co.uk"],
    ///     "Example Corp",
    /// );
    ///
    /// // https://example.com is left out: the rp_id already covers it.
    /// let payload = passki.related_origins();
    /// assert_eq!(payload.origins, ["https://example.co.uk"]);
    /// ```
    pub fn related_origins(&self) -> RelatedOrigins {
        RelatedOrigins {
            origins: self
                .rp_origins
                .iter()
                .filter(|origin| !self.covered_by_rp_id(origin))
                .cloned()
                .collect(),
        }
    }

    /// Builds the payload saying this server does not hold that credential.
    ///
    /// The passkey is still on the user's device; your database is the side that lost it, so
    /// the browser keeps offering a credential that cannot work.
    ///
    /// Return it in the response to an authentication that failed on an unknown credential ID.
    /// The page passes it to `PublicKeyCredential.signalUnknownCredential()`, and the browser
    /// hides the passkey. It names no user, so it is safe to return to a caller who is not
    /// signed in.
    ///
    /// # Example
    ///
    /// ```
    /// # use passki::Passki;
    /// let passki = Passki::new("example.com", &["https://example.com"], "Example Corp");
    ///
    /// let signal = passki.signal_unknown_credential(&[1, 2, 3]);
    /// assert_eq!(signal.credential_id, "AQID");
    /// ```
    pub fn signal_unknown_credential(&self, credential_id: &[u8]) -> UnknownCredentialSignal {
        UnknownCredentialSignal {
            rp_id: self.rp_id.clone(),
            credential_id: Self::base64_encode(credential_id),
        }
    }

    /// Builds the payload listing every passkey this user still has.
    ///
    /// Return it after a successful sign-in, and whenever the user adds or removes a passkey.
    /// The page passes it to `PublicKeyCredential.signalAllAcceptedCredentials()`, and the browser
    /// hides every passkey missing from `passkeys` - an empty slice hides all of them. It reveals
    /// how many passkeys the account has, so return it only to that user, signed in.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user handle given to [`Passki::start_passkey_registration`]
    /// * `passkeys` - Every passkey still valid for that user
    pub fn signal_all_accepted_credentials(
        &self,
        user_id: &[u8],
        passkeys: &[StoredPasskey],
    ) -> AllAcceptedCredentialsSignal {
        AllAcceptedCredentialsSignal {
            rp_id: self.rp_id.clone(),
            user_id: Self::base64_encode(user_id),
            all_accepted_credential_ids: passkeys
                .iter()
                .map(|passkey| Self::base64_encode(&passkey.credential_id))
                .collect(),
        }
    }

    /// Builds the payload carrying the name to show for this account.
    ///
    /// Return it when the username or display name changes, and on every sign-in. The page passes
    /// it to `PublicKeyCredential.signalCurrentUserDetails()`, and the browser relabels the account
    /// in the passkey picker - though a password manager may keep a name the user edited
    /// themselves.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user handle given to [`Passki::start_passkey_registration`]
    /// * `username` - The current username or account identifier
    /// * `display_name` - The current human-readable display name
    pub fn signal_current_user_details(
        &self,
        user_id: &[u8],
        username: &str,
        display_name: &str,
    ) -> CurrentUserDetailsSignal {
        CurrentUserDetailsSignal {
            rp_id: self.rp_id.clone(),
            user_id: Self::base64_encode(user_id),
            name: username.to_string(),
            display_name: display_name.to_string(),
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

    /// Encodes binary data as base64url without padding, the encoding WebAuthn uses for every
    /// binary value on the wire.
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
