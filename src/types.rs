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

//! Data structures and error types for WebAuthn/Passkey operations.

use serde::{Deserialize, Serialize};
use std::error::Error as StdError;
use std::fmt;

// Error handling

/// Error type for Passki operations.
///
/// This error type wraps a string message describing what went wrong during
/// passkey registration or authentication operations.
#[derive(Debug)]
pub struct PasskiError(pub String);

impl PasskiError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for PasskiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StdError for PasskiError {}

/// Convenience type alias for Results that may return any error.
pub type Result<T> = std::result::Result<T, Box<dyn StdError>>;

/// Attestation conveyance preference for passkey registration.
///
/// Specifies whether and how the relying party wants to receive attestation
/// information about the authenticator.
#[derive(Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    /// No attestation information is requested.
    None,
    /// Attestation information may be provided if available.
    Indirect,
    /// Direct attestation from the authenticator is requested.
    Direct,
    /// Enterprise attestation is requested (for managed devices).
    Enterprise,
}

/// Resident key requirement for passkey registration.
///
/// Specifies whether the authenticator should store the credential locally
/// (resident/discoverable credential) or rely on the server to provide it.
#[derive(Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    /// The authenticator should not create a resident credential.
    Discouraged,
    /// A resident credential is preferred but not required.
    Preferred,
    /// A resident credential must be created.
    Required,
}

/// User verification requirement for passkey operations.
///
/// Specifies whether user verification (e.g., PIN, biometric) is required
/// during the authentication ceremony.
#[derive(Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    /// User verification is required.
    Required,
    /// User verification is preferred but not required.
    Preferred,
    /// User verification should not be performed.
    Discouraged,
}

/// A stored passkey credential.
///
/// This structure contains all the information needed to verify future
/// authentication attempts using this passkey.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct StoredPasskey {
    /// The unique identifier for this credential.
    pub credential_id: Vec<u8>,

    /// The public key in COSE format.
    pub public_key: Vec<u8>,

    /// The signature counter used to detect cloned authenticators.
    pub counter: u32,

    /// The COSE algorithm identifier (e.g., -7 for ES256, -8 for EdDSA, -257 for RS256).
    pub algorithm: i32,
}

/// Information about the relying party (RP).
///
/// The relying party is the web application that is requesting authentication.
#[derive(Serialize, Debug)]
pub struct RelyingParty {
    /// Human-readable name of the relying party.
    pub name: String,

    /// Unique identifier for the relying party (typically the domain).
    pub id: String,
}

/// Information about the user account.
#[derive(Clone, Serialize, Debug)]
pub struct UserInfo {
    /// Unique identifier for the user account (base64url-encoded).
    pub id: String,

    /// Username or account identifier.
    pub name: String,

    /// Human-readable display name for the user.
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// A public key credential parameter specifying an acceptable algorithm.
#[derive(Serialize, Debug)]
pub struct PubKeyCredParam {
    /// COSE algorithm identifier (e.g., -7 for ES256).
    pub alg: i32,

    /// Credential type (always "public-key" for passkeys).
    #[serde(rename = "type")]
    pub type_: String,
}

/// Authenticator selection criteria for passkey registration.
#[derive(Serialize, Debug)]
pub struct AuthenticatorSelection {
    /// Resident key requirement.
    #[serde(rename = "residentKey")]
    pub resident_key: ResidentKeyRequirement,

    /// User verification requirement.
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationRequirement,
}

/// A credential descriptor for exclusion during registration.
///
/// Used to prevent re-registration of existing credentials.
#[derive(Serialize, Debug)]
pub struct ExcludeCredential {
    /// The credential ID (base64url-encoded).
    pub id: String,

    /// Credential type (always "public-key" for passkeys).
    #[serde(rename = "type")]
    pub type_: String,
}

/// A credential that is allowed for authentication.
#[derive(Serialize)]
pub struct AllowCredential {
    /// The credential ID (base64url-encoded).
    pub id: String,

    /// Credential type (always "public-key" for passkeys).
    #[serde(rename = "type")]
    pub type_: String,
}
