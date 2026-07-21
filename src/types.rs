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
use thiserror::Error;

use crate::client_data::ClientDataType;

// Error handling

/// Error type for Passki operations.
///
/// Distinguishes the different ways a passkey registration or authentication
/// ceremony can fail, so callers can react to specific failures (e.g. a
/// [`PasskiError::CounterRegression`] indicating a possibly cloned
/// authenticator) instead of matching on error message strings.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PasskiError {
    /// `user_id` passed to [`crate::Passki::start_passkey_registration`] was too short.
    #[error("user_id must be at least 16 bytes")]
    UserIdTooShort,

    /// Base64url decoding failed.
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64ct::Error),

    /// Client data JSON could not be parsed.
    #[error("Invalid client data JSON: {0}")]
    InvalidClientDataJson(#[from] serde_json::Error),

    /// CBOR decoding failed.
    #[error("Failed to parse CBOR: {0}")]
    CborDecode(#[from] ciborium::de::Error<std::io::Error>),

    /// CBOR encoding failed.
    #[error("Failed to serialize CBOR: {0}")]
    CborEncode(#[from] ciborium::ser::Error<std::io::Error>),

    /// A required field was missing from the client data JSON.
    #[error("Missing {0} in client data")]
    MissingClientDataField(String),

    /// The client data `type` field was not a recognized WebAuthn operation.
    #[error("Invalid type in client data: {0}")]
    InvalidClientDataType(String),

    /// The client data `type` did not match the expected operation.
    #[error("Invalid type: expected {expected}, got {got}")]
    ClientDataTypeMismatch {
        expected: ClientDataType,
        got: ClientDataType,
    },

    /// The client data challenge did not match the one that was issued.
    #[error("Challenge mismatch")]
    ChallengeMismatch,

    /// The client data origin did not match the relying party's origin.
    #[error("Invalid origin: expected {expected}, got {got}")]
    OriginMismatch { expected: String, got: String },

    /// The client data indicated a cross-origin iframe request.
    #[error("Cross-origin requests are not allowed")]
    CrossOriginNotAllowed,

    /// The authenticator data was truncated or otherwise malformed.
    #[error("Invalid authenticator data")]
    InvalidAuthenticatorData,

    /// The `rpIdHash` in the authenticator data did not match the relying party.
    #[error("rpId hash mismatch")]
    RpIdHashMismatch,

    /// The UP (user present) flag was not set.
    #[error("User not present (UP flag not set)")]
    UserNotPresent,

    /// User verification was required but the UV flag was not set.
    #[error("User verification required but UV flag not set")]
    UserVerificationRequired,

    /// The signature counter did not increase, indicating a possible replay
    /// attack or a cloned authenticator.
    #[error("Invalid counter (possible replay attack)")]
    CounterRegression,

    /// The authenticator data did not contain attested credential data.
    #[error("No attested credential data present")]
    NoAttestedCredentialData,

    /// The credential used for authentication was not in the allowed list.
    #[error("Credential not allowed")]
    CredentialNotAllowed,

    /// The credential ID reported by the client did not match the one in the
    /// attested credential data.
    #[error("Credential ID mismatch between client and attested credential data")]
    CredentialIdMismatch,

    /// The COSE algorithm identifier is not supported.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(i32),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// A COSE key was malformed or missing a required field.
    #[error("Invalid COSE key: {0}")]
    InvalidCoseKey(String),

    /// The attestation object did not have the expected structure.
    #[error("Invalid attestation object: {0}")]
    InvalidAttestationObject(String),

    /// The attestation format (`fmt`) is not supported.
    #[error("Unsupported attestation format: {0}")]
    UnsupportedAttestationFormat(String),

    /// A required field was missing from the attestation statement.
    #[error("Missing {0} in attStmt")]
    MissingAttStmtField(String),

    /// The attestation statement failed a format-specific structural or
    /// signature check.
    #[error("Invalid attestation: {0}")]
    InvalidAttestation(String),

    /// The attestation certificate was malformed or did not satisfy the
    /// WebAuthn attestation certificate requirements.
    #[error("Invalid attestation certificate: {0}")]
    InvalidCertificate(String),
}

/// Convenience type alias for Results returned by Passki operations.
pub type Result<T> = std::result::Result<T, PasskiError>;

// Authenticator data flag bits

/// UP (user present) flag bit in authenticator data.
pub(crate) const FLAG_UP: u8 = 0x01;
/// UV (user verified) flag bit in authenticator data.
pub(crate) const FLAG_UV: u8 = 0x04;
/// AT (attested credential data) flag bit in authenticator data.
pub(crate) const FLAG_AT: u8 = 0x40;

// COSE algorithm identifiers

/// EdDSA (Ed25519).
pub(crate) const ALG_EDDSA: i32 = -8;
/// ES256 (ECDSA with P-256 and SHA-256).
pub(crate) const ALG_ES256: i32 = -7;
/// ES384 (ECDSA with P-384 and SHA-384).
pub(crate) const ALG_ES384: i32 = -35;
/// RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
pub(crate) const ALG_RS256: i32 = -257;
/// RS384 (RSASSA-PKCS1-v1_5 with SHA-384).
pub(crate) const ALG_RS384: i32 = -258;

// COSE key types

/// OKP (Octet Key Pair, used by Ed25519).
pub(crate) const KTY_OKP: i64 = 1;
/// EC2 (elliptic curve with x/y coordinates).
pub(crate) const KTY_EC2: i64 = 2;
/// RSA.
pub(crate) const KTY_RSA: i64 = 3;

// COSE elliptic curves

/// P-256 curve.
pub(crate) const CRV_P256: i64 = 1;
/// P-384 curve.
pub(crate) const CRV_P384: i64 = 2;
/// Ed25519 curve.
pub(crate) const CRV_ED25519: i64 = 6;

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
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
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

    /// Whether this is a discoverable (resident) credential, as reported by the `credProps`
    /// extension during registration. `None` if `credProps` was not requested or not reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,
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
#[derive(Clone, Serialize, Deserialize, Debug)]
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
#[derive(Serialize, Debug)]
pub struct AllowCredential {
    /// The credential ID (base64url-encoded).
    pub id: String,

    /// Credential type (always "public-key" for passkeys).
    #[serde(rename = "type")]
    pub type_: String,
}

/// Extensions included in a registration challenge.
#[derive(Serialize, Debug, Default)]
pub struct RegistrationExtensions {
    #[serde(rename = "credProps", skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfInput>,
}

/// Extensions included in an authentication challenge.
#[derive(Serialize, Debug)]
pub struct AuthenticationExtensions {
    pub prf: PrfInput,
}

/// PRF extension input included in challenges.
#[derive(Serialize, Debug, Default)]
pub struct PrfInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval: Option<PrfEval>,
}

/// PRF evaluation inputs sent to the authenticator.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrfEval {
    /// Base64url-encoded first PRF input.
    pub first: String,
    /// Optional base64url-encoded second PRF input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}

/// The full `clientExtensionResults` object returned by the browser.
///
/// Each field corresponds to one WebAuthn extension. This struct is used in
/// both [`RegistrationCredential`] and [`AuthenticationCredential`] and maps
/// directly to what `credential.getClientExtensionResults()` returns in JS.
/// Adding support for a new extension means adding a field here.
#[derive(Deserialize, Debug, Default)]
pub struct ClientExtensionResults {
    /// Results for the credProps extension.
    #[serde(default, rename = "credProps")]
    pub cred_props: Option<CredPropsResult>,
    /// Results for the PRF extension.
    #[serde(default)]
    pub prf: Option<PrfExtensionResult>,
}

/// Credential properties returned by the browser after registration.
#[derive(Deserialize, Debug)]
pub struct CredPropsResult {
    /// Whether a discoverable (resident) credential was created.
    pub rk: Option<bool>,
}

/// PRF extension result returned by the client.
#[derive(Deserialize, Debug)]
pub struct PrfExtensionResult {
    /// Set during registration to indicate whether PRF is supported.
    pub enabled: Option<bool>,
    /// PRF outputs from the authenticator.
    pub results: Option<PrfResults>,
}

/// PRF outputs returned by the authenticator.
#[derive(Deserialize, Debug)]
pub struct PrfResults {
    /// Base64url-encoded first PRF output.
    pub first: Option<String>,
    /// Base64url-encoded second PRF output.
    pub second: Option<String>,
}
