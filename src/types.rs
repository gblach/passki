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
/// One variant per way a ceremony can fail, so callers can react to a specific
/// failure - a [`PasskiError::CounterRegression`] means something quite
/// different from a malformed request - without matching on message strings.
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

    /// The client data origin did not match any of the relying party's origins.
    #[error("Invalid origin: expected one of {expected:?}, got {got}")]
    OriginMismatch { expected: Vec<String>, got: String },

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

    /// The BS (backup state) flag was set without the BE (backup eligibility)
    /// flag, which the WebAuthn spec forbids.
    #[error("BS flag set without BE flag")]
    InvalidBackupFlags,

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

    /// The certificate chain did not hold together: a broken signature link, an
    /// expired certificate, or an issuer that is not a CA.
    #[error("Invalid attestation certificate chain: {0}")]
    InvalidCertificateChain(String),

    /// The chain was well formed but did not reach any of the roots installed
    /// with [`crate::Passki::with_attestation_trust`].
    #[error("Attestation certificate chain does not reach a trust anchor")]
    UntrustedAttestation,

    /// [`AttestationTrustPolicy::Required`] is in effect but the authenticator
    /// sent no attestation certificate to validate.
    #[error("Attestation is required but the statement carried no certificate chain")]
    MissingAttestationChain,
}

/// Convenience type alias for Results returned by Passki operations.
pub type Result<T> = std::result::Result<T, PasskiError>;

// Authenticator data flag bits

/// UP: the user interacted with the authenticator.
pub(crate) const FLAG_UP: u8 = 0x01;
/// UV: the user was verified by PIN or biometric.
pub(crate) const FLAG_UV: u8 = 0x04;
/// BE: the credential may be synced to other devices.
pub(crate) const FLAG_BE: u8 = 0x08;
/// BS: the credential is currently synced.
pub(crate) const FLAG_BS: u8 = 0x10;
/// AT: attested credential data follows the fixed-size header.
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

/// How much the relying party wants to learn about the authenticator hardware
/// at registration.
///
/// Attestation is the authenticator's signed claim about what model it is.
/// Synced passkeys usually return nothing regardless of what is asked for.
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

/// What an attestation statement turned out to be worth.
///
/// [`AttestationType::Basic`] and [`AttestationType::AttCa`] are only reported
/// after a certificate chain reached a trusted root, so either of them means the
/// authenticator model is proven. Every other variant leaves it a claim.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationType {
    /// No statement at all, which is what
    /// [`AttestationConveyancePreference::None`] asks for. Nothing is known
    /// about the authenticator model.
    #[default]
    None,

    /// The credential key signed its own statement, proving only that the
    /// authenticator holds the matching private key.
    SelfAttested,

    /// A certificate chain arrived but was not validated, because
    /// [`AttestationTrustPolicy::Ignore`] is in effect. A client can mint such a
    /// certificate claiming any model and still pass every check made here.
    Unverified,

    /// Validated chain from a certificate shared by all authenticators of the
    /// same model.
    Basic,

    /// Validated chain from a per-device certificate issued by the vendor's CA.
    AttCa,
}

/// How strictly attestation certificate chains are checked, set together with
/// the trust anchors by [`crate::Passki::with_attestation_trust`].
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum AttestationTrustPolicy {
    /// Do not validate chains. Statements are still checked for internal
    /// consistency, and one carrying certificates is reported as
    /// [`AttestationType::Unverified`]. The default, and what releases before
    /// 0.3.0 did unconditionally.
    #[default]
    Ignore,

    /// Validate whenever the statement carries certificates, and reject the
    /// registration if the chain does not reach an anchor. Statements without
    /// certificates are still accepted.
    VerifyWhenPresent,

    /// As [`AttestationTrustPolicy::VerifyWhenPresent`], but also reject
    /// statements carrying no chain at all. Most synced passkeys return none, so
    /// this only suits deployments limited to security keys.
    Required,
}

/// Whether the authenticator is built into the device or a separate one.
///
/// As a registration option it restricts what the client offers. Reported back
/// on a credential it says what was actually used, but that value comes from the
/// client and is not signed, so treat it as a hint, not as authorization.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    /// An authenticator built into the client device (e.g. Touch ID, Windows Hello).
    Platform,
    /// A roaming authenticator, such as a security key or a phone used over hybrid transport.
    CrossPlatform,
}

/// How an authenticator can be reached.
///
/// The client reports this at registration via `getTransports()`. Echoing it
/// back in later ceremonies lets the browser prompt for the one the credential
/// actually lives on instead of offering every option.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorTransport {
    /// Removable USB.
    Usb,
    /// Near Field Communication.
    Nfc,
    /// Bluetooth Low Energy.
    Ble,
    /// ISO/IEC 7816 smart card.
    SmartCard,
    /// A phone acting as an authenticator for a nearby computer, over a mix of
    /// Bluetooth and the network. Called `cable` before it was renamed.
    Hybrid,
    /// Built into the client device and not removable.
    Internal,
}

impl AuthenticatorTransport {
    /// Maps a transport string to its variant, accepting the legacy `cable`
    /// spelling. Returns `None` for anything else.
    fn parse(value: &str) -> Option<Self> {
        match value {
            "usb" => Some(Self::Usb),
            "nfc" => Some(Self::Nfc),
            "ble" => Some(Self::Ble),
            "smart-card" => Some(Self::SmartCard),
            "hybrid" | "cable" => Some(Self::Hybrid),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Deserializes a `transports` list, dropping unknown values and normalizing the
/// legacy `cable` value to `hybrid`. A missing or `null` list reads as empty.
///
/// Clients send transports from newer spec levels than the server was built
/// against, and the spec says not to fail on those, so an unrecognized entry is
/// dropped rather than rejecting the whole credential. Nothing is lost: the list
/// is only a hint passed back to the client.
pub(crate) fn deserialize_transports<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<AuthenticatorTransport>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default();
    let mut transports = Vec::with_capacity(raw.len());

    for value in raw {
        if let Some(transport) = AuthenticatorTransport::parse(&value)
            && !transports.contains(&transport)
        {
            transports.push(transport);
        }
    }

    Ok(transports)
}

/// Whether the authenticator should store the credential itself.
///
/// A resident (discoverable) credential can be picked from a list without the
/// user typing a username first; otherwise the server must name the credential
/// up front. Storage on the authenticator is limited, hence the choice.
#[derive(Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    /// Do not create a resident credential.
    Discouraged,
    /// Create one if possible.
    Preferred,
    /// Fail registration if one cannot be created.
    Required,
}

/// Whether the user must prove who they are, with a PIN or biometric, rather
/// than merely touching the authenticator.
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

/// A registered passkey, as it should be saved in the database.
///
/// Everything needed to verify this credential's future authentications. All
/// `#[serde(default)]` fields read as their default for passkeys serialized
/// before that field existed.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct StoredPasskey {
    /// The unique identifier for this credential.
    pub credential_id: Vec<u8>,

    /// The public key in COSE format.
    pub public_key: Vec<u8>,

    /// Counts how often this credential has been used. Must be stored after each
    /// authentication; a value that fails to increase means a cloned authenticator.
    pub counter: u32,

    /// The COSE algorithm identifier (e.g., -7 for ES256, -8 for EdDSA, -257 for RS256).
    pub algorithm: i32,

    /// Identifies the authenticator model. All-zero when the authenticator stayed
    /// anonymous, which is what [`AttestationConveyancePreference::None`] asks for.
    #[serde(default)]
    pub aaguid: [u8; 16],

    /// Whether `aaguid` above was proven or merely claimed. Only
    /// [`AttestationType::Basic`] and [`AttestationType::AttCa`] mean proven.
    #[serde(default)]
    pub attestation_type: AttestationType,

    /// What the client reported at registration, sent back in later ceremonies so
    /// the browser prompts for the right one. Empty if the client reported none.
    #[serde(default, deserialize_with = "deserialize_transports")]
    pub transports: Vec<AuthenticatorTransport>,

    /// Whether a discoverable (resident) credential was created, per the
    /// `credProps` extension. `None` if that extension was not requested or the
    /// client did not answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,

    /// Whether this credential can store a blob, per the `largeBlob` extension.
    /// Only reported at registration, so a caller that drops it cannot find out
    /// later whether a read or write is worth attempting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub large_blob_supported: Option<bool>,

    /// BE flag: the credential may be synced across the user's devices.
    #[serde(default)]
    pub be: bool,

    /// BS flag: the credential is currently synced. Always `false` when `be` is.
    #[serde(default)]
    pub bs: bool,
}

/// The site requesting authentication, as sent to the browser.
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

/// One signature algorithm the relying party will accept.
#[derive(Serialize, Debug)]
pub struct PubKeyCredParam {
    /// COSE algorithm identifier (e.g., -7 for ES256).
    pub alg: i32,

    /// Credential type (always "public-key" for passkeys).
    #[serde(rename = "type")]
    pub type_: &'static str,
}

/// Constraints on which authenticators the browser may use for registration.
#[derive(Serialize, Debug)]
#[non_exhaustive]
pub struct AuthenticatorSelection {
    /// Restricts registration to platform or roaming authenticators. Omitted
    /// from the challenge when `None`, which lets the client offer both.
    #[serde(
        rename = "authenticatorAttachment",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// Resident key requirement.
    #[serde(rename = "residentKey")]
    pub resident_key: ResidentKeyRequirement,

    /// User verification requirement.
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationRequirement,
}

/// An existing credential the authenticator must refuse to register again.
#[derive(Serialize, Debug)]
#[non_exhaustive]
pub struct ExcludeCredential {
    /// The credential ID (base64url-encoded).
    pub id: String,

    /// Credential type (always "public-key" for passkeys).
    #[serde(rename = "type")]
    pub type_: &'static str,

    /// Transports reported at registration. Omitted when empty, leaving the
    /// client free to probe everything it supports.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<AuthenticatorTransport>,
}

/// A credential the browser may use for this authentication.
#[derive(Serialize, Debug)]
#[non_exhaustive]
pub struct AllowCredential {
    /// The credential ID (base64url-encoded).
    pub id: String,

    /// Credential type (always "public-key" for passkeys).
    #[serde(rename = "type")]
    pub type_: &'static str,

    /// Transports reported at registration. Omitted when empty, leaving the
    /// client free to probe everything it supports.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<AuthenticatorTransport>,
}

/// Extensions included in a registration challenge.
#[derive(Serialize, Debug, Default)]
#[non_exhaustive]
pub struct RegistrationExtensions {
    #[serde(rename = "credProps", skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfInput>,
    #[serde(rename = "largeBlob", skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlobRegistrationInput>,
}

/// Extensions included in an authentication challenge.
#[derive(Serialize, Debug, Default)]
#[non_exhaustive]
pub struct AuthenticationExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfInput>,
    #[serde(rename = "largeBlob", skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlobAuthenticationInput>,
}

/// `prf` extension input included in challenges.
///
/// The authenticator derives a secret from the credential and the inputs below.
/// The same inputs always yield the same secret, which makes it usable as an
/// encryption key that never leaves the user's devices.
#[derive(Serialize, Debug, Default)]
pub struct PrfInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval: Option<PrfEval>,
}

/// The inputs the authenticator derives its PRF outputs from.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrfEval {
    /// Base64url-encoded first PRF input.
    pub first: String,
    /// Optional base64url-encoded second PRF input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}

/// `largeBlob` extension input included in registration challenges.
///
/// Asks for a credential that can hold a small amount of data on the
/// authenticator itself. The data is read and written in later authentication
/// ceremonies, with [`LargeBlobAuthenticationInput`].
#[derive(Serialize, Debug)]
pub struct LargeBlobRegistrationInput {
    /// How badly the relying party wants blob storage.
    pub support: LargeBlobSupport,
}

/// How badly a relying party wants the new credential to support blob storage.
#[derive(Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LargeBlobSupport {
    /// Fail the registration when the authenticator cannot store a blob.
    Required,
    /// Register either way, and report the answer in
    /// [`StoredPasskey::large_blob_supported`].
    Preferred,
}

/// `largeBlob` extension input included in authentication challenges.
///
/// An enum because the spec allows only one of read and write per ceremony. A
/// write replaces the whole blob; there is no append.
#[derive(Debug)]
pub enum LargeBlobAuthenticationInput {
    /// Read the blob, which arrives decoded in
    /// [`crate::AuthenticationResult::large_blob`].
    Read,
    /// Overwrite the blob with these base64url-encoded bytes, as produced by
    /// [`crate::Passki::base64_encode`].
    Write(String),
}

impl Serialize for LargeBlobAuthenticationInput {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::Read => map.serialize_entry("read", &true)?,
            Self::Write(blob) => map.serialize_entry("write", blob)?,
        }
        map.end()
    }
}

/// What `credential.getClientExtensionResults()` returned in the browser, one
/// field per extension.
///
/// Shared by [`RegistrationCredential`] and [`AuthenticationCredential`];
/// supporting another extension means adding a field here.
#[derive(Deserialize, Debug, Default)]
#[non_exhaustive]
pub struct ClientExtensionResults {
    /// Results for the credProps extension.
    #[serde(default, rename = "credProps")]
    pub cred_props: Option<CredPropsResult>,
    /// Results for the PRF extension.
    #[serde(default)]
    pub prf: Option<PrfExtensionResult>,
    /// Results for the largeBlob extension.
    #[serde(default, rename = "largeBlob")]
    pub large_blob: Option<LargeBlobResult>,
}

/// Credential properties returned by the browser after registration.
#[derive(Deserialize, Debug)]
pub struct CredPropsResult {
    /// Whether a discoverable (resident) credential was created.
    pub rk: Option<bool>,
}

/// `prf` extension result returned by the client.
#[derive(Deserialize, Debug)]
pub struct PrfExtensionResult {
    /// Set at registration: whether the authenticator supports PRF at all.
    pub enabled: Option<bool>,
    /// The derived secrets, returned during authentication.
    pub results: Option<PrfResults>,
}

/// The secrets the authenticator derived from the PRF inputs.
#[derive(Deserialize, Debug)]
pub struct PrfResults {
    /// Base64url-encoded first PRF output.
    pub first: Option<String>,
    /// Base64url-encoded second PRF output.
    pub second: Option<String>,
}

/// `largeBlob` extension result returned by the client.
///
/// Which field is set follows what was asked for: `supported` answers a
/// registration input, `blob` a read, `written` a write.
#[derive(Deserialize, Debug)]
pub struct LargeBlobResult {
    /// Set at registration: whether the new credential can store a blob.
    pub supported: Option<bool>,
    /// Base64url-encoded blob read from the credential.
    pub blob: Option<String>,
    /// Set after a write: whether the blob was stored.
    pub written: Option<bool>,
}
