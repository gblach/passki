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

//! Passkey registration functionality.

use aws_lc_rs::digest::{self, SHA256};
use serde::{Deserialize, Serialize};

use crate::Passki;
use crate::client_data::{ClientData, ClientDataType};
use crate::types::*;

/// Challenge sent to the client to begin passkey registration.
///
/// Serialize this to JSON and hand it to `navigator.credentials.create()`.
#[derive(Serialize, Debug)]
pub struct RegistrationChallenge {
    /// Information about the relying party.
    pub rp: RelyingParty,

    /// Information about the user.
    pub user: UserInfo,

    /// The challenge value (base64url-encoded).
    pub challenge: String,

    /// List of acceptable public key credential parameters.
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,

    /// Timeout for the operation in milliseconds.
    pub timeout: u64,

    /// Attestation conveyance preference.
    pub attestation: AttestationConveyancePreference,

    /// Authenticator selection criteria.
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelection,

    /// Credentials the user already has, which the authenticator must refuse to register a second
    /// time.
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<ExcludeCredential>,

    /// WebAuthn extensions to request from the authenticator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<RegistrationExtensions>,
}

/// Server-side half of a registration in progress.
///
/// Keep it in a session or cache between the two steps; without it the response cannot be verified.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegistrationState {
    /// The challenge that was sent to the client.
    pub challenge: Vec<u8>,

    /// The user information.
    pub user: UserInfo,

    /// What was asked for when the ceremony started, re-checked against what the authenticator
    /// actually did.
    pub user_verification: UserVerificationRequirement,
}

/// What the client sends back after `navigator.credentials.create()`.
#[derive(Deserialize)]
pub struct RegistrationCredential {
    /// The credential ID (base64url-encoded).
    pub credential_id: String,

    /// The attestation object, which carries the new public key (base64url-encoded).
    pub public_key: String,

    /// The client data JSON (base64url-encoded).
    pub client_data_json: String,

    /// Extension results from the client (e.g., PRF support flag).
    pub client_extension_results: Option<ClientExtensionResults>,

    /// Whether the client used a built-in or a separate authenticator. `None` when
    /// it did not report.
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// What `getTransports()` reported. Empty when the client sent nothing, and also when the front
    /// end simply does not forward the list.
    #[serde(default, deserialize_with = "deserialize_transports")]
    pub transports: Vec<AuthenticatorTransport>,
}

/// Options for starting a passkey registration ceremony.
///
/// The [`Default`] value uses a 60 second timeout, no attestation, and `Preferred` resident
/// key and user verification requirements.
#[derive(Debug)]
#[non_exhaustive]
pub struct RegistrationOptions<'a> {
    /// Timeout for the operation in milliseconds.
    pub timeout: u64,

    /// Attestation conveyance preference.
    pub attestation: AttestationConveyancePreference,

    /// Resident key requirement.
    pub resident_key: ResidentKeyRequirement,

    /// User verification requirement.
    pub user_verification: UserVerificationRequirement,

    /// Restricts registration to platform or roaming authenticators. `None` lets the client offer
    /// both.
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// Existing credentials to exclude from registration.
    pub exclude_credentials: Option<&'a [StoredPasskey]>,

    /// WebAuthn extensions to request from the authenticator.
    pub extensions: Option<RegistrationExtensions>,
}

impl Default for RegistrationOptions<'_> {
    fn default() -> Self {
        Self {
            timeout: 60000,
            attestation: AttestationConveyancePreference::None,
            resident_key: ResidentKeyRequirement::Preferred,
            user_verification: UserVerificationRequirement::Preferred,
            authenticator_attachment: None,
            exclude_credentials: None,
            extensions: None,
        }
    }
}

/// Authenticator data parsed from a CBOR attestation object.
#[derive(Debug)]
pub(crate) struct ParsedAttestation {
    /// The credential ID from the attested credential data.
    pub credential_id: Vec<u8>,

    /// The raw COSE public key bytes.
    pub public_key: Vec<u8>,

    /// The COSE algorithm identifier.
    pub algorithm: i32,

    /// The authenticator data flags byte.
    pub flags: u8,

    /// The signature counter at registration time.
    pub counter: u32,

    /// Identifies the authenticator model.
    pub aaguid: [u8; 16],

    /// Left at [`AttestationType::None`] here, since parsing authenticator data sees no attestation
    /// statement; `verify_attestation` fills it in.
    pub attestation_type: AttestationType,
}

impl Passki {
    /// Starts a passkey registration: generates a random challenge and returns it alongside
    /// the state needed to finish.
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identifier for the user (must be at least 16 bytes)
    /// * `username` - Username or account identifier
    /// * `display_name` - Human-readable display name for the user
    /// * `options` - Ceremony options; see [`RegistrationOptions`]
    ///
    /// # Returns
    ///
    /// The challenge to send to the client, and the state to keep on the server.
    ///
    /// # Errors
    ///
    /// Returns an error if `user_id` is less than 16 bytes.
    pub fn start_passkey_registration(
        &self,
        user_id: &[u8],
        username: &str,
        display_name: &str,
        options: RegistrationOptions<'_>,
    ) -> Result<(RegistrationChallenge, RegistrationState)> {
        if user_id.len() < 16 {
            return Err(PasskiError::UserIdTooShort);
        }

        let challenge = Self::generate_challenge();
        let user_id_bytes = user_id.to_vec();

        let exclude_credentials = options
            .exclude_credentials
            .unwrap_or(&[])
            .iter()
            .map(|pk| ExcludeCredential {
                id: Self::base64_encode(&pk.credential_id),
                type_: "public-key",
                transports: pk.transports.clone(),
            })
            .collect();

        let user = UserInfo {
            id: Self::base64_encode(&user_id_bytes),
            name: username.to_string(),
            display_name: display_name.to_string(),
        };

        let challenge_response = RegistrationChallenge {
            rp: RelyingParty {
                name: self.rp_name.clone(),
                id: self.rp_id.clone(),
            },
            user: user.clone(),
            challenge: Self::base64_encode(&challenge),
            pub_key_cred_params: [ALG_EDDSA, ALG_ES256, ALG_ES384, ALG_RS256, ALG_RS384]
                .into_iter()
                .map(|alg| PubKeyCredParam {
                    alg,
                    type_: "public-key",
                })
                .collect(),
            timeout: options.timeout,
            attestation: options.attestation,
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment: options.authenticator_attachment,
                resident_key: options.resident_key,
                user_verification: options.user_verification,
            },
            exclude_credentials,
            extensions: options.extensions,
        };

        let state = RegistrationState {
            challenge: challenge.clone(),
            user,
            user_verification: options.user_verification,
        };

        Ok((challenge_response, state))
    }

    /// Completes a passkey registration by verifying what the client returned.
    ///
    /// # Arguments
    ///
    /// * `credential` - The credential data returned by the client
    /// * `state` - The registration state stored on the server
    ///
    /// # Returns
    ///
    /// A `StoredPasskey` to save in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The client data is invalid
    /// * The challenge doesn't match
    /// * The origin doesn't match
    /// * The attestation object is malformed
    pub fn finish_passkey_registration(
        &self,
        credential: &RegistrationCredential,
        state: &RegistrationState,
    ) -> Result<StoredPasskey> {
        let client_data_bytes = Self::base64_decode(&credential.client_data_json)?;
        let client_data = ClientData::from_bytes(&client_data_bytes)?;
        client_data.verify(ClientDataType::Create, &state.challenge, &self.rp_origins)?;
        let client_data_hash = digest::digest(&SHA256, &client_data_bytes);

        let attestation_bytes = Self::base64_decode(&credential.public_key)?;
        let parsed = self.verify_attestation(&attestation_bytes, client_data_hash.as_ref())?;

        if (parsed.flags & FLAG_UP) == 0 {
            return Err(PasskiError::UserNotPresent);
        }
        if state.user_verification == UserVerificationRequirement::Required
            && (parsed.flags & FLAG_UV) == 0
        {
            return Err(PasskiError::UserVerificationRequired);
        }

        // The signed authenticator data is authoritative; the ID the client sent alongside it must
        // agree.
        let credential_id = Self::base64_decode(&credential.credential_id)?;
        if credential_id != parsed.credential_id {
            return Err(PasskiError::CredentialIdMismatch);
        }

        let rk = credential
            .client_extension_results
            .as_ref()
            .and_then(|ext| ext.cred_props.as_ref())
            .and_then(|cp| cp.rk);

        let large_blob_supported = credential
            .client_extension_results
            .as_ref()
            .and_then(|ext| ext.large_blob.as_ref())
            .and_then(|lb| lb.supported);

        Ok(StoredPasskey {
            credential_id: parsed.credential_id,
            public_key: parsed.public_key,
            counter: parsed.counter,
            algorithm: parsed.algorithm,
            aaguid: parsed.aaguid,
            attestation_type: parsed.attestation_type,
            transports: credential.transports.clone(),
            rk,
            large_blob_supported,
            be: (parsed.flags & FLAG_BE) != 0,
            bs: (parsed.flags & FLAG_BS) != 0,
        })
    }

    /// Splits a CBOR attestation object into its `fmt`, raw `authData`, and `attStmt`.
    pub(crate) fn split_attestation_object(
        attestation_bytes: &[u8],
    ) -> Result<(Option<String>, Vec<u8>, ciborium::Value)> {
        let attestation: ciborium::Value = ciborium::from_reader(attestation_bytes)?;

        let map = attestation
            .as_map()
            .ok_or_else(|| PasskiError::InvalidAttestationObject("not a map".to_string()))?;

        let auth_data = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("authData"))
            .and_then(|(_, v)| v.as_bytes())
            .ok_or_else(|| PasskiError::InvalidAttestationObject("Missing authData".to_string()))?
            .to_vec();

        let fmt = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("fmt"))
            .and_then(|(_, v)| v.as_text())
            .map(str::to_string);

        let att_stmt = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("attStmt"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| ciborium::Value::Map(Vec::new()));

        Ok((fmt, auth_data, att_stmt))
    }

    /// Parses an attestation object without verifying its attestation statement.
    #[cfg(test)]
    pub(crate) fn parse_attestation_object(
        &self,
        attestation_bytes: &[u8],
    ) -> Result<ParsedAttestation> {
        let (_, auth_data, _) = Self::split_attestation_object(attestation_bytes)?;
        self.parse_auth_data(&auth_data)
    }

    /// Parses authenticator data, whose layout is a fixed 37-byte header (rpIdHash, flags, counter)
    /// followed by the attested credential data.
    pub(crate) fn parse_auth_data(&self, auth_data_bytes: &[u8]) -> Result<ParsedAttestation> {
        if auth_data_bytes.len() < 37 {
            return Err(PasskiError::InvalidAuthenticatorData);
        }

        // Bytes 0-31 bind the credential to our domain.
        let rp_id_hash = digest::digest(&SHA256, self.rp_id.as_bytes());
        if &auth_data_bytes[..32] != rp_id_hash.as_ref() {
            return Err(PasskiError::RpIdHashMismatch);
        }

        let flags = auth_data_bytes[32];

        if (flags & FLAG_BS) != 0 && (flags & FLAG_BE) == 0 {
            return Err(PasskiError::InvalidBackupFlags);
        }

        let counter = u32::from_be_bytes([
            auth_data_bytes[33],
            auth_data_bytes[34],
            auth_data_bytes[35],
            auth_data_bytes[36],
        ]);

        if (flags & FLAG_AT) == 0 {
            return Err(PasskiError::NoAttestedCredentialData);
        }

        // Header (37) + aaguid (16) + credential ID length (2) = 55 bytes
        if auth_data_bytes.len() < 55 {
            return Err(PasskiError::InvalidAuthenticatorData);
        }

        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&auth_data_bytes[37..53]);

        let cred_id_len = u16::from_be_bytes([auth_data_bytes[53], auth_data_bytes[54]]) as usize;
        let cose_key_offset = 55 + cred_id_len;

        if auth_data_bytes.len() < cose_key_offset {
            return Err(PasskiError::InvalidAuthenticatorData);
        }

        let credential_id = auth_data_bytes[55..cose_key_offset].to_vec();

        let cose_key_bytes = &auth_data_bytes[cose_key_offset..];
        let cose_key_value: ciborium::Value = ciborium::from_reader(cose_key_bytes)?;

        let algorithm = cose_key_value
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_integer() == Some(3.into())))
            .and_then(|(_, v)| v.as_integer())
            .and_then(|i| i.try_into().ok())
            .ok_or_else(|| {
                PasskiError::InvalidCoseKey("Missing or invalid algorithm".to_string())
            })?;

        // Re-serialize the key: the remaining bytes may carry extension data after it, which must
        // not be stored as part of the key.
        let mut public_key = Vec::new();
        ciborium::into_writer(&cose_key_value, &mut public_key)?;

        Ok(ParsedAttestation {
            credential_id,
            public_key,
            algorithm,
            flags,
            counter,
            aaguid,
            attestation_type: AttestationType::None,
        })
    }
}
