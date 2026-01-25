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

use serde::{Deserialize, Serialize};

use crate::client_data::{ClientData, ClientDataType};
use crate::types::*;
use crate::Passki;

/// Challenge sent to the client to begin passkey registration.
///
/// This structure contains all the parameters needed by the WebAuthn client
/// to create a new credential.
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

    /// List of credentials to exclude from registration.
    ///
    /// These credentials will not be allowed to be registered again,
    /// preventing duplicate registrations.
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<ExcludeCredential>,
}

/// Server-side state for a passkey registration in progress.
///
/// This state must be stored temporarily and provided when completing the registration.
#[derive(Clone, Debug)]
pub struct RegistrationState {
    /// The challenge that was sent to the client.
    pub challenge: Vec<u8>,

    /// The user information.
    pub user: UserInfo,
}

/// Credential data returned by the client after registration.
///
/// This structure contains the new credential's ID, public key, and client data.
#[derive(Deserialize)]
pub struct RegistrationCredential {
    /// The credential ID (base64url-encoded).
    pub credential_id: String,

    /// The attestation object containing the public key (base64url-encoded).
    pub public_key: String,

    /// The client data JSON (base64url-encoded).
    pub client_data_json: String,
}

impl Passki {
    /// Starts a passkey registration ceremony.
    ///
    /// Generates a challenge and returns both the challenge to send to the client
    /// and the state to store on the server.
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identifier for the user (must be at least 16 bytes)
    /// * `username` - Username or account identifier
    /// * `display_name` - Human-readable display name for the user
    /// * `timeout` - Timeout for the operation in milliseconds
    /// * `attestation` - Attestation conveyance preference
    /// * `resident_key` - Resident key requirement
    /// * `user_verification` - User verification requirement
    /// * `existing_credentials` - Optional list of existing credentials to exclude from registration
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * `RegistrationChallenge` - Challenge to send to the client
    /// * `RegistrationState` - State to store on the server
    ///
    /// # Errors
    ///
    /// Returns an error if `user_id` is less than 16 bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn start_passkey_registration(
        &self,
        user_id: &[u8],
        username: &str,
        display_name: &str,
        timeout: u64,
        attestation: AttestationConveyancePreference,
        resident_key: ResidentKeyRequirement,
        user_verification: UserVerificationRequirement,
        existing_credentials: Option<&[StoredPasskey]>,
    ) -> Result<(RegistrationChallenge, RegistrationState)> {
        // Validate user_id length
        if user_id.len() < 16 {
            return Err(Box::new(PasskiError::new(
                "user_id must be at least 16 bytes",
            )));
        }

        let challenge = Self::generate_challenge();
        let user_id_bytes = user_id.to_vec();

        let exclude_credentials = existing_credentials
            .unwrap_or(&[])
            .iter()
            .map(|pk| ExcludeCredential {
                id: Self::base64_encode(&pk.credential_id),
                type_: "public-key".to_string(),
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
            pub_key_cred_params: vec![
                PubKeyCredParam {
                    alg: -8,
                    type_: "public-key".to_string(),
                },
                PubKeyCredParam {
                    alg: -7,
                    type_: "public-key".to_string(),
                },
                PubKeyCredParam {
                    alg: -257,
                    type_: "public-key".to_string(),
                },
            ],
            timeout,
            attestation,
            authenticator_selection: AuthenticatorSelection {
                resident_key,
                user_verification,
            },
            exclude_credentials,
        };

        let state = RegistrationState {
            challenge: challenge.clone(),
            user,
        };

        Ok((challenge_response, state))
    }

    /// Completes a passkey registration ceremony.
    ///
    /// Verifies the credential data returned by the client and returns a
    /// stored passkey that can be saved in the database.
    ///
    /// # Arguments
    ///
    /// * `credential` - The credential data returned by the client
    /// * `state` - The registration state stored on the server
    ///
    /// # Returns
    ///
    /// A `StoredPasskey` containing the credential information to save.
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
        // Verify client data
        let client_data = ClientData::from_base64(&credential.client_data_json)?;
        client_data.verify(ClientDataType::Create, &state.challenge, &self.rp_origin)?;

        // Parse attestation object to extract public key and algorithm
        let attestation_bytes = Self::base64_decode(&credential.public_key)?;
        let (public_key_bytes, algorithm) = Self::parse_attestation_object(&attestation_bytes)?;

        // Store passkey
        Ok(StoredPasskey {
            credential_id: Self::base64_decode(&credential.credential_id)?,
            public_key: public_key_bytes,
            counter: 0,
            algorithm,
        })
    }

    /// Parses a CBOR attestation object to extract the public key and algorithm.
    pub(crate) fn parse_attestation_object(attestation_bytes: &[u8]) -> Result<(Vec<u8>, i32)> {
        // Parse CBOR attestation object
        let attestation: ciborium::Value = ciborium::from_reader(attestation_bytes)
            .map_err(|e| PasskiError::new(format!("Failed to parse attestation object: {}", e)))?;

        // Extract authData
        let auth_data_bytes = attestation
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("authData")))
            .and_then(|(_, v)| v.as_bytes())
            .ok_or_else(|| PasskiError::new("Missing authData in attestation"))?;

        // Parse authenticator data
        if auth_data_bytes.len() < 37 {
            return Err(Box::new(PasskiError::new(
                "Invalid authenticator data length",
            )));
        }

        // Check if attested credential data is present (bit 6 of flags)
        let flags = auth_data_bytes[32];
        if (flags & 0x40) == 0 {
            return Err(Box::new(PasskiError::new(
                "No attested credential data present",
            )));
        }

        // Skip: rpIdHash (32) + flags (1) + signCount (4) + aaguid (16) + credIdLen (2) = 55 bytes
        if auth_data_bytes.len() < 55 {
            return Err(Box::new(PasskiError::new("Authenticator data too short")));
        }

        let cred_id_len = u16::from_be_bytes([auth_data_bytes[53], auth_data_bytes[54]]) as usize;
        let cose_key_offset = 55 + cred_id_len;

        if auth_data_bytes.len() < cose_key_offset {
            return Err(Box::new(PasskiError::new(
                "Authenticator data too short for credential",
            )));
        }

        // Parse COSE key as CBOR map
        let cose_key_bytes = &auth_data_bytes[cose_key_offset..];
        let cose_key_value: ciborium::Value = ciborium::from_reader(cose_key_bytes)
            .map_err(|e| PasskiError::new(format!("Failed to parse COSE key: {}", e)))?;

        // Extract algorithm from COSE key
        let algorithm = cose_key_value
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_integer() == Some(3.into())))
            .and_then(|(_, v)| v.as_integer())
            .and_then(|i| i.try_into().ok())
            .ok_or_else(|| PasskiError::new("Missing or invalid algorithm in COSE key"))?;

        // Store the raw COSE key bytes
        let public_key_bytes = cose_key_bytes.to_vec();

        Ok((public_key_bytes, algorithm))
    }
}
