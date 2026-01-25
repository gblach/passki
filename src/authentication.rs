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

//! Passkey authentication functionality.

use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::signature::{
    RsaPublicKeyComponents, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ED25519,
    RSA_PKCS1_2048_8192_SHA256,
};
use serde::{Deserialize, Serialize};

use crate::client_data::{ClientData, ClientDataType};
use crate::types::*;
use crate::Passki;

/// Challenge sent to the client to begin passkey authentication.
///
/// This structure contains all the parameters needed by the WebAuthn client
/// to authenticate using an existing credential.
#[derive(Serialize)]
pub struct AuthenticationChallenge {
    /// The challenge value (base64url-encoded).
    pub challenge: String,

    /// Timeout for the operation in milliseconds.
    pub timeout: u64,

    /// The relying party identifier.
    #[serde(rename = "rpId")]
    pub rp_id: String,

    /// List of credentials that are allowed for this authentication.
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<AllowCredential>,

    /// User verification requirement.
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationRequirement,
}

/// Server-side state for a passkey authentication in progress.
///
/// This state must be stored temporarily and provided when completing the authentication.
#[derive(Clone)]
pub struct AuthenticationState {
    /// The challenge that was sent to the client.
    pub challenge: Vec<u8>,

    /// List of credential IDs that are allowed for this authentication.
    pub allowed_credentials: Vec<Vec<u8>>,
}

/// Credential data returned by the client after authentication.
///
/// This structure contains the signature and authenticator data needed to
/// verify the authentication.
#[derive(Deserialize)]
pub struct AuthenticationCredential {
    /// The credential ID that was used (base64url-encoded).
    pub credential_id: String,

    /// The authenticator data (base64url-encoded).
    pub authenticator_data: String,

    /// The client data JSON (base64url-encoded).
    pub client_data_json: String,

    /// The signature over the authenticator data and client data hash (base64url-encoded).
    pub signature: String,
}

/// Result of a successful authentication.
///
/// Contains the credential ID and updated counter value.
#[derive(Debug)]
pub struct AuthenticationResult {
    /// The credential ID that was used for authentication.
    pub credential_id: Vec<u8>,

    /// The updated signature counter from the authenticator.
    pub counter: u32,
}

impl Passki {
    /// Starts a passkey authentication ceremony.
    ///
    /// Generates a challenge and returns both the challenge to send to the client
    /// and the state to store on the server.
    ///
    /// # Arguments
    ///
    /// * `passkeys` - List of stored passkeys that are allowed for this authentication
    /// * `timeout` - Timeout for the operation in milliseconds
    /// * `user_verification` - User verification requirement
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * `AuthenticationChallenge` - Challenge to send to the client
    /// * `AuthenticationState` - State to store on the server
    pub fn start_passkey_authentication(
        &self,
        passkeys: &[StoredPasskey],
        timeout: u64,
        user_verification: UserVerificationRequirement,
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let challenge = Self::generate_challenge();

        let challenge_response = AuthenticationChallenge {
            challenge: Self::base64_encode(&challenge),
            timeout,
            rp_id: self.rp_id.clone(),
            allow_credentials: passkeys
                .iter()
                .map(|pk| AllowCredential {
                    id: Self::base64_encode(&pk.credential_id),
                    type_: "public-key".to_string(),
                })
                .collect(),
            user_verification,
        };

        let state = AuthenticationState {
            challenge: challenge.clone(),
            allowed_credentials: passkeys.iter().map(|pk| pk.credential_id.clone()).collect(),
        };

        (challenge_response, state)
    }

    /// Completes a passkey authentication ceremony.
    ///
    /// Verifies the signature and authenticator data returned by the client.
    ///
    /// # Arguments
    ///
    /// * `credential` - The credential data returned by the client
    /// * `state` - The authentication state stored on the server
    /// * `stored_passkey` - The stored passkey for the credential being used
    ///
    /// # Returns
    ///
    /// An `AuthenticationResult` containing the credential ID and updated counter.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The credential is not in the allowed list
    /// * The client data is invalid
    /// * The challenge doesn't match
    /// * The origin doesn't match
    /// * The signature is invalid
    /// * The counter hasn't increased (possible replay attack)
    pub fn finish_passkey_authentication(
        &self,
        credential: &AuthenticationCredential,
        state: &AuthenticationState,
        stored_passkey: &StoredPasskey,
    ) -> Result<AuthenticationResult> {
        // Verify credential is allowed (skip check for usernameless/discoverable credential flow)
        let credential_id = Self::base64_decode(&credential.credential_id)?;
        if !state.allowed_credentials.is_empty()
            && !state.allowed_credentials.contains(&credential_id)
        {
            return Err(Box::new(PasskiError::new("Credential not allowed")));
        }

        // Verify client data
        let client_data_bytes = Self::base64_decode(&credential.client_data_json)?;
        let client_data = ClientData::from_bytes(&client_data_bytes)?;
        client_data.verify(ClientDataType::Get, &state.challenge, &self.rp_origin)?;

        // Verify counter
        let authenticator_data = Self::base64_decode(&credential.authenticator_data)?;
        if authenticator_data.len() < 37 {
            return Err(Box::new(PasskiError::new("Invalid authenticator data")));
        }

        let counter = u32::from_be_bytes([
            authenticator_data[33],
            authenticator_data[34],
            authenticator_data[35],
            authenticator_data[36],
        ]);

        if counter <= stored_passkey.counter {
            return Err(Box::new(PasskiError::new(
                "Invalid counter (possible replay attack)",
            )));
        }

        // Verify signature
        let signature = Self::base64_decode(&credential.signature)?;
        let client_data_hash = digest::digest(&SHA256, &client_data_bytes);

        // Concatenate authenticator data and client data hash
        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(client_data_hash.as_ref());

        Self::verify_signature(
            &stored_passkey.public_key,
            stored_passkey.algorithm,
            &signed_data,
            &signature,
        )?;

        Ok(AuthenticationResult {
            credential_id,
            counter,
        })
    }

    /// Verifies a signature using the appropriate algorithm.
    #[inline] pub(crate) fn verify_signature(
        cose_key_bytes: &[u8],
        algorithm: i32,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        match algorithm {
            -8 => Self::verify_eddsa(cose_key_bytes, signed_data, signature),
            -7 => Self::verify_es256(cose_key_bytes, signed_data, signature),
            -257 => Self::verify_rs256(cose_key_bytes, signed_data, signature),
            _ => Err(Box::new(PasskiError::new(format!(
                "Unsupported algorithm: {}",
                algorithm
            )))),
        }
    }

    /// Verifies an EdDSA (Ed25519) signature.
    pub(crate) fn verify_eddsa(
        cose_key_bytes: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let cose_key_value: ciborium::Value = ciborium::from_reader(cose_key_bytes)
            .map_err(|e| PasskiError::new(format!("Failed to parse COSE key: {}", e)))?;

        // Extract x coordinate from COSE key (label -2)
        let cose_map = cose_key_value
            .as_map()
            .ok_or_else(|| PasskiError::new("COSE key is not a map"))?;

        let x = cose_map
            .iter()
            .find(|(k, _)| k.as_integer() == Some((-2).into()))
            .and_then(|(_, v)| v.as_bytes())
            .ok_or_else(|| PasskiError::new("Missing x coordinate in COSE key"))?;

        if x.len() != 32 {
            return Err(Box::new(PasskiError::new(
                "Invalid Ed25519 public key length",
            )));
        }

        let public_key = UnparsedPublicKey::new(&ED25519, x);
        public_key
            .verify(signed_data, signature)
            .map_err(|_| PasskiError::new("EdDSA signature verification failed"))?;

        Ok(())
    }

    /// Verifies an ES256 (ECDSA with P-256 and SHA-256) signature.
    pub(crate) fn verify_es256(
        cose_key_bytes: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let cose_key_value: ciborium::Value = ciborium::from_reader(cose_key_bytes)
            .map_err(|e| PasskiError::new(format!("Failed to parse COSE key: {}", e)))?;

        // Extract x and y coordinates from COSE key (labels -2 and -3)
        let cose_map = cose_key_value
            .as_map()
            .ok_or_else(|| PasskiError::new("COSE key is not a map"))?;

        let x = cose_map
            .iter()
            .find(|(k, _)| k.as_integer() == Some((-2).into()))
            .and_then(|(_, v)| v.as_bytes())
            .ok_or_else(|| PasskiError::new("Missing x coordinate in COSE key"))?;

        let y = cose_map
            .iter()
            .find(|(k, _)| k.as_integer() == Some((-3).into()))
            .and_then(|(_, v)| v.as_bytes())
            .ok_or_else(|| PasskiError::new("Missing y coordinate in COSE key"))?;

        // Construct uncompressed public key (0x04 || x || y)
        let mut public_key_bytes = vec![0x04];
        public_key_bytes.extend_from_slice(x);
        public_key_bytes.extend_from_slice(y);

        // ECDSA_P256_SHA256_ASN1 handles SHA-256 hashing internally
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key_bytes);
        public_key
            .verify(signed_data, signature)
            .map_err(|_| PasskiError::new("ES256 signature verification failed"))?;

        Ok(())
    }

    /// Verifies an RS256 (RSA with SHA-256) signature.
    pub(crate) fn verify_rs256(
        cose_key_bytes: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let cose_key_value: ciborium::Value = ciborium::from_reader(cose_key_bytes)
            .map_err(|e| PasskiError::new(format!("Failed to parse COSE key: {}", e)))?;

        // Extract n and e from COSE key (labels -1 and -2)
        let cose_map = cose_key_value
            .as_map()
            .ok_or_else(|| PasskiError::new("COSE key is not a map"))?;

        let n = cose_map
            .iter()
            .find(|(k, _)| k.as_integer() == Some((-1).into()))
            .and_then(|(_, v)| v.as_bytes())
            .ok_or_else(|| PasskiError::new("Missing n (modulus) in COSE key"))?;

        let e = cose_map
            .iter()
            .find(|(k, _)| k.as_integer() == Some((-2).into()))
            .and_then(|(_, v)| v.as_bytes())
            .ok_or_else(|| PasskiError::new("Missing e (exponent) in COSE key"))?;

        // RSA_PKCS1_2048_8192_SHA256 handles SHA-256 hashing internally
        let public_key = RsaPublicKeyComponents { n, e };
        public_key
            .verify(&RSA_PKCS1_2048_8192_SHA256, signed_data, signature)
            .map_err(|_| PasskiError::new("RS256 signature verification failed"))?;

        Ok(())
    }
}
