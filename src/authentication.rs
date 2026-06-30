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
    ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519, EcdsaVerificationAlgorithm,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RsaParameters, RsaPublicKeyComponents,
    UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::Passki;
use crate::client_data::{ClientData, ClientDataType};
use crate::types::*;

/// Challenge sent to the client to begin passkey authentication.
///
/// This structure contains all the parameters needed by the WebAuthn client
/// to authenticate using an existing credential.
#[derive(Serialize, Debug)]
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

    /// WebAuthn extensions to request from the authenticator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensions>,
}

/// Server-side state for a passkey authentication in progress.
///
/// This state must be stored temporarily and provided when completing the authentication.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AuthenticationState {
    /// The challenge that was sent to the client.
    pub challenge: Vec<u8>,

    /// List of credential IDs that are allowed for this authentication.
    pub allowed_credentials: Vec<Vec<u8>>,

    /// The user verification requirement requested when the ceremony was started.
    pub user_verification: UserVerificationRequirement,
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

    /// The user handle returned by the authenticator (base64url-encoded).
    ///
    /// This is the `user.id` set during registration. Authenticators only return it
    /// for discoverable credentials, so it is the primary way to identify the user in
    /// usernameless flows where `allowCredentials` was empty.
    pub user_handle: Option<String>,

    /// Extension results from the client (e.g., PRF outputs).
    pub client_extension_results: Option<ClientExtensionResults>,
}

/// Result of a successful authentication.
///
/// Contains the credential ID, updated counter, and any PRF outputs.
#[derive(Debug)]
pub struct AuthenticationResult {
    /// The credential ID that was used for authentication.
    pub credential_id: Vec<u8>,

    /// The updated signature counter from the authenticator.
    pub counter: u32,

    /// The decoded user handle (`user.id` from registration), if the authenticator
    /// returned one. Use this to identify the user in usernameless flows.
    pub user_handle: Option<Vec<u8>>,

    /// Decoded first PRF output, if the PRF extension was requested and supported.
    pub prf_first: Option<Vec<u8>>,

    /// Decoded second PRF output, if a second input was requested and supported.
    pub prf_second: Option<Vec<u8>>,
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
    /// * `extensions` - Optional WebAuthn extensions, e.g. `Some(AuthenticationExtensions { prf:
    ///   PrfInput { eval: Some(PrfEval { first: ..., second: None }) } })` to request a PRF
    ///   derivation.
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
        extensions: Option<AuthenticationExtensions>,
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
            extensions,
        };

        let state = AuthenticationState {
            challenge: challenge.clone(),
            allowed_credentials: passkeys.iter().map(|pk| pk.credential_id.clone()).collect(),
            user_verification,
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

        let client_data_bytes = Self::base64_decode(&credential.client_data_json)?;
        let client_data = ClientData::from_bytes(&client_data_bytes)?;
        client_data.verify(ClientDataType::Get, &state.challenge, &self.rp_origin)?;

        let authenticator_data = Self::base64_decode(&credential.authenticator_data)?;
        if authenticator_data.len() < 37 {
            return Err(Box::new(PasskiError::new("Invalid authenticator data")));
        }

        // Verify rpId hash (bytes 0-31)
        let rp_id_hash = digest::digest(&SHA256, self.rp_id.as_bytes());
        if &authenticator_data[..32] != rp_id_hash.as_ref() {
            return Err(Box::new(PasskiError::new("rpId hash mismatch")));
        }

        // Check UP flag - user must be present
        let flags = authenticator_data[32];
        if (flags & FLAG_UP) == 0 {
            return Err(Box::new(PasskiError::new(
                "User not present (UP flag not set)",
            )));
        }

        // Check UV flag - required only when user_verification is Required
        if state.user_verification == UserVerificationRequirement::Required
            && (flags & FLAG_UV) == 0
        {
            return Err(Box::new(PasskiError::new(
                "User verification required but UV flag not set",
            )));
        }

        let counter = u32::from_be_bytes([
            authenticator_data[33],
            authenticator_data[34],
            authenticator_data[35],
            authenticator_data[36],
        ]);

        // Per the WebAuthn spec, the counter check only applies when at least one
        // of the values is nonzero. Both being zero means the authenticator does
        // not use counters (e.g. Google Password Manager), which is valid.
        if (counter != 0 || stored_passkey.counter != 0) && counter <= stored_passkey.counter {
            return Err(Box::new(PasskiError::new(
                "Invalid counter (possible replay attack)",
            )));
        }

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

        let prf_results = credential
            .client_extension_results
            .as_ref()
            .and_then(|ext| ext.prf.as_ref())
            .and_then(|prf| prf.results.as_ref());

        let prf_first = prf_results
            .and_then(|r| r.first.as_deref())
            .map(Self::base64_decode)
            .transpose()?;
        let prf_second = prf_results
            .and_then(|r| r.second.as_deref())
            .map(Self::base64_decode)
            .transpose()?;

        let user_handle = credential
            .user_handle
            .as_deref()
            .map(Self::base64_decode)
            .transpose()?;

        Ok(AuthenticationResult {
            credential_id,
            counter,
            user_handle,
            prf_first,
            prf_second,
        })
    }

    /// Verifies a signature using the appropriate algorithm.
    #[inline]
    pub(crate) fn verify_signature(
        cose_key_bytes: &[u8],
        algorithm: i32,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        match algorithm {
            ALG_EDDSA => Self::verify_eddsa(cose_key_bytes, signed_data, signature),
            ALG_ES256 => Self::verify_ecdsa(
                &ECDSA_P256_SHA256_ASN1,
                CRV_P256,
                "ES256",
                cose_key_bytes,
                signed_data,
                signature,
            ),
            ALG_ES384 => Self::verify_ecdsa(
                &ECDSA_P384_SHA384_ASN1,
                CRV_P384,
                "ES384",
                cose_key_bytes,
                signed_data,
                signature,
            ),
            ALG_RS256 => Self::verify_rsa(
                &RSA_PKCS1_2048_8192_SHA256,
                "RS256",
                cose_key_bytes,
                signed_data,
                signature,
            ),
            ALG_RS384 => Self::verify_rsa(
                &RSA_PKCS1_2048_8192_SHA384,
                "RS384",
                cose_key_bytes,
                signed_data,
                signature,
            ),
            _ => Err(Box::new(PasskiError::new(format!(
                "Unsupported algorithm: {}",
                algorithm
            )))),
        }
    }

    /// Parses COSE key bytes into a CBOR map.
    pub(crate) fn cose_parse(
        cose_key_bytes: &[u8],
    ) -> Result<Vec<(ciborium::Value, ciborium::Value)>> {
        let cose_key_value: ciborium::Value = ciborium::from_reader(cose_key_bytes)
            .map_err(|e| PasskiError::new(format!("Failed to parse COSE key: {}", e)))?;

        match cose_key_value {
            ciborium::Value::Map(map) => Ok(map),
            _ => Err(Box::new(PasskiError::new("COSE key is not a map"))),
        }
    }

    /// Looks up a byte-string field in a COSE key map by its integer label.
    pub(crate) fn cose_field<'a>(
        cose_map: &'a [(ciborium::Value, ciborium::Value)],
        label: i64,
        name: &str,
    ) -> Result<&'a [u8]> {
        cose_map
            .iter()
            .find(|(k, _)| k.as_integer() == Some(label.into()))
            .and_then(|(_, v)| v.as_bytes())
            .map(Vec::as_slice)
            .ok_or_else(|| PasskiError::new(format!("Missing {} in COSE key", name)).into())
    }

    /// Verifies that an integer field in a COSE key map has the expected value.
    fn cose_expect(
        cose_map: &[(ciborium::Value, ciborium::Value)],
        label: i64,
        name: &str,
        expected: i64,
    ) -> Result<()> {
        let value: i64 = cose_map
            .iter()
            .find(|(k, _)| k.as_integer() == Some(label.into()))
            .and_then(|(_, v)| v.as_integer())
            .and_then(|i| i.try_into().ok())
            .ok_or_else(|| PasskiError::new(format!("Missing {} in COSE key", name)))?;

        if value != expected {
            return Err(Box::new(PasskiError::new(format!(
                "Invalid {} in COSE key: expected {}, got {}",
                name, expected, value
            ))));
        }

        Ok(())
    }

    /// Verifies an EdDSA (Ed25519) signature.
    pub(crate) fn verify_eddsa(
        cose_key_bytes: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let cose_map = Self::cose_parse(cose_key_bytes)?;
        Self::cose_expect(&cose_map, 1, "kty", KTY_OKP)?;
        Self::cose_expect(&cose_map, -1, "crv", CRV_ED25519)?;
        let x = Self::cose_field(&cose_map, -2, "x coordinate")?;

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

    /// Verifies an ECDSA signature (ES256 or ES384).
    pub(crate) fn verify_ecdsa(
        algorithm: &'static EcdsaVerificationAlgorithm,
        crv: i64,
        name: &str,
        cose_key_bytes: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let cose_map = Self::cose_parse(cose_key_bytes)?;
        Self::cose_expect(&cose_map, 1, "kty", KTY_EC2)?;
        Self::cose_expect(&cose_map, -1, "crv", crv)?;
        let x = Self::cose_field(&cose_map, -2, "x coordinate")?;
        let y = Self::cose_field(&cose_map, -3, "y coordinate")?;

        // Construct uncompressed public key (0x04 || x || y)
        let mut public_key_bytes = vec![0x04];
        public_key_bytes.extend_from_slice(x);
        public_key_bytes.extend_from_slice(y);

        // The verification algorithm handles hashing internally
        let public_key = UnparsedPublicKey::new(algorithm, &public_key_bytes);
        public_key
            .verify(signed_data, signature)
            .map_err(|_| PasskiError::new(format!("{} signature verification failed", name)))?;

        Ok(())
    }

    /// Verifies an RSA PKCS#1 v1.5 signature (RS256 or RS384).
    pub(crate) fn verify_rsa(
        algorithm: &'static RsaParameters,
        name: &str,
        cose_key_bytes: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let cose_map = Self::cose_parse(cose_key_bytes)?;
        Self::cose_expect(&cose_map, 1, "kty", KTY_RSA)?;
        let n = Self::cose_field(&cose_map, -1, "n (modulus)")?;
        let e = Self::cose_field(&cose_map, -2, "e (exponent)")?;

        // The verification algorithm handles hashing internally
        let public_key = RsaPublicKeyComponents { n, e };
        public_key
            .verify(algorithm, signed_data, signature)
            .map_err(|_| PasskiError::new(format!("{} signature verification failed", name)))?;

        Ok(())
    }
}
