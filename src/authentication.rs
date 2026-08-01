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
/// Serialize this to JSON and hand it to `navigator.credentials.get()`.
#[derive(Serialize, Debug)]
pub struct AuthenticationChallenge {
    /// The challenge value (base64url-encoded).
    pub challenge: String,

    /// Timeout for the operation in milliseconds.
    pub timeout: u64,

    /// The relying party identifier.
    #[serde(rename = "rpId")]
    pub rp_id: String,

    /// The credentials the browser may use. Empty lets the user pick any
    /// discoverable credential, so no username is needed up front.
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<AllowCredential>,

    /// User verification requirement.
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationRequirement,

    /// WebAuthn extensions to request from the authenticator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensions>,
}

/// Server-side half of an authentication in progress.
///
/// Keep it in a session or cache between the two steps; without it the response
/// cannot be verified.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AuthenticationState {
    /// The challenge that was sent to the client.
    pub challenge: Vec<u8>,

    /// The credential IDs the client was offered. Empty means any discoverable
    /// credential was acceptable.
    pub allowed_credentials: Vec<Vec<u8>>,

    /// What was asked for when the ceremony started, re-checked against what the
    /// authenticator actually did.
    pub user_verification: UserVerificationRequirement,
}

/// What the client sends back after `navigator.credentials.get()`.
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

    /// The `user_id` from registration, base64url-encoded. Only returned for
    /// discoverable credentials, where it is how the server learns who is
    /// logging in.
    pub user_handle: Option<String>,

    /// Extension results from the client (e.g., PRF outputs).
    pub client_extension_results: Option<ClientExtensionResults>,

    /// Whether the client used a built-in or a separate authenticator. A
    /// credential registered as `Platform` reporting `CrossPlatform` here was
    /// used from another device. `None` when the client did not report.
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
}

/// Result of a successful authentication.
#[derive(Debug)]
#[non_exhaustive]
pub struct AuthenticationResult {
    /// The credential ID that was used for authentication.
    pub credential_id: Vec<u8>,

    /// The new signature counter. Store it on the passkey, or the next login has
    /// nothing to compare against.
    pub counter: u32,

    /// The decoded `user_id` from registration, if the authenticator returned
    /// one. Identifies the user when no username was given up front.
    pub user_handle: Option<Vec<u8>>,

    /// Decoded first PRF output, if the extension was requested and supported.
    pub prf_first: Option<Vec<u8>>,

    /// Decoded second PRF output, if a second input was requested and supported.
    pub prf_second: Option<Vec<u8>>,

    /// The decoded blob, if [`LargeBlobAuthenticationInput::Read`] was requested
    /// and the authenticator returned one.
    pub large_blob: Option<Vec<u8>>,

    /// Whether a [`LargeBlobAuthenticationInput::Write`] was stored. `None` when
    /// no write was requested or the client did not report.
    pub large_blob_written: Option<bool>,
}

/// Options for starting a passkey authentication ceremony.
///
/// The [`Default`] value uses a 60 second timeout and a `Preferred` user
/// verification requirement.
#[derive(Debug)]
#[non_exhaustive]
pub struct AuthenticationOptions {
    /// Timeout for the operation in milliseconds.
    pub timeout: u64,

    /// User verification requirement.
    pub user_verification: UserVerificationRequirement,

    /// WebAuthn extensions to request from the authenticator.
    pub extensions: Option<AuthenticationExtensions>,
}

impl Default for AuthenticationOptions {
    fn default() -> Self {
        Self {
            timeout: 60000,
            user_verification: UserVerificationRequirement::Preferred,
            extensions: None,
        }
    }
}

impl Passki {
    /// Starts a passkey authentication: generates a random challenge and returns
    /// it alongside the state needed to finish.
    ///
    /// # Arguments
    ///
    /// * `passkeys` - The passkeys the client may use; empty allows any
    ///   discoverable credential, for logins without a username
    /// * `options` - Ceremony options; see [`AuthenticationOptions`]
    ///
    /// # Returns
    ///
    /// The challenge to send to the client, and the state to keep on the server.
    pub fn start_passkey_authentication(
        &self,
        passkeys: &[StoredPasskey],
        options: AuthenticationOptions,
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let challenge = Self::generate_challenge();

        let challenge_response = AuthenticationChallenge {
            challenge: Self::base64_encode(&challenge),
            timeout: options.timeout,
            rp_id: self.rp_id.clone(),
            allow_credentials: passkeys
                .iter()
                .map(|pk| AllowCredential {
                    id: Self::base64_encode(&pk.credential_id),
                    type_: "public-key",
                    transports: pk.transports.clone(),
                })
                .collect(),
            user_verification: options.user_verification,
            extensions: options.extensions,
        };

        let state = AuthenticationState {
            challenge: challenge.clone(),
            allowed_credentials: passkeys.iter().map(|pk| pk.credential_id.clone()).collect(),
            user_verification: options.user_verification,
        };

        (challenge_response, state)
    }

    /// Completes a passkey authentication by verifying the signature and
    /// authenticator data the client returned.
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
        // An empty list means the caller accepted any discoverable credential.
        let credential_id = Self::base64_decode(&credential.credential_id)?;
        if !state.allowed_credentials.is_empty()
            && !state.allowed_credentials.contains(&credential_id)
        {
            return Err(PasskiError::CredentialNotAllowed);
        }

        let client_data_bytes = Self::base64_decode(&credential.client_data_json)?;
        let client_data = ClientData::from_bytes(&client_data_bytes)?;
        client_data.verify(ClientDataType::Get, &state.challenge, &self.rp_origins)?;

        let authenticator_data = Self::base64_decode(&credential.authenticator_data)?;
        if authenticator_data.len() < 37 {
            return Err(PasskiError::InvalidAuthenticatorData);
        }

        // Bytes 0-31 bind the assertion to our domain.
        let rp_id_hash = digest::digest(&SHA256, self.rp_id.as_bytes());
        if &authenticator_data[..32] != rp_id_hash.as_ref() {
            return Err(PasskiError::RpIdHashMismatch);
        }

        let flags = authenticator_data[32];
        if (flags & FLAG_UP) == 0 {
            return Err(PasskiError::UserNotPresent);
        }

        if (flags & FLAG_BS) != 0 && (flags & FLAG_BE) == 0 {
            return Err(PasskiError::InvalidBackupFlags);
        }

        if state.user_verification == UserVerificationRequirement::Required
            && (flags & FLAG_UV) == 0
        {
            return Err(PasskiError::UserVerificationRequired);
        }

        let counter = u32::from_be_bytes([
            authenticator_data[33],
            authenticator_data[34],
            authenticator_data[35],
            authenticator_data[36],
        ]);

        // Two zeros mean the authenticator does not count at all, which the spec
        // allows and synced passkeys (e.g. Google Password Manager) do.
        if (counter != 0 || stored_passkey.counter != 0) && counter <= stored_passkey.counter {
            return Err(PasskiError::CounterRegression);
        }

        let signature = Self::base64_decode(&credential.signature)?;
        let client_data_hash = digest::digest(&SHA256, &client_data_bytes);

        // The authenticator signed authData || SHA-256(clientDataJSON).
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

        let large_blob_result = credential
            .client_extension_results
            .as_ref()
            .and_then(|ext| ext.large_blob.as_ref());

        let large_blob = large_blob_result
            .and_then(|lb| lb.blob.as_deref())
            .map(Self::base64_decode)
            .transpose()?;
        let large_blob_written = large_blob_result.and_then(|lb| lb.written);

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
            large_blob,
            large_blob_written,
        })
    }

    /// Verifies a signature with the verifier for the credential's algorithm.
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
                cose_key_bytes,
                signed_data,
                signature,
            ),
            ALG_ES384 => Self::verify_ecdsa(
                &ECDSA_P384_SHA384_ASN1,
                CRV_P384,
                cose_key_bytes,
                signed_data,
                signature,
            ),
            ALG_RS256 => Self::verify_rsa(
                &RSA_PKCS1_2048_8192_SHA256,
                cose_key_bytes,
                signed_data,
                signature,
            ),
            ALG_RS384 => Self::verify_rsa(
                &RSA_PKCS1_2048_8192_SHA384,
                cose_key_bytes,
                signed_data,
                signature,
            ),
            _ => Err(PasskiError::UnsupportedAlgorithm(algorithm)),
        }
    }

    /// Parses a COSE key, the CBOR map WebAuthn encodes public keys as, into its
    /// entries. Its fields are keyed by small integers rather than by name.
    pub(crate) fn cose_parse(
        cose_key_bytes: &[u8],
    ) -> Result<Vec<(ciborium::Value, ciborium::Value)>> {
        let cose_key_value: ciborium::Value = ciborium::from_reader(cose_key_bytes)?;

        match cose_key_value {
            ciborium::Value::Map(map) => Ok(map),
            _ => Err(PasskiError::InvalidCoseKey("not a map".to_string())),
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
            .ok_or_else(|| PasskiError::InvalidCoseKey(format!("Missing {}", name)))
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
            .ok_or_else(|| PasskiError::InvalidCoseKey(format!("Missing {}", name)))?;

        if value != expected {
            return Err(PasskiError::InvalidCoseKey(format!(
                "Invalid {}: expected {}, got {}",
                name, expected, value
            )));
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
            return Err(PasskiError::InvalidCoseKey(
                "Invalid Ed25519 public key length".to_string(),
            ));
        }

        let public_key = UnparsedPublicKey::new(&ED25519, x);
        public_key
            .verify(signed_data, signature)
            .map_err(|_| PasskiError::SignatureVerificationFailed)?;

        Ok(())
    }

    /// Verifies an ECDSA signature (ES256 or ES384).
    pub(crate) fn verify_ecdsa(
        algorithm: &'static EcdsaVerificationAlgorithm,
        crv: i64,
        cose_key_bytes: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let cose_map = Self::cose_parse(cose_key_bytes)?;
        Self::cose_expect(&cose_map, 1, "kty", KTY_EC2)?;
        Self::cose_expect(&cose_map, -1, "crv", crv)?;
        let x = Self::cose_field(&cose_map, -2, "x coordinate")?;
        let y = Self::cose_field(&cose_map, -3, "y coordinate")?;

        // Uncompressed point encoding: 0x04 || x || y
        let mut public_key_bytes = vec![0x04];
        public_key_bytes.extend_from_slice(x);
        public_key_bytes.extend_from_slice(y);

        // signed_data goes in unhashed; the algorithm hashes it itself.
        let public_key = UnparsedPublicKey::new(algorithm, &public_key_bytes);
        public_key
            .verify(signed_data, signature)
            .map_err(|_| PasskiError::SignatureVerificationFailed)?;

        Ok(())
    }

    /// Verifies an RSA PKCS#1 v1.5 signature (RS256 or RS384).
    pub(crate) fn verify_rsa(
        algorithm: &'static RsaParameters,
        cose_key_bytes: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let cose_map = Self::cose_parse(cose_key_bytes)?;
        Self::cose_expect(&cose_map, 1, "kty", KTY_RSA)?;
        let n = Self::cose_field(&cose_map, -1, "n (modulus)")?;
        let e = Self::cose_field(&cose_map, -2, "e (exponent)")?;

        // signed_data goes in unhashed; the algorithm hashes it itself.
        let public_key = RsaPublicKeyComponents { n, e };
        public_key
            .verify(algorithm, signed_data, signature)
            .map_err(|_| PasskiError::SignatureVerificationFailed)?;

        Ok(())
    }
}
