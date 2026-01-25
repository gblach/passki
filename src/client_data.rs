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

//! Client data parsing and verification for WebAuthn operations.

use std::fmt;
use std::str::FromStr;

use crate::types::{PasskiError, Result};

/// The type of WebAuthn operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDataType {
    /// Registration operation ("webauthn.create").
    Create,
    /// Authentication operation ("webauthn.get").
    Get,
}

impl ClientDataType {
    /// Returns the string representation used in the client data JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientDataType::Create => "webauthn.create",
            ClientDataType::Get => "webauthn.get",
        }
    }
}

impl FromStr for ClientDataType {
    type Err = PasskiError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "webauthn.create" => Ok(ClientDataType::Create),
            "webauthn.get" => Ok(ClientDataType::Get),
            _ => Err(PasskiError::new(format!("Invalid type in client data: {}", s))),
        }
    }
}

impl fmt::Display for ClientDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Parsed client data from WebAuthn operations.
///
/// This structure contains the parsed fields from the client data JSON
/// that is sent by the browser during registration and authentication.
#[derive(Debug)]
pub struct ClientData {
    /// The type of operation (Create for registration, Get for authentication).
    pub type_: ClientDataType,

    /// The challenge that was signed (base64url-encoded).
    pub challenge: String,

    /// The origin of the requesting page.
    pub origin: String,

    /// Whether the request came from a cross-origin iframe.
    pub cross_origin: bool,
}

impl ClientData {
    /// Parses client data from raw JSON bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw JSON bytes
    ///
    /// # Returns
    ///
    /// A `ClientData` struct containing the parsed fields.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The JSON parsing fails
    /// * Required fields are missing
    pub fn from_bytes(bytes: &[u8]) -> Result<ClientData> {
        let json: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| PasskiError::new(format!("Invalid client data JSON: {}", e)))?;

        let type_str = json["type"]
            .as_str()
            .ok_or_else(|| PasskiError::new("Missing type in client data"))?;

        let type_ = type_str.parse::<ClientDataType>()?;

        let challenge = json["challenge"]
            .as_str()
            .ok_or_else(|| PasskiError::new("Missing challenge in client data"))?
            .to_string();

        let origin = json["origin"]
            .as_str()
            .ok_or_else(|| PasskiError::new("Missing origin in client data"))?
            .to_string();

        let cross_origin = json["crossOrigin"].as_bool().unwrap_or(false);

        Ok(ClientData {
            type_,
            challenge,
            origin,
            cross_origin,
        })
    }

    /// Parses a base64url-encoded client data JSON string.
    ///
    /// This function decodes and parses the client data JSON that is returned
    /// by the browser during WebAuthn operations. The challenge field can be
    /// used to look up pending registration or authentication state.
    ///
    /// # Arguments
    ///
    /// * `client_data_json` - The base64url-encoded client data JSON string
    ///
    /// # Returns
    ///
    /// A `ClientData` struct containing the parsed fields.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The base64url decoding fails
    /// * The JSON parsing fails
    /// * Required fields are missing
    ///
    /// # Example
    ///
    /// ```
    /// # use passki::ClientData;
    /// # /*
    /// let client_data = ClientData::from_base64(&credential.client_data_json)?;
    /// let state = pending_states.remove(&client_data.challenge)
    ///     .ok_or("No pending state")?;
    /// # */
    /// ```
    #[inline] pub fn from_base64(client_data_json: &str) -> Result<ClientData> {
        let bytes = crate::Passki::base64_decode(client_data_json)?;
        Self::from_bytes(&bytes)
    }

    #[allow(rustdoc::bare_urls)]
    /// Verifies the client data against expected values.
    ///
    /// Checks that the type, challenge, and origin match the expected values.
    ///
    /// # Arguments
    ///
    /// * `expected_type` - The expected type (Create or Get)
    /// * `expected_challenge` - The expected challenge bytes
    /// * `expected_origin` - The expected origin (e.g., "https://example.com")
    ///
    /// # Errors
    ///
    /// Returns an error if any of the values don't match.
    pub fn verify(
        &self,
        expected_type: ClientDataType,
        expected_challenge: &[u8],
        expected_origin: &str,
    ) -> Result<()> {
        // Verify type
        if self.type_ != expected_type {
            return Err(Box::new(PasskiError::new(format!(
                "Invalid type: expected {}, got {}",
                expected_type, self.type_
            ))));
        }

        // Verify challenge
        let challenge = crate::Passki::base64_decode(&self.challenge)?;
        if challenge != expected_challenge {
            return Err(Box::new(PasskiError::new("Challenge mismatch")));
        }

        // Verify origin
        if self.origin != expected_origin {
            return Err(Box::new(PasskiError::new(format!(
                "Invalid origin: expected {}, got {}",
                expected_origin, self.origin
            ))));
        }

        Ok(())
    }
}
