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

//! # Passkeys Demo Server (Warp)
//!
//! Passkey registration and login with Passki on the Warp web framework, plus optional
//! PRF key derivation.
//!
//! ## Registration
//! 1. Client posts a username to `/register/start`
//! 2. Server returns a challenge and the options for the browser
//! 3. Browser calls `navigator.credentials.create()` and prompts the user
//! 4. Client posts the new credential to `/register/finish`
//! 5. Server verifies it and stores the passkey
//!
//! ## Authentication
//! **With a username**: the challenge names that user's credentials, so the browser offers only
//! those.
//!
//! **Without one**: the challenge names none, the browser offers every passkey it holds for this
//! site, and the server works out who is logging in from the user handle the authenticator returns.
//!
//! ## PRF key derivation (optional)
//! When the client sends a `prf_salt` with its authentication request, the server passes
//! it to the authenticator as `extensions.prf.eval.first`. The authenticator derives 32 bytes from
//! it, returned hex-encoded in `prf_output`. The same passkey and salt always yield the same bytes,
//! which makes them usable as an encryption key.
//!
//! ## Running
//! ```sh
//! cargo run --example warp
//! ```
//! Then open http://localhost:3000 in your browser.

use passki::{
    AttestationConveyancePreference, AuthenticationCredential, AuthenticationExtensions,
    AuthenticationOptions, AuthenticationState, AuthenticatorAttachment, AuthenticatorTransport,
    ClientData, ClientExtensionResults, Passki, PrfEval, PrfInput, RegistrationCredential,
    RegistrationExtensions, RegistrationOptions, RegistrationState, StoredPasskey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use warp::{Filter, Reply, http::StatusCode, reject::Reject, reply};

// Error handling

#[derive(Debug)]
struct AppError(String);

impl Reject for AppError {}

/// Converts rejections into HTTP 400 responses with the error message.
async fn handle_rejection(err: warp::Rejection) -> Result<impl Reply, Infallible> {
    let message = if let Some(e) = err.find::<AppError>() {
        e.0.clone()
    } else {
        "Internal server error".to_string()
    };

    Ok(reply::with_status(message, StatusCode::BAD_REQUEST))
}

// Storage

/// In-memory storage for users and ceremonies in progress.
///
/// A real server would use a database for the users and an expiring cache for the pending states.
#[derive(Clone, Default)]
struct Store {
    /// Keyed by username.
    users: Arc<Mutex<HashMap<String, User>>>,

    /// Registrations waiting for their finish call, keyed by challenge.
    pending_registrations: Arc<Mutex<HashMap<String, RegistrationState>>>,

    /// Authentications waiting for their finish call, keyed by challenge.
    pending_authentications: Arc<Mutex<HashMap<String, AuthenticationState>>>,
}

/// A registered user and their passkeys.
#[derive(Clone)]
#[allow(unused)]
struct User {
    /// Unique user identifier.
    id: Uuid,
    /// Username or account identifier.
    username: String,
    /// Human-readable display name.
    display_name: String,
    /// One user can register several: a phone, a laptop, a security key.
    passkeys: Vec<StoredPasskey>,
    /// Whether any of their passkeys reported PRF support.
    prf_supported: bool,
}

// Request/Response types

#[derive(Deserialize)]
struct RegisterStartRequest {
    username: String,
    /// Ask for an attestation statement, so the AAGUID names a real authenticator model instead
    /// of staying all zeros
    #[serde(default)]
    attestation: bool,
}

/// What the client posts back after `navigator.credentials.create()`.
#[derive(Deserialize)]
struct RegisterFinishRequest {
    /// Base64url-encoded credential ID from the authenticator
    credential_id: String,
    /// Base64url-encoded attestation object, which carries the public key
    public_key: String,
    /// Base64url-encoded client data JSON
    client_data_json: String,
    /// Extension results from the browser (e.g., PRF support flag)
    client_extension_results: Option<ClientExtensionResults>,
    /// Whether the browser used a built-in or a separate authenticator
    authenticator_attachment: Option<AuthenticatorAttachment>,
    /// What `getTransports()` reported, stored so later ceremonies can tell the browser where this
    /// credential lives
    #[serde(default)]
    transports: Vec<AuthenticatorTransport>,
}

/// Both fields are optional.
#[derive(Deserialize, Default)]
struct AuthStartRequest {
    /// When given, the server names the allowed credentials; when omitted, the browser offers every
    /// passkey it holds for this site
    #[serde(default)]
    username: Option<String>,
    /// Base64url-encoded PRF input. When present, the server asks the authenticator to derive
    /// a key from it.
    #[serde(default)]
    prf_salt: Option<String>,
}

/// What the client posts back after `navigator.credentials.get()`.
#[derive(Deserialize)]
struct AuthFinishRequest {
    /// Base64url-encoded ID of the passkey that was used
    credential_id: String,
    /// Base64url-encoded authenticator data (contains flags and counter)
    authenticator_data: String,
    /// Base64url-encoded client data JSON
    client_data_json: String,
    /// Base64url-encoded signature over authenticator_data + hash(client_data_json)
    signature: String,
    /// Base64url-encoded user handle, returned only for discoverable credentials
    user_handle: Option<String>,
    /// Extension results from the browser (e.g., PRF outputs)
    client_extension_results: Option<ClientExtensionResults>,
    /// Whether the browser used a built-in or a separate authenticator
    authenticator_attachment: Option<AuthenticatorAttachment>,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
    /// Who the server decided was logging in, when no username was given
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    /// Registration only: whether a resident key was created
    #[serde(skip_serializing_if = "Option::is_none")]
    resident_key: Option<bool>,
    /// Registration only: whether the credential is eligible for backup (BE flag)
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_eligible: Option<bool>,
    /// Registration only: whether the credential is currently backed up (BS flag)
    #[serde(skip_serializing_if = "Option::is_none")]
    backed_up: Option<bool>,
    /// Registration only: the authenticator model, absent when it stayed anonymous
    #[serde(skip_serializing_if = "Option::is_none")]
    aaguid: Option<String>,
    /// Registration only: whether this passkey supports PRF
    #[serde(skip_serializing_if = "Option::is_none")]
    prf_supported: Option<bool>,
    /// Authentication only: hex-encoded 32-byte derived key, when prf_salt was provided
    #[serde(skip_serializing_if = "Option::is_none")]
    prf_output: Option<String>,
}

// Application state

#[derive(Clone)]
struct AppState {
    passki: Arc<Passki>,
    store: Store,
}

// Filters

/// Extracts AppState for injection into handlers.
fn with_state(state: AppState) -> impl Filter<Extract = (AppState,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

// Handlers

async fn index() -> Result<impl Reply, warp::Rejection> {
    Ok(reply::html(include_str!("index.html")))
}

/// POST /register/start - Begin passkey registration
///
/// Returns the random challenge the authenticator will have to sign, plus the options the browser
/// needs to create a credential.
async fn register_start(
    state: AppState,
    req: RegisterStartRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Random and opaque rather than the username, so it cannot be used to track the user across
    // sites.
    let user_id = Uuid::new_v4().as_bytes().to_vec();

    // Passkeys the user already has, which the authenticator must refuse to register a second time.
    let existing = state
        .store
        .users
        .lock()
        .unwrap()
        .get(&req.username)
        .map(|u| u.passkeys.clone());

    // credProps reports whether a discoverable credential was created. The eval-less PRF input only
    // asks whether PRF is supported at all.
    let mut extensions = RegistrationExtensions::default();
    extensions.cred_props = Some(true);
    extensions.prf = Some(PrfInput { eval: None });

    let mut options = RegistrationOptions::default();
    options.attestation = if req.attestation {
        AttestationConveyancePreference::Direct
    } else {
        AttestationConveyancePreference::None
    };
    options.exclude_credentials = existing.as_deref();
    options.extensions = Some(extensions);

    let (challenge, reg_state) = state
        .passki
        .start_passkey_registration(
            &user_id,
            &req.username, // username, shown by the authenticator
            &req.username, // display name
            options,
        )
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    // Keyed by the challenge, which is what the finish call brings back.
    state
        .store
        .pending_registrations
        .lock()
        .unwrap()
        .insert(challenge.challenge.clone(), reg_state);

    Ok(reply::json(&challenge))
}

/// POST /register/finish - Complete passkey registration
///
/// Verifies the new credential, stores it, and reports whether the passkey supports
/// the PRF extension.
async fn register_finish(
    state: AppState,
    req: RegisterFinishRequest,
) -> Result<impl Reply, warp::Rejection> {
    // The challenge says which pending ceremony this belongs to.
    let client_data = ClientData::from_base64(&req.client_data_json)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    let reg_state = state
        .store
        .pending_registrations
        .lock()
        .unwrap()
        .remove(&client_data.challenge)
        .ok_or_else(|| warp::reject::custom(AppError("No pending registration".into())))?;

    let prf_supported = req
        .client_extension_results
        .as_ref()
        .and_then(|ext| ext.prf.as_ref())
        .and_then(|prf| prf.enabled)
        .unwrap_or(false);

    let credential = RegistrationCredential {
        credential_id: req.credential_id,
        public_key: req.public_key,
        client_data_json: req.client_data_json,
        client_extension_results: req.client_extension_results,
        authenticator_attachment: req.authenticator_attachment,
        transports: req.transports,
    };

    // Checks origin, challenge and attestation, and extracts the public key.
    let passkey = state
        .passki
        .finish_passkey_registration(&credential, &reg_state)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;
    let resident_key = passkey.rk;
    let backup_eligible = passkey.be;
    let backed_up = passkey.bs;
    // All-zero unless attestation was both requested and supplied.
    let aaguid =
        (passkey.aaguid != [0u8; 16]).then(|| Uuid::from_bytes(passkey.aaguid).to_string());

    let user_id_bytes = Passki::base64_decode(&reg_state.user.id)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;
    let user_id = Uuid::from_slice(&user_id_bytes)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    // Store the passkey so it can be used to log in.
    let mut users = state.store.users.lock().unwrap();
    users
        .entry(reg_state.user.name.clone())
        .and_modify(|user| {
            user.passkeys.push(passkey.clone());
            user.prf_supported |= prf_supported;
        })
        .or_insert(User {
            id: user_id,
            username: reg_state.user.name,
            display_name: reg_state.user.display_name,
            passkeys: vec![passkey],
            prf_supported,
        });

    Ok(reply::json(&ApiResponse {
        success: true,
        message: "Registration successful".into(),
        username: None,
        resident_key,
        backup_eligible: Some(backup_eligible),
        backed_up: Some(backed_up),
        aaguid,
        prf_supported: Some(prf_supported),
        prf_output: None,
    }))
}

/// POST /auth/start - Begin passkey authentication
///
/// With a username the challenge names that user's credentials, so the browser offers only those;
/// without one it names none and the browser offers every passkey it holds for this site.
///
/// A `prf_salt` is passed on to the authenticator, which derives a key from it.
async fn auth_start(state: AppState, req: AuthStartRequest) -> Result<impl Reply, warp::Rejection> {
    let passkeys = if let Some(ref username) = req.username {
        // Named user: offer only their credentials.
        let users = state.store.users.lock().unwrap();
        let user = users
            .get(username)
            .ok_or_else(|| warp::reject::custom(AppError("User not found".into())))?;
        user.passkeys.clone()
    } else {
        // No username: an empty list lets the browser offer any passkey.
        vec![]
    };

    let extensions = req.prf_salt.map(|salt| {
        let mut extensions = AuthenticationExtensions::default();
        extensions.prf = Some(PrfInput {
            eval: Some(PrfEval {
                first: salt,
                second: None,
            }),
        });
        extensions
    });

    let mut options = AuthenticationOptions::default();
    options.extensions = extensions;

    let (challenge, auth_state) = state
        .passki
        .start_passkey_authentication(&passkeys, options);

    // Keyed by the challenge, which is what the finish call brings back.
    state
        .store
        .pending_authentications
        .lock()
        .unwrap()
        .insert(challenge.challenge.clone(), auth_state);

    Ok(reply::json(&challenge))
}

/// POST /auth/finish - Complete passkey authentication
///
/// Verifies the signature and, when a PRF salt was sent, returns the derived key hex-encoded
/// in `prf_output`.
async fn auth_finish(
    state: AppState,
    req: AuthFinishRequest,
) -> Result<impl Reply, warp::Rejection> {
    // The challenge says which pending ceremony this belongs to.
    let client_data = ClientData::from_base64(&req.client_data_json)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    let auth_state = state
        .store
        .pending_authentications
        .lock()
        .unwrap()
        .remove(&client_data.challenge)
        .ok_or_else(|| warp::reject::custom(AppError("No pending authentication".into())))?;

    let credential_id = Passki::base64_decode(&req.credential_id)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    // The user handle gives a direct lookup; without it, scan every user for a matching credential
    // ID.
    let mut users = state.store.users.lock().unwrap();
    let (username, passkey) = match req.user_handle.as_deref() {
        Some(handle) => {
            let handle_bytes = Passki::base64_decode(handle)
                .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;
            let user_id = Uuid::from_slice(&handle_bytes)
                .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;
            users
                .iter_mut()
                .find(|(_, user)| user.id == user_id)
                .and_then(|(name, user)| {
                    user.passkeys
                        .iter_mut()
                        .find(|pk| pk.credential_id == credential_id)
                        .map(|pk| (name.clone(), pk))
                })
        }
        None => users.iter_mut().find_map(|(name, user)| {
            user.passkeys
                .iter_mut()
                .find(|pk| pk.credential_id == credential_id)
                .map(|pk| (name.clone(), pk))
        }),
    }
    .ok_or_else(|| warp::reject::custom(AppError("Unknown credential".into())))?;

    let credential = AuthenticationCredential {
        credential_id: req.credential_id,
        authenticator_data: req.authenticator_data,
        client_data_json: req.client_data_json,
        signature: req.signature,
        user_handle: req.user_handle,
        client_extension_results: req.client_extension_results,
        authenticator_attachment: req.authenticator_attachment,
    };

    // Checks origin, challenge, signature and counter.
    let result = state
        .passki
        .finish_passkey_authentication(&credential, &auth_state, passkey)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    // Must be stored: if the next login reports a counter that did not grow, the credential
    // has been cloned.
    passkey.counter = result.counter;

    let prf_output = result
        .prf_first
        .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect());

    Ok(reply::json(&ApiResponse {
        success: true,
        message: format!("Welcome back, {}!", username),
        username: Some(username),
        prf_supported: None,
        resident_key: None,
        backup_eligible: None,
        backed_up: None,
        aaguid: None,
        prf_output,
    }))
}

// Main

#[tokio::main]
async fn main() {
    // The domain the passkeys are bound to, the origins allowed to use them, and the name
    // authenticators show in their prompt.
    let state = AppState {
        passki: Arc::new(Passki::new(
            "localhost",
            &["http://localhost:3000"],
            "Passkeys Demo",
        )),
        store: Store::default(),
    };

    let index = warp::path::end().and(warp::get()).and_then(index);

    let register_start = warp::path!("register" / "start")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::body::json())
        .and_then(register_start);

    let register_finish = warp::path!("register" / "finish")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::body::json())
        .and_then(register_finish);

    let auth_start = warp::path!("auth" / "start")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::body::json())
        .and_then(auth_start);

    let auth_finish = warp::path!("auth" / "finish")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::body::json())
        .and_then(auth_finish);

    let routes = index
        .or(register_start)
        .or(register_finish)
        .or(auth_start)
        .or(auth_finish)
        .recover(handle_rejection);

    println!("Server starting on http://localhost:3000");
    warp::serve(routes).run(([0, 0, 0, 0], 3000)).await;
}
