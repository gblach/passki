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

//! # Passkeys Demo Server (Rocket)
//!
//! Passkey registration and login with Passki on the Rocket web framework, plus
//! optional PRF key derivation.
//!
//! ## Registration
//! 1. Client posts a username to `/register/start`
//! 2. Server returns a challenge and the options for the browser
//! 3. Browser calls `navigator.credentials.create()` and prompts the user
//! 4. Client posts the new credential to `/register/finish`
//! 5. Server verifies it and stores the passkey
//!
//! ## Authentication
//! **With a username**: the challenge names that user's credentials, so the
//! browser offers only those.
//!
//! **Without one**: the challenge names none, the browser offers every passkey
//! it holds for this site, and the server works out who is logging in from the
//! user handle the authenticator returns.
//!
//! ## PRF key derivation (optional)
//! When the client sends a `prf_salt` with its authentication request, the
//! server passes it to the authenticator as `extensions.prf.eval.first`. The
//! authenticator derives 32 bytes from it, returned hex-encoded in
//! `prf_output`. The same passkey and salt always yield the same bytes, which
//! makes them usable as an encryption key.
//!
//! ## Running
//! ```sh
//! cargo run --example rocket
//! ```
//! Then open http://localhost:3000 in your browser.

#[macro_use]
extern crate rocket;

use passki::{
    AttestationConveyancePreference, AuthenticationChallenge, AuthenticationCredential,
    AuthenticationExtensions, AuthenticationOptions, AuthenticationState, AuthenticatorAttachment,
    AuthenticatorTransport, ClientData, ClientExtensionResults, Passki, PasskiError, PrfEval,
    PrfInput, RegistrationChallenge, RegistrationCredential, RegistrationExtensions,
    RegistrationOptions, RegistrationState, StoredPasskey,
};
use rocket::http::Status;
use rocket::response::content::RawHtml;
use rocket::serde::json::Json;
use rocket::{Build, Rocket, State};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

// Error handling

struct AppError(String);

impl<'r> rocket::response::Responder<'r, 'static> for AppError {
    fn respond_to(self, _req: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        rocket::Response::build()
            .status(Status::BadRequest)
            .sized_body(self.0.len(), std::io::Cursor::new(self.0))
            .ok()
    }
}

impl From<PasskiError> for AppError {
    fn from(err: PasskiError) -> Self {
        AppError(err.to_string())
    }
}

impl From<uuid::Error> for AppError {
    fn from(err: uuid::Error) -> Self {
        AppError(err.to_string())
    }
}

type AppResult<T> = Result<Json<T>, AppError>;

// Storage

/// In-memory storage for users and ceremonies in progress.
///
/// A real server would use a database for the users and an expiring cache for
/// the pending states.
#[derive(Default)]
struct Store {
    /// Keyed by username.
    users: Mutex<HashMap<String, User>>,

    /// Registrations waiting for their finish call, keyed by challenge.
    pending_registrations: Mutex<HashMap<String, RegistrationState>>,

    /// Authentications waiting for their finish call, keyed by challenge.
    pending_authentications: Mutex<HashMap<String, AuthenticationState>>,
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
    /// Ask for an attestation statement, so the AAGUID names a real
    /// authenticator model instead of staying all zeros
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
    /// What `getTransports()` reported, stored so later ceremonies can tell
    /// the browser where this credential lives
    #[serde(default)]
    transports: Vec<AuthenticatorTransport>,
}

/// Both fields are optional.
#[derive(Deserialize, Default)]
struct AuthStartRequest {
    /// When given, the server names the allowed credentials; when omitted, the
    /// browser offers every passkey it holds for this site
    #[serde(default)]
    username: Option<String>,
    /// Base64url-encoded PRF input. When present, the server asks the
    /// authenticator to derive a key from it.
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

// Handlers

#[get("/")]
fn index() -> RawHtml<&'static str> {
    RawHtml(include_str!("index.html"))
}

/// POST /register/start - Begin passkey registration
///
/// Returns the random challenge the authenticator will have to sign, plus the
/// options the browser needs to create a credential.
#[post("/register/start", data = "<req>")]
fn register_start(
    passki: &State<Passki>,
    store: &State<Store>,
    req: Json<RegisterStartRequest>,
) -> AppResult<RegistrationChallenge> {
    // Random and opaque rather than the username, so it cannot be used to
    // track the user across sites.
    let user_id = Uuid::new_v4().as_bytes().to_vec();

    // Passkeys the user already has, which the authenticator must refuse to
    // register a second time.
    let existing = store
        .users
        .lock()
        .unwrap()
        .get(&req.username)
        .map(|u| u.passkeys.clone());

    // credProps reports whether a discoverable credential was created. The
    // eval-less PRF input only asks whether PRF is supported at all.
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

    let (challenge, reg_state) = passki.start_passkey_registration(
        &user_id,
        &req.username, // username, shown by the authenticator
        &req.username, // display name
        options,
    )?;

    // Keyed by the challenge, which is what the finish call brings back.
    store
        .pending_registrations
        .lock()
        .unwrap()
        .insert(challenge.challenge.clone(), reg_state);

    Ok(Json(challenge))
}

/// POST /register/finish - Complete passkey registration
///
/// Verifies the new credential, stores it, and reports whether the passkey
/// supports the PRF extension.
#[post("/register/finish", data = "<req>")]
fn register_finish(
    passki: &State<Passki>,
    store: &State<Store>,
    req: Json<RegisterFinishRequest>,
) -> AppResult<ApiResponse> {
    let req = req.into_inner();

    // The challenge says which pending ceremony this belongs to.
    let client_data = ClientData::from_base64(&req.client_data_json)?;

    let reg_state = store
        .pending_registrations
        .lock()
        .unwrap()
        .remove(&client_data.challenge)
        .ok_or(AppError("No pending registration".into()))?;

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
    let passkey = passki.finish_passkey_registration(&credential, &reg_state)?;
    let resident_key = passkey.rk;
    let backup_eligible = passkey.be;
    let backed_up = passkey.bs;
    // All-zero unless attestation was both requested and supplied.
    let aaguid =
        (passkey.aaguid != [0u8; 16]).then(|| Uuid::from_bytes(passkey.aaguid).to_string());

    let user_id_bytes = Passki::base64_decode(&reg_state.user.id)?;
    let user_id = Uuid::from_slice(&user_id_bytes)?;

    // Store the passkey so it can be used to log in.
    let mut users = store.users.lock().unwrap();
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

    Ok(Json(ApiResponse {
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
/// With a username the challenge names that user's credentials, so the browser
/// offers only those; without one it names none and the browser offers every
/// passkey it holds for this site.
///
/// A `prf_salt` is passed on to the authenticator, which derives a key from it.
#[post("/auth/start", data = "<req>")]
fn auth_start(
    passki: &State<Passki>,
    store: &State<Store>,
    req: Json<AuthStartRequest>,
) -> AppResult<AuthenticationChallenge> {
    let passkeys = if let Some(ref username) = req.username {
        // Named user: offer only their credentials.
        let users = store.users.lock().unwrap();
        let user = users
            .get(username)
            .ok_or(AppError("User not found".into()))?;
        user.passkeys.clone()
    } else {
        // No username: an empty list lets the browser offer any passkey.
        vec![]
    };

    let extensions = req.prf_salt.clone().map(|salt| {
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

    let (challenge, auth_state) = passki.start_passkey_authentication(&passkeys, options);

    // Keyed by the challenge, which is what the finish call brings back.
    store
        .pending_authentications
        .lock()
        .unwrap()
        .insert(challenge.challenge.clone(), auth_state);

    Ok(Json(challenge))
}

/// POST /auth/finish - Complete passkey authentication
///
/// Verifies the signature and, when a PRF salt was sent, returns the derived
/// key hex-encoded in `prf_output`.
#[post("/auth/finish", data = "<req>")]
fn auth_finish(
    passki: &State<Passki>,
    store: &State<Store>,
    req: Json<AuthFinishRequest>,
) -> AppResult<ApiResponse> {
    let req = req.into_inner();

    // The challenge says which pending ceremony this belongs to.
    let client_data = ClientData::from_base64(&req.client_data_json)?;

    let auth_state = store
        .pending_authentications
        .lock()
        .unwrap()
        .remove(&client_data.challenge)
        .ok_or(AppError("No pending authentication".into()))?;

    let credential_id = Passki::base64_decode(&req.credential_id)?;

    // The user handle gives a direct lookup; without it, scan every user for a
    // matching credential ID.
    let mut users = store.users.lock().unwrap();
    let (username, passkey) = match req.user_handle.as_deref() {
        Some(handle) => {
            let user_id = Uuid::from_slice(&Passki::base64_decode(handle)?)?;
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
    .ok_or(AppError("Unknown credential".into()))?;

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
    let result = passki.finish_passkey_authentication(&credential, &auth_state, passkey)?;

    // Must be stored: if the next login reports a counter that did not grow,
    // the credential has been cloned.
    passkey.counter = result.counter;

    let prf_output = result
        .prf_first
        .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect());

    Ok(Json(ApiResponse {
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

#[launch]
fn rocket() -> Rocket<Build> {
    // The domain the passkeys are bound to, the origins allowed to use them,
    // and the name authenticators show in their prompt.
    let passki = Passki::new("localhost", &["http://localhost:3000"], "Passkeys Demo");

    let figment = rocket::Config::figment().merge(("port", 3000));

    rocket::custom(figment)
        .manage(passki)
        .manage(Store::default())
        .mount(
            "/",
            routes![
                index,
                register_start,
                register_finish,
                auth_start,
                auth_finish,
            ],
        )
}
