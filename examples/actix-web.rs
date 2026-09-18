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

//! # Passkeys Demo Server (Actix Web)
//!
//! Passkey registration and login with Passki on the Actix Web web framework, plus optional
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
//! ## Signal API
//! Responses carry a `signals` object for the page to hand to the browser's
//! `PublicKeyCredential.signal*` methods. Registration and sign-in send the account's passkey list
//! and name; a credential this server does not hold sends the unknown-credential signal instead.
//!
//! ## Running
//! ```sh
//! cargo run --example actix-web
//! ```
//! Then open http://localhost:3000 in your browser.

use actix_web::{App, HttpResponse, HttpServer, web};
use passki::{
    AllAcceptedCredentialsSignal, AttestationConveyancePreference, AuthenticationChallenge,
    AuthenticationCredential, AuthenticationExtensions, AuthenticationOptions, AuthenticationState,
    ClientData, CurrentUserDetailsSignal, Passki, PasskiError, PrfEval, PrfInput,
    RegistrationChallenge, RegistrationCredential, RegistrationExtensions, RegistrationOptions,
    RegistrationState, StoredPasskey, UnknownCredentialSignal,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// Error handling

#[derive(Debug)]
struct AppError(String);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl actix_web::ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::BadRequest().body(self.0.clone())
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

type AppResult<T> = Result<web::Json<T>, AppError>;

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

#[derive(Serialize, Default)]
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

    /// What the page should pass to the browser's `PublicKeyCredential.signal*` methods
    #[serde(skip_serializing_if = "Option::is_none")]
    signals: Option<Signals>,
}

/// Payloads the page hands to the browser's `PublicKeyCredential.signal*` methods, so the passkeys
/// the browser offers match what this server holds.
#[derive(Serialize, Default)]
struct Signals {
    /// A credential this server does not hold; the browser hides that passkey
    #[serde(skip_serializing_if = "Option::is_none")]
    unknown_credential: Option<UnknownCredentialSignal>,

    /// Every passkey the user still has; the browser hides whatever the list omits
    #[serde(skip_serializing_if = "Option::is_none")]
    all_accepted_credentials: Option<AllAcceptedCredentialsSignal>,

    /// The name the passkey picker should show for this account
    #[serde(skip_serializing_if = "Option::is_none")]
    current_user_details: Option<CurrentUserDetailsSignal>,
}

// Application state

struct AppState {
    passki: Passki,
    store: Store,
}

// Handlers

async fn index() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(include_str!("index.html"))
}

/// POST /register/start - Begin passkey registration
///
/// Returns the random challenge the authenticator will have to sign, plus the options the browser
/// needs to create a credential.
async fn register_start(
    state: web::Data<AppState>,
    req: web::Json<RegisterStartRequest>,
) -> AppResult<RegistrationChallenge> {
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
    extensions.prf = Some(PrfInput::default());

    let mut options = RegistrationOptions::default();
    options.attestation = if req.attestation {
        AttestationConveyancePreference::Direct
    } else {
        AttestationConveyancePreference::None
    };
    options.exclude_credentials = existing.as_deref();
    options.extensions = Some(extensions);

    let (challenge, reg_state) = state.passki.start_passkey_registration(
        &user_id,
        &req.username, // username, shown by the authenticator
        &req.username, // display name
        options,
    )?;

    // Keyed by the challenge, which is what the finish call brings back.
    state
        .store
        .pending_registrations
        .lock()
        .unwrap()
        .insert(challenge.challenge.clone(), reg_state);

    Ok(web::Json(challenge))
}

/// POST /register/finish - Complete passkey registration
///
/// Verifies the new credential, stores it, and reports whether the passkey supports
/// the PRF extension.
async fn register_finish(
    state: web::Data<AppState>,
    credential: web::Json<RegistrationCredential>,
) -> AppResult<ApiResponse> {
    let credential = credential.into_inner();

    // The challenge says which pending ceremony this belongs to.
    let client_data = ClientData::from_base64(&credential.response.client_data_json)?;

    let reg_state = state
        .store
        .pending_registrations
        .lock()
        .unwrap()
        .remove(&client_data.challenge)
        .ok_or(AppError("No pending registration".into()))?;

    let prf_supported = credential
        .client_extension_results
        .as_ref()
        .and_then(|ext| ext.prf.as_ref())
        .and_then(|prf| prf.enabled)
        .unwrap_or(false);

    // Checks origin, challenge and attestation, and extracts the public key.
    let passkey = state
        .passki
        .finish_passkey_registration(&credential, &reg_state)?;
    let resident_key = passkey.rk;
    let backup_eligible = passkey.be;
    let backed_up = passkey.bs;
    // All-zero unless attestation was both requested and supplied.
    let aaguid =
        (passkey.aaguid != [0u8; 16]).then(|| Uuid::from_bytes(passkey.aaguid).to_string());

    let user_id_bytes = Passki::base64_decode(&reg_state.user.id)?;
    let user_id = Uuid::from_slice(&user_id_bytes)?;

    // Store the passkey so it can be used to log in.
    let mut users = state.store.users.lock().unwrap();
    let user = users
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

    // The user's passkey list just changed, so tell the client what to keep and what to show.
    let signals = Signals {
        all_accepted_credentials: Some(
            state
                .passki
                .signal_all_accepted_credentials(user.id.as_bytes(), &user.passkeys),
        ),
        current_user_details: Some(state.passki.signal_current_user_details(
            user.id.as_bytes(),
            &user.username,
            &user.display_name,
        )),
        ..Default::default()
    };

    Ok(web::Json(ApiResponse {
        success: true,
        message: "Registration successful".into(),
        username: None,
        resident_key,
        backup_eligible: Some(backup_eligible),
        backed_up: Some(backed_up),
        aaguid,
        prf_supported: Some(prf_supported),
        prf_output: None,
        signals: Some(signals),
    }))
}

/// POST /auth/start - Begin passkey authentication
///
/// With a username the challenge names that user's credentials, so the browser offers only those;
/// without one it names none and the browser offers every passkey it holds for this site.
///
/// A `prf_salt` is passed on to the authenticator, which derives a key from it.
async fn auth_start(
    state: web::Data<AppState>,
    req: web::Json<AuthStartRequest>,
) -> AppResult<AuthenticationChallenge> {
    let passkeys = if let Some(ref username) = req.username {
        // Named user: offer only their credentials.
        let users = state.store.users.lock().unwrap();
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
        let mut prf = PrfInput::default();
        prf.eval = Some(PrfEval {
            first: salt,
            second: None,
        });
        extensions.prf = Some(prf);
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

    Ok(web::Json(challenge))
}

/// POST /auth/finish - Complete passkey authentication
///
/// Verifies the signature and, when a PRF salt was sent, returns the derived key hex-encoded
/// in `prf_output`.
async fn auth_finish(
    state: web::Data<AppState>,
    credential: web::Json<AuthenticationCredential>,
) -> AppResult<ApiResponse> {
    let credential = credential.into_inner();

    // The challenge says which pending ceremony this belongs to.
    let client_data = ClientData::from_base64(&credential.response.client_data_json)?;

    let auth_state = state
        .store
        .pending_authentications
        .lock()
        .unwrap()
        .remove(&client_data.challenge)
        .ok_or(AppError("No pending authentication".into()))?;

    let credential_id = Passki::base64_decode(&credential.raw_id)?;

    // The user handle gives a direct lookup; without it, scan every user for a matching credential
    // ID.
    let mut users = state.store.users.lock().unwrap();
    let found = match credential.response.user_handle.as_deref() {
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
    };

    // The browser offered a passkey this server does not hold. The signal tells it to hide that
    // passkey rather than offer it again; it names no user, so a signed-out caller may see it.
    let Some((username, passkey)) = found else {
        return Ok(web::Json(ApiResponse {
            success: false,
            message: "Unknown credential".into(),
            signals: Some(Signals {
                unknown_credential: Some(state.passki.signal_unknown_credential(&credential_id)),
                ..Default::default()
            }),
            ..Default::default()
        }));
    };

    // Checks origin, challenge, signature and counter.
    let result = state
        .passki
        .finish_passkey_authentication(&credential, &auth_state, passkey)?;

    // Must be stored: if the next login reports a counter that did not grow, the credential
    // has been cloned.
    passkey.counter = result.counter;

    // The passkey borrow is done, so the whole user is reachable again.
    let user = &users[&username];
    let signals = Signals {
        all_accepted_credentials: Some(
            state
                .passki
                .signal_all_accepted_credentials(user.id.as_bytes(), &user.passkeys),
        ),
        current_user_details: Some(state.passki.signal_current_user_details(
            user.id.as_bytes(),
            &user.username,
            &user.display_name,
        )),
        ..Default::default()
    };

    let prf_output = result
        .prf_first
        .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect());

    Ok(web::Json(ApiResponse {
        success: true,
        message: format!("Welcome back, {}!", username),
        username: Some(username),
        prf_supported: None,
        resident_key: None,
        backup_eligible: None,
        backed_up: None,
        aaguid: None,
        prf_output,
        signals: Some(signals),
    }))
}

// Main

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // The domain the passkeys are bound to, the origins allowed to use them, and the name
    // authenticators show in their prompt.
    let state = web::Data::new(AppState {
        passki: Passki::new("localhost", &["http://localhost:3000"], "Passkeys Demo"),
        store: Store::default(),
    });

    println!("Server starting on http://localhost:3000");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/", web::get().to(index))
            .route("/register/start", web::post().to(register_start))
            .route("/register/finish", web::post().to(register_finish))
            .route("/auth/start", web::post().to(auth_start))
            .route("/auth/finish", web::post().to(auth_finish))
    })
    .bind("0.0.0.0:3000")?
    .run()
    .await
}
