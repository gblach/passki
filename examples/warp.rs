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
//! ## Sessions
//! A successful sign-in, or a registration that creates a new account, sets a session cookie.
//! `GET /session` is a protected route that answers only with that cookie, and `POST /logout`
//! ends the session. Adding a passkey to an existing account needs a session for that account,
//! otherwise anyone could add their own passkey to someone else's account.
//!
//! ## Signal API
//! Responses carry a `signals` object for the page to hand to the browser's
//! `PublicKeyCredential.signal*` methods. Registration and sign-in send the account's passkey list
//! and name; a credential this server does not hold sends the unknown-credential signal instead.
//!
//! ## Running
//! ```sh
//! cargo run --example warp
//! ```
//! Then open http://localhost:3000 in your browser.

use passki::{
    AllAcceptedCredentialsSignal, AttestationConveyancePreference, AuthenticationCredential,
    AuthenticationExtensions, AuthenticationOptions, AuthenticationState, ClientData,
    CurrentUserDetailsSignal, Passki, PrfAuthenticationInput, PrfEval, PrfRegistrationInput,
    RegistrationCredential, RegistrationExtensions, RegistrationOptions, RegistrationState,
    StoredPasskey, UnknownCredentialSignal,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use warp::{
    Filter, Reply,
    http::{StatusCode, header::SET_COOKIE},
    reject::Reject,
    reply,
};

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

/// Beyond this many ceremonies in progress, new ones are refused, so a flood of start calls cannot
/// grow memory without bound.
const MAX_PENDING: usize = 1000;

/// Ceremonies waiting for their finish call, keyed by challenge. Each one expires with its
/// timeout, so one the user abandoned does not stay forever.
struct Pending<T>(HashMap<String, (Instant, T)>);

impl<T> Default for Pending<T> {
    fn default() -> Self {
        Pending(HashMap::new())
    }
}

impl<T> Pending<T> {
    fn insert(&mut self, challenge: String, timeout_ms: u64, state: T) -> Result<(), String> {
        let now = Instant::now();
        self.0.retain(|_, (expires, _)| *expires > now);
        if self.0.len() >= MAX_PENDING {
            return Err("Too many ceremonies in progress, try again later".into());
        }
        let expires = now + Duration::from_millis(timeout_ms);
        self.0.insert(challenge, (expires, state));
        Ok(())
    }

    fn remove(&mut self, challenge: &str) -> Option<T> {
        let (expires, state) = self.0.remove(challenge)?;
        (expires > Instant::now()).then_some(state)
    }
}

/// In-memory storage for users and ceremonies in progress.
///
/// A real server would use a database for the users and a shared expiring cache, such as Redis,
/// for the pending states.
#[derive(Clone, Default)]
struct Store {
    /// Keyed by username.
    users: Arc<Mutex<HashMap<String, User>>>,

    /// Registrations waiting for their finish call, keyed by challenge.
    pending_registrations: Arc<Mutex<Pending<RegistrationState>>>,

    /// Authentications waiting for their finish call, keyed by challenge.
    pending_authentications: Arc<Mutex<Pending<AuthenticationState>>>,

    /// Signed-in usernames, keyed by the token in the session cookie.
    sessions: Arc<Mutex<HashMap<String, String>>>,
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

// Sessions

const SESSION_COOKIE: &str = "session";

fn session_user(store: &Store, token: Option<&str>) -> Option<String> {
    store.sessions.lock().unwrap().get(token?).cloned()
}

/// Signs the user in and returns the `Set-Cookie` value that carries the new session.
fn start_session(store: &Store, username: &str) -> String {
    let token = Uuid::new_v4().simple().to_string();
    store
        .sessions
        .lock()
        .unwrap()
        .insert(token.clone(), username.to_owned());
    // HttpOnly hides the token from page scripts and SameSite=Strict stops other sites from
    // sending it. A real site must also add Secure; it is left out here because the demo runs on
    // plain http://localhost.
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/")
}

/// Anyone may create a new account, but only its signed-in owner may add a passkey to one.
fn check_may_register(
    users: &HashMap<String, User>,
    signed_in: Option<&str>,
    username: &str,
) -> Result<(), warp::Rejection> {
    if users.contains_key(username) && signed_in != Some(username) {
        return Err(warp::reject::custom(AppError(format!(
            "Sign in as {username} to add a passkey"
        ))));
    }
    Ok(())
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
    token: Option<String>,
    req: RegisterStartRequest,
) -> Result<impl Reply, warp::Rejection> {
    let signed_in = session_user(&state.store, token.as_deref());

    // Passkeys the user already has, which the authenticator must refuse to register a second time.
    let existing = {
        let users = state.store.users.lock().unwrap();
        check_may_register(&users, signed_in.as_deref(), &req.username)?;
        users.get(&req.username).map(|u| (u.id, u.passkeys.clone()))
    };

    // Random and opaque rather than the username, so it cannot be used to track the user across
    // sites. A returning user keeps their first ID, because sign-in finds the user by it.
    let user_id = existing
        .as_ref()
        .map_or_else(Uuid::new_v4, |(id, _)| *id)
        .as_bytes()
        .to_vec();

    // credProps reports whether a discoverable credential was created. The eval-less PRF input only
    // asks whether PRF is supported at all.
    let mut extensions = RegistrationExtensions::default();
    extensions.cred_props = Some(true);
    extensions.prf = Some(PrfRegistrationInput::default());

    let mut options = RegistrationOptions::default();
    options.attestation = if req.attestation {
        AttestationConveyancePreference::Direct
    } else {
        AttestationConveyancePreference::None
    };
    options.exclude_credentials = existing.as_ref().map(|(_, passkeys)| passkeys.as_slice());
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
        .insert(challenge.challenge.clone(), challenge.timeout, reg_state)
        .map_err(|e| warp::reject::custom(AppError(e)))?;

    Ok(reply::json(&challenge))
}

/// POST /register/finish - Complete passkey registration
///
/// Verifies the new credential, stores it, and reports whether the passkey supports
/// the PRF extension. A new account is signed in straight away.
async fn register_finish(
    state: AppState,
    token: Option<String>,
    credential: RegistrationCredential,
) -> Result<impl Reply, warp::Rejection> {
    let signed_in = session_user(&state.store, token.as_deref());

    // The challenge says which pending ceremony this belongs to.
    let client_data = ClientData::from_base64(&credential.response.client_data_json)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    let reg_state = state
        .store
        .pending_registrations
        .lock()
        .unwrap()
        .remove(&client_data.challenge)
        .ok_or_else(|| warp::reject::custom(AppError("No pending registration".into())))?;

    let prf_supported = credential
        .client_extension_results
        .as_ref()
        .and_then(|ext| ext.prf.as_ref())
        .and_then(|prf| prf.enabled)
        .unwrap_or(false);

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

    let mut users = state.store.users.lock().unwrap();
    // Checked again, because someone else may have created the account since the start call.
    check_may_register(&users, signed_in.as_deref(), &reg_state.user.name)?;
    let cookie = (!users.contains_key(&reg_state.user.name))
        .then(|| start_session(&state.store, &reg_state.user.name));

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

    let body = reply::json(&ApiResponse {
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
    });

    Ok(match cookie {
        Some(cookie) => reply::with_header(body, SET_COOKIE, cookie).into_response(),
        None => body.into_response(),
    })
}

/// POST /auth/start - Begin passkey authentication
///
/// With a username the challenge names that user's credentials, so the browser offers only those;
/// without one it names none and the browser offers every passkey it holds for this site.
///
/// A `prf_salt` is passed on to the authenticator, which derives a key from it.
async fn auth_start(state: AppState, req: AuthStartRequest) -> Result<impl Reply, warp::Rejection> {
    let passkeys = if let Some(ref username) = req.username {
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
        let mut prf = PrfAuthenticationInput::default();
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
        .start_passkey_authentication(&passkeys, options)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    // Keyed by the challenge, which is what the finish call brings back.
    state
        .store
        .pending_authentications
        .lock()
        .unwrap()
        .insert(challenge.challenge.clone(), challenge.timeout, auth_state)
        .map_err(|e| warp::reject::custom(AppError(e)))?;

    Ok(reply::json(&challenge))
}

/// POST /auth/finish - Complete passkey authentication
///
/// Verifies the signature, signs the user in and, when a PRF salt was sent, returns the derived
/// key hex-encoded in `prf_output`.
async fn auth_finish(
    state: AppState,
    credential: AuthenticationCredential,
) -> Result<impl Reply, warp::Rejection> {
    // The challenge says which pending ceremony this belongs to.
    let client_data = ClientData::from_base64(&credential.response.client_data_json)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    let auth_state = state
        .store
        .pending_authentications
        .lock()
        .unwrap()
        .remove(&client_data.challenge)
        .ok_or_else(|| warp::reject::custom(AppError("No pending authentication".into())))?;

    let credential_id = Passki::base64_decode(&credential.raw_id)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    // The user handle gives a direct lookup; without it, scan every user for a matching credential
    // ID.
    let mut users = state.store.users.lock().unwrap();
    let found = match credential.response.user_handle.as_deref() {
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
    };

    // The browser offered a passkey this server does not hold. The signal tells it to hide that
    // passkey rather than offer it again; it names no user, so a signed-out caller may see it.
    let Some((username, passkey)) = found else {
        return Ok(reply::json(&ApiResponse {
            success: false,
            message: "Unknown credential".into(),
            signals: Some(Signals {
                unknown_credential: Some(state.passki.signal_unknown_credential(&credential_id)),
                ..Default::default()
            }),
            ..Default::default()
        })
        .into_response());
    };

    let result = state
        .passki
        .finish_passkey_authentication(&credential, &auth_state, passkey)
        .map_err(|e| warp::reject::custom(AppError(e.to_string())))?;

    // Must be stored: if the next login reports a counter that did not grow, the credential
    // has been cloned.
    passkey.counter = result.counter;
    // Synced state can change after registration, e.g. when the user turns on a sync service.
    passkey.bs = result.bs;

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

    let cookie = start_session(&state.store, &username);

    let body = reply::json(&ApiResponse {
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
    });

    Ok(reply::with_header(body, SET_COOKIE, cookie).into_response())
}

/// GET /session - The protected route: answers only to a signed-in user
async fn session(state: AppState, token: Option<String>) -> Result<impl Reply, warp::Rejection> {
    Ok(match session_user(&state.store, token.as_deref()) {
        Some(username) => reply::json(&ApiResponse {
            success: true,
            message: format!("Signed in as {username}"),
            username: Some(username),
            ..Default::default()
        })
        .into_response(),
        None => reply::with_status("Not signed in", StatusCode::UNAUTHORIZED).into_response(),
    })
}

/// POST /logout - End the session
async fn logout(state: AppState, token: Option<String>) -> Result<impl Reply, warp::Rejection> {
    if let Some(token) = token {
        state.store.sessions.lock().unwrap().remove(&token);
    }
    let body = reply::json(&ApiResponse {
        success: true,
        message: "Signed out".into(),
        ..Default::default()
    });
    Ok(reply::with_header(
        body,
        SET_COOKIE,
        format!("{SESSION_COOKIE}=; Max-Age=0; Path=/"),
    ))
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
        .and(warp::cookie::optional::<String>(SESSION_COOKIE))
        .and(warp::body::json())
        .and_then(register_start);

    let register_finish = warp::path!("register" / "finish")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::cookie::optional::<String>(SESSION_COOKIE))
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

    let session = warp::path!("session")
        .and(warp::get())
        .and(with_state(state.clone()))
        .and(warp::cookie::optional::<String>(SESSION_COOKIE))
        .and_then(session);

    let logout = warp::path!("logout")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::cookie::optional::<String>(SESSION_COOKIE))
        .and_then(logout);

    let routes = index
        .or(register_start)
        .or(register_finish)
        .or(auth_start)
        .or(auth_finish)
        .or(session)
        .or(logout)
        .recover(handle_rejection);

    println!("Server starting on http://localhost:3000");
    warp::serve(routes).run(([0, 0, 0, 0], 3000)).await;
}
