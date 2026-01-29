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

//! # Passkeys Demo Server
//!
//! This example demonstrates WebAuthn/Passkey authentication using the Passki library
//! with the Axum web framework.
//!
//! ## Authentication Flows
//!
//! ### Registration (creating a new passkey)
//! 1. Client sends username to `/register/start`
//! 2. Server generates a challenge and returns WebAuthn options
//! 3. Client calls `navigator.credentials.create()` with these options
//! 4. User authenticates with their device (fingerprint, face, PIN, etc.)
//! 5. Client sends the credential to `/register/finish`
//! 6. Server verifies and stores the passkey
//!
//! ### Authentication (using an existing passkey)
//! Two modes are supported:
//!
//! **Passwordless** (username provided):
//! - Server returns only the credentials registered to that user
//! - Browser shows only matching passkeys
//!
//! **Usernameless** (no username):
//! - Server returns empty credential list
//! - Browser shows all available passkeys (discoverable credentials)
//! - Server identifies the user by the credential used
//!
//! ## Running
//! ```sh
//! cargo run --example axum
//! ```
//! Then open http://localhost:3000 in your browser.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use passki::{
    AttestationConveyancePreference, AuthenticationChallenge, AuthenticationCredential,
    AuthenticationState, ClientData, Passki, RegistrationChallenge, RegistrationCredential,
    RegistrationState, ResidentKeyRequirement, StoredPasskey, UserVerificationRequirement,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

// =============================================================================
// Error handling
// =============================================================================

struct AppError(String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.0).into_response()
    }
}

impl<T: std::fmt::Display> From<T> for AppError {
    fn from(err: T) -> Self {
        AppError(err.to_string())
    }
}

type AppResult<T> = Result<Json<T>, AppError>;

// =============================================================================
// Storage
// =============================================================================

/// In-memory storage for users and pending WebAuthn ceremonies.
///
/// In production, you would use a database for users and a cache (e.g., Redis)
/// for pending states with appropriate expiration.
#[derive(Clone, Default)]
struct Store {
    /// Maps username -> User data
    users: Arc<Mutex<HashMap<String, User>>>,

    /// Pending registration ceremonies, keyed by challenge.
    /// The state must be kept between start and finish calls.
    pending_registrations: Arc<Mutex<HashMap<String, RegistrationState>>>,

    /// Pending authentication ceremonies, keyed by challenge.
    /// The state must be kept between start and finish calls.
    pending_authentications: Arc<Mutex<HashMap<String, AuthenticationState>>>,
}

/// User record containing their profile and registered passkeys.
#[derive(Clone)]
#[allow(unused)]
struct User {
    /// Unique user identifier.
    id: Uuid,
    /// Username or account identifier.
    username: String,
    /// Human-readable display name.
    display_name: String,
    /// All passkeys registered by this user. A user can have multiple passkeys
    /// (e.g., one on their phone, one on their laptop, one security key).
    passkeys: Vec<StoredPasskey>,
}

// =============================================================================
// Request/Response types
// =============================================================================

#[derive(Deserialize)]
struct RegisterStartRequest {
    username: String,
}

/// Data sent by the client after WebAuthn credential creation.
#[derive(Deserialize)]
struct RegisterFinishRequest {
    /// Base64url-encoded credential ID from the authenticator
    credential_id: String,
    /// Base64url-encoded attestation object containing the public key
    public_key: String,
    /// Base64url-encoded client data JSON
    client_data_json: String,
}

/// Request to start authentication. Username is optional:
/// - If provided: passwordless flow (server specifies allowed credentials)
/// - If omitted: usernameless flow (browser shows all available passkeys)
#[derive(Deserialize, Default)]
struct AuthStartRequest {
    #[serde(default)]
    username: Option<String>,
}

/// Data sent by the client after WebAuthn authentication.
#[derive(Deserialize)]
struct AuthFinishRequest {
    /// Base64url-encoded credential ID identifying which passkey was used
    credential_id: String,
    /// Base64url-encoded authenticator data (contains flags and counter)
    authenticator_data: String,
    /// Base64url-encoded client data JSON
    client_data_json: String,
    /// Base64url-encoded signature over authenticator_data + hash(client_data_json)
    signature: String,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
    /// In usernameless flow, returns the identified username
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

// =============================================================================
// Application state
// =============================================================================

#[derive(Clone)]
struct AppState {
    passki: Arc<Passki>,
    store: Store,
}

// =============================================================================
// Handlers
// =============================================================================

async fn index() -> Result<Html<String>, AppError> {
    let html = fs::read_to_string("examples/index.html")
        .map_err(|e| AppError(e.to_string()))?;
    Ok(Html(html))
}

/// POST /register/start - Begin passkey registration
///
/// Generates a challenge and WebAuthn options for the client to create a credential.
/// The challenge is random bytes that the authenticator must sign, preventing replay attacks.
async fn register_start(
    State(state): State<AppState>,
    Json(req): Json<RegisterStartRequest>,
) -> AppResult<RegistrationChallenge> {
    // Generate a unique user ID. This should be random and opaque (not the username)
    // to prevent tracking users across sites.
    let user_id = Uuid::new_v4().as_bytes().to_vec();

    // If user exists, get their existing passkeys to exclude them from re-registration
    let existing = state.store.users.lock().unwrap()
        .get(&req.username).map(|u| u.passkeys.clone());

    let (challenge, reg_state) = state.passki.start_passkey_registration(
        &user_id,
        &req.username,                          // User handle (displayed by authenticator)
        &req.username,                          // Display name
        60000,                                  // Timeout in milliseconds
        AttestationConveyancePreference::None,  // Don't request attestation
        ResidentKeyRequirement::Preferred,      // Request discoverable credential if possible
        UserVerificationRequirement::Preferred, // Request user verification if available
        existing.as_deref(),                    // Exclude existing credentials
    )?;

    // Store state for verification in finish step, keyed by the challenge
    state.store.pending_registrations.lock().unwrap().insert(challenge.challenge.clone(), reg_state);

    // Return challenge to client (will be passed to navigator.credentials.create())
    Ok(Json(challenge))
}

/// POST /register/finish - Complete passkey registration
///
/// Verifies the credential created by the authenticator and stores it.
async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegisterFinishRequest>,
) -> AppResult<ApiResponse> {
    // Parse client data to extract challenge
    let client_data = ClientData::from_base64(&req.client_data_json)?;

    // Retrieve and remove the pending registration state
    let reg_state = state.store.pending_registrations.lock().unwrap()
        .remove(&client_data.challenge)
        .ok_or(AppError("No pending registration".into()))?;

    // Package the credential data from the client
    let credential = RegistrationCredential {
        credential_id: req.credential_id,
        public_key: req.public_key,
        client_data_json: req.client_data_json,
    };

    // Verify the credential (checks origin, challenge, parses public key)
    let passkey = state.passki.finish_passkey_registration(&credential, &reg_state)?;

    // Decode user ID from base64url to UUID
    let user_id_bytes = Passki::base64_decode(&reg_state.user.id)?;
    let user_id = Uuid::from_slice(&user_id_bytes)?;

    // Store the passkey for future authentication.
    let mut users = state.store.users.lock().unwrap();
    users
        .entry(reg_state.user.name.clone())
        // If user exists, add passkey to their list.
        .and_modify(|user| user.passkeys.push(passkey.clone()))
        // If new user, create user record with their info.
        .or_insert(User {
            id: user_id,
            username: reg_state.user.name,
            display_name: reg_state.user.display_name,
            passkeys: vec![passkey],
        });

    Ok(Json(ApiResponse { success: true, message: "Registration successful".into(), username: None }))
}

/// POST /auth/start - Begin passkey authentication
///
/// Two modes based on whether username is provided:
/// - Passwordless: returns challenge with user's credential IDs (browser filters to these)
/// - Usernameless: returns challenge with empty credential list (browser shows all passkeys)
///
/// The challenge is used to correlate start and finish requests.
async fn auth_start(
    State(state): State<AppState>,
    Json(req): Json<AuthStartRequest>,
) -> AppResult<AuthenticationChallenge> {
    let passkeys = if let Some(ref username) = req.username {
        // Passwordless flow: get user's passkeys to include in allowCredentials
        let users = state.store.users.lock().unwrap();
        let user = users.get(username).ok_or(AppError("User not found".into()))?;
        user.passkeys.clone()
    } else {
        // Usernameless flow: empty allowCredentials lets browser show all passkeys
        vec![]
    };

    let (challenge, auth_state) = state.passki.start_passkey_authentication(
        &passkeys,
        60000,                                  // Timeout in milliseconds
        UserVerificationRequirement::Preferred, // Request user verification if available
    );

    // Store state for verification in finish step, keyed by the challenge
    state.store.pending_authentications.lock().unwrap().insert(challenge.challenge.clone(), auth_state);

    // Return challenge to client
    Ok(Json(challenge))
}

/// POST /auth/finish - Complete passkey authentication
///
/// Verifies the signature from the authenticator. The signature proves:
/// 1. The user possesses the private key for this credential
/// 2. The user approved this specific authentication (via the signed challenge)
/// 3. User verification was performed (if required)
async fn auth_finish(
    State(state): State<AppState>,
    Json(req): Json<AuthFinishRequest>,
) -> AppResult<ApiResponse> {
    // Parse client data to extract challenge
    let client_data = ClientData::from_base64(&req.client_data_json)?;

    // Retrieve pending state using challenge
    let auth_state = state.store.pending_authentications.lock().unwrap()
        .remove(&client_data.challenge)
        .ok_or(AppError("No pending authentication".into()))?;

    // Decode credential ID to find the matching passkey
    let credential_id = Passki::base64_decode(&req.credential_id)?;

    // Find user by credential_id
    let mut users = state.store.users.lock().unwrap();
    let (username, passkey) = users.iter_mut()
        .find_map(|(name, user)| {
            user.passkeys.iter_mut()
                .find(|pk| pk.credential_id == credential_id)
                .map(|pk| (name.clone(), pk))
        })
        .ok_or(AppError("Unknown credential".into()))?;

    // Package the authentication response from the client
    let credential = AuthenticationCredential {
        credential_id: req.credential_id,
        authenticator_data: req.authenticator_data,
        client_data_json: req.client_data_json,
        signature: req.signature,
    };

    // Verify the signature (checks origin, challenge, signature, counter)
    let result = state.passki.finish_passkey_authentication(&credential, &auth_state, passkey)?;

    // Update the counter to detect cloned authenticators.
    // If counter goes backwards, it may indicate the credential was cloned.
    passkey.counter = result.counter;

    Ok(Json(ApiResponse {
        success: true,
        message: format!("Welcome back, {}!", username),
        username: Some(username),
    }))
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_target(false).init();

    // Initialize Passki with relying party information.
    // - rp_id: The domain name (no protocol or port). Credentials are bound to this.
    // - origin: The full origin URL. Must match what the browser sends.
    // - rp_name: Human-readable name shown by authenticators.
    let state = AppState {
        passki: Arc::new(Passki::new(
            "localhost",
            "http://localhost:3000",
            "Passkeys Demo",
        )),
        store: Store::default(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        .route("/auth/start", post(auth_start))
        .route("/auth/finish", post(auth_finish))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server starting on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
