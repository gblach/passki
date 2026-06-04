# Passki

A simple, secure, and easy-to-use WebAuthn/Passkey implementation for Rust.

[![Crates.io](https://img.shields.io/crates/v/passki.svg)](https://crates.io/crates/passki)
[![Documentation](https://docs.rs/passki/badge.svg)](https://docs.rs/passki)
[![License](https://img.shields.io/crates/l/passki.svg)](https://github.com/gblach/passki#license)

## Features

- ✨ **Simple API** - Easy-to-use interface for passkey registration and authentication
- 🔐 **Multiple Algorithms** - Support for EdDSA (Ed25519), ES256/ES384 (P-256/P-384), and RS256/RS384 (RSA)
- 🛡️ **Security First** - Built-in replay attack protection via signature counters
- 📦 **Framework Agnostic** - No web framework lock-in, works with any HTTP server
- 🔑 **Extensions** - Support for `credProps` (discoverable credential reporting) and PRF (key derivation / E2E encryption)
- 🦀 **Pure Rust** - Memory-safe implementation with no unsafe code

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
passki = "0.1"
```

## Quick Start

```rust
use passki::{
    Passki, AttestationConveyancePreference, ResidentKeyRequirement,
    UserVerificationRequirement, StoredPasskey,
};

// Initialize Passki with your relying party information
let passki = Passki::new(
    "example.com",              // Relying Party ID (domain)
    "https://example.com",      // Relying Party Origin
    "Example Corp"              // Relying Party Name
);

// Registration flow
// Step 1: Start registration and send challenge to client
let user_id = b"unique_user_identifier_12345"; // At least 16 bytes
let (registration_challenge, registration_state) = passki.start_passkey_registration(
    user_id,                                        // User ID (bytes)
    "alice@example.com",                            // Username
    "Alice Smith",                                  // Display name
    60000,                                          // Timeout (ms)
    AttestationConveyancePreference::None,          // Attestation
    ResidentKeyRequirement::Preferred,              // Resident key
    UserVerificationRequirement::Preferred,         // User verification
    None,                                           // Exclude existing credentials
    None,                                           // Extensions (None, or Some(RegistrationExtensions { ... }))
).expect("user_id must be at least 16 bytes");

// Send registration_challenge to client (as JSON)
// Client uses WebAuthn API to create credential

// Step 2: Receive credential from client and complete registration
let mut stored_passkey = passki.finish_passkey_registration(
    &registration_credential,  // Credential from client
    &registration_state,       // State from step 1
)?;

// Save stored_passkey to your database associated with the user

// Authentication flow
// Step 1: Start authentication and send challenge to client
let (authentication_challenge, authentication_state) = passki.start_passkey_authentication(
    &user_passkeys,                            // User's stored passkeys
    60000,                                     // Timeout (ms)
    UserVerificationRequirement::Preferred,    // User verification
    None,                                      // Extensions (None, or Some(AuthenticationExtensions { ... }))
);

// Send authentication_challenge to client (as JSON)
// Client uses WebAuthn API to sign the challenge

// Step 2: Receive credential from client and verify authentication
let result = passki.finish_passkey_authentication(
    &authentication_credential,  // Credential from client
    &authentication_state,       // State from step 1
    &stored_passkey,             // User's passkey from database
)?;

// Update the counter in your database to prevent replay attacks
stored_passkey.counter = result.counter;
```

## Supported Algorithms

Passki supports the following COSE algorithms:

- **EdDSA** (Ed25519) - Algorithm ID: -8
- **ES256** (ECDSA with P-256 and SHA-256) - Algorithm ID: -7
- **ES384** (ECDSA with P-384 and SHA-384) - Algorithm ID: -35
- **RS256** (RSASSA-PKCS1-v1_5 with SHA-256) - Algorithm ID: -257
- **RS384** (RSASSA-PKCS1-v1_5 with SHA-384) - Algorithm ID: -258

## Extensions

### credProps

The `credProps` extension reports whether the authenticator created a discoverable (resident) credential - one stored on the device and usable in passwordless flows. Request it during registration; the result is stored in `StoredPasskey::rk`.

```rust
use passki::RegistrationExtensions;

// Request credProps during registration
let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, 60000,
    AttestationConveyancePreference::None,
    ResidentKeyRequirement::Preferred,
    UserVerificationRequirement::Preferred,
    None,
    Some(RegistrationExtensions { cred_props: Some(true), ..Default::default() }),
)?;

let passkey = passki.finish_passkey_registration(&credential, &state)?;
// passkey.rk == Some(true)  → discoverable credential created
// passkey.rk == Some(false) → non-discoverable credential created
// passkey.rk == None        → authenticator did not report
```

### PRF

The [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) lets a passkey derive deterministic secret bytes from the authenticator's internal HMAC-secret. This is useful for end-to-end encryption, per-user key derivation, and other scenarios where you need a stable secret tied to a specific passkey.

The server passes input salts; the browser computes `HMAC-SHA256("WebAuthn PRF" || 0x00 || input)` and feeds the result into the authenticator. Passki passes the outputs through without processing them.

```rust
use passki::{AuthenticationExtensions, PrfEval, PrfInput, RegistrationExtensions};

// During registration, probe for PRF support
let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, 60000,
    AttestationConveyancePreference::None,
    ResidentKeyRequirement::Preferred,
    UserVerificationRequirement::Preferred,
    None,
    Some(RegistrationExtensions { prf: Some(PrfInput { eval: None }), ..Default::default() }),
)?;
// Check client_extension_results.prf.enabled in the credential before calling finish
// to know whether the authenticator supports PRF

// During authentication, request a PRF derivation for a given context
let (challenge, state) = passki.start_passkey_authentication(
    &user_passkeys,
    60000,
    UserVerificationRequirement::Preferred,
    Some(AuthenticationExtensions {
        prf: PrfInput { eval: Some(PrfEval {
            first: Passki::base64_encode(b"my-app-encryption-key-context"),
            second: None,
        }) },
    }),
);

// result.prf_first contains the derived key bytes (32 bytes)
// The same passkey + same context always yields the same bytes
```

## Security Considerations

- 🔒 **Always use HTTPS in production** to prevent man-in-the-middle attacks
- 🔄 **Update signature counters** after successful authentication to detect cloned authenticators
- 🎯 **Verify origin matches** your expected domain (Passki does this automatically)
- 💾 **Store passkeys securely** in your database with proper access controls
- ⏱️ **Set appropriate timeouts** for registration and authentication ceremonies
- 🔐 **Use user verification** when handling sensitive operations

## Architecture

Passki follows a simple two-step pattern for both registration and authentication:

1. **Start**: Generate a challenge and return it to the client
2. **Finish**: Verify the response from the client

This design keeps state management simple and allows you to store session data however you prefer (in-memory, Redis, database, etc.).

## Requirements

- Rust 1.85 or later (Edition 2024)
- A web server to handle HTTP requests
- HTTPS in production (required by WebAuthn specification)

## Examples

The `examples/` directory has complete registration and authentication flows for several web frameworks:
[Actix-web](examples/actix-web.rs) | [Axum](examples/axum.rs) | [Poem](examples/poem.rs) | [Rocket](examples/rocket.rs) | [Warp](examples/warp.rs)

All examples request both `credProps` and PRF during registration. Registration reports whether a resident key was created; authentication accepts an optional key context string (`prf_salt`) to derive a 32-byte key.

```bash
cargo run --example axum  # or actix-web, poem, rocket, warp
```

Then visit `http://localhost:3000` in your browser.

## WebAuthn Specification Levels

WebAuthn has three specification levels published by the W3C. Checkboxes mark features
currently implemented in passki.

### Level 1 (2019)

The initial recommendation. Defined the core protocol:

- [x] Registration ceremony (`create`) and authentication ceremony (`get`)
- [x] Challenge generation and binding
- [x] Client data JSON origin verification
- [x] Authenticator data parsing
- [x] COSE public key extraction
- [x] Signature verification (EdDSA/Ed25519, ES256/P-256, ES384/P-384, RS256, RS384)
- [x] Signature counter tracking and replay detection
- [x] Credential exclusion (`excludeCredentials`)
- [x] `AttestationConveyancePreference` (`none` / `indirect` / `direct`)
- [x] Attestation object CBOR parsing
- [ ] Attestation statement verification (`packed`, `tpm`, `android-key`, `fido-u2f`) - `attStmt` is ignored; only `authData` is extracted
- [x] rpId hash verification in authenticator data - the hash in bytes 0-31 is compared against `sha256(rp_id)`
- [x] UP (user present) flag enforcement
- [ ] UV (user verified) flag enforcement

### Level 2 (2021)

A substantial expansion, still the most widely implemented level today:

- [x] Discoverable credentials / usernameless flows (empty `allowCredentials`)
- [x] `ResidentKeyRequirement` (`discouraged` / `preferred` / `required`)
- [x] `enterprise` attestation conveyance preference
- [x] Zero-counter authenticator support (explicitly allowed per spec)
- [x] `credProps` extension - reports whether a discoverable credential was created
- [ ] `largeBlob` extension - store small blobs on the authenticator (e.g. SSH keys)
- [ ] `minPinLength` extension - query or enforce minimum PIN length
- [ ] `credProtect` extension - control UV requirement for credential access
- [ ] `uvm` extension - user verification method details
- [ ] `userHandle` in authentication response - needed to identify the user in usernameless flows

### Level 3 (Candidate Recommendation, not yet a W3C Recommendation)

Still under active development:

- [x] PRF extension (`prf`) - deterministic key derivation via HMAC-Secret
- [ ] `payment` extension - Secure Payment Confirmation (SPC) integration
- [ ] Related origin requests - use credentials across subdomains / related origins
- [ ] JSON serialization helpers (`parseCreationOptionsFromJSON`, `toJSON`, etc.)
- [ ] Signal API - lets RPs notify the browser that a credential was deleted or changed
- [ ] Hybrid transport / cross-device auth (caBLE) - QR/BLE cross-device flows

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) ([LICENSE](LICENSE)).

## Acknowledgments

Passki is built on top of [aws-lc-rs](https://github.com/aws/aws-lc-rs) for cryptographic operations.

## Resources

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-3/)
- [FIDO Alliance](https://fidoalliance.org/)
- [WebAuthn Guide](https://webauthn.guide/)
