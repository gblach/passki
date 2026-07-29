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
passki = "0.2"
```

## Quick Start

```rust
use passki::{AuthenticationOptions, Passki, RegistrationOptions, StoredPasskey};

// Initialize Passki with your relying party information
let passki = Passki::new(
    "example.com",              // Relying Party ID (domain)
    &["https://example.com"],   // Accepted Relying Party Origins
    "Example Corp"              // Relying Party Name
);

// Registration flow
// Step 1: Start registration and send challenge to client
let user_id = b"unique_user_identifier_12345"; // At least 16 bytes
let (registration_challenge, registration_state) = passki.start_passkey_registration(
    user_id,                        // User ID (bytes)
    "alice@example.com",            // Username
    "Alice Smith",                  // Display name
    RegistrationOptions::default(), // Timeout, attestation, resident key, UV, exclusions, extensions
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
    &user_passkeys,                   // User's stored passkeys
    AuthenticationOptions::default(), // Timeout, user verification, extensions
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
use passki::{RegistrationExtensions, RegistrationOptions};

// Request credProps during registration
let mut extensions = RegistrationExtensions::default();
extensions.cred_props = Some(true);

let mut options = RegistrationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, options,
)?;

let passkey = passki.finish_passkey_registration(&credential, &state)?;
// passkey.rk == Some(true)  → discoverable credential created
// passkey.rk == Some(false) → non-discoverable credential created
// passkey.rk == None        → authenticator did not report
```

### PRF

The [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) lets a passkey derive deterministic secret bytes from the authenticator's internal HMAC-secret. This is useful for end-to-end encryption, per-user key derivation, and other scenarios where you need a stable secret tied to a specific passkey.

The server passes input salts; the browser computes `SHA-256("WebAuthn PRF" || 0x00 || input)` and feeds the result into the authenticator, which computes the HMAC with the credential's own secret through the CTAP2 `hmac-secret` extension. Passki passes the outputs through without processing them.

```rust
use passki::{
    AuthenticationExtensions, AuthenticationOptions, PrfEval, PrfInput, RegistrationExtensions,
    RegistrationOptions,
};

// During registration, probe for PRF support
let mut extensions = RegistrationExtensions::default();
extensions.prf = Some(PrfInput { eval: None });

let mut options = RegistrationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, options,
)?;
// Check client_extension_results.prf.enabled in the credential before calling finish
// to know whether the authenticator supports PRF

// During authentication, request a PRF derivation for a given context
let mut extensions = AuthenticationExtensions::default();
extensions.prf = PrfInput {
    eval: Some(PrfEval {
        first: Passki::base64_encode(b"my-app-encryption-key-context"),
        second: None,
    }),
};

let mut options = AuthenticationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_authentication(&user_passkeys, options);

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

WebAuthn has three specification levels published by the W3C, plus extensions that other
specifications define. Checkboxes mark features currently implemented in passki.

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
- [x] Attestation statement verification (`packed`, `tpm`, `android-key`, `fido-u2f`) - verifies the statement signature and certificate requirements
- [x] rpId hash verification in authenticator data - the hash in bytes 0-31 is compared against `sha256(rp_id)`
- [x] UP (user present) flag enforcement
- [x] UV (user verified) flag enforcement
- [ ] `authenticatorAttachment` (`platform` / `cross-platform`) - restrict registration to platform or roaming authenticators
- [ ] Attestation trust path validation - chain the attestation certificate to a trusted root; today only the statement signature and certificate requirements are checked
- [ ] AAGUID exposure - parsed internally for certificate checks, but not surfaced on `StoredPasskey`; needed for Metadata Service lookups

### Level 2 (2021)

A substantial expansion, still the most widely implemented level today:

- [x] Discoverable credentials / usernameless flows (empty `allowCredentials`)
- [x] `ResidentKeyRequirement` (`discouraged` / `preferred` / `required`)
- [x] `enterprise` attestation conveyance preference
- [x] Zero-counter authenticator support (explicitly allowed per spec)
- [x] `credProps` extension - reports whether a discoverable credential was created
- [ ] `largeBlob` extension - store small blobs on the authenticator (e.g. SSH keys)
- [x] `userHandle` in authentication response - needed to identify the user in usernameless flows
- [ ] `transports` on credential descriptors - report what `getTransports()` returned so the browser can show the right USB / NFC / BLE / internal prompt

### Level 3 (Candidate Recommendation, not yet a W3C Recommendation)

Still under active development:

- [x] PRF extension (`prf`) - deterministic key derivation, backed by the CTAP `hmac-secret` extension
- [x] BE/BS flags (backup eligibility/state) - exposed on `StoredPasskey`; rejects BS set without BE
- [ ] Related origin requests - use credentials across subdomains / related origins
- [ ] Accept the spec's `RegistrationResponseJSON` and `AuthenticationResponseJSON` shapes, so a front end can post `credential.toJSON()` unmodified instead of remapping fields; the outbound challenge JSON already matches `PublicKeyCredentialCreationOptionsJSON`
- [ ] Signal API - lets RPs notify the browser that a credential was deleted or changed
- [ ] `hints` (`security-key` / `client-device` / `hybrid`) - guide the client toward a kind of authenticator
- [ ] `attestationFormats` - state which attestation statement formats the relying party prefers; cheap to add, but it is only a preference and no browser is known to honor it yet
- [ ] `evalByCredential` in the `prf` extension - per-credential PRF inputs, required when `allowCredentials` holds more than one credential
- [ ] `authenticatorDisplayName` in the `credProps` extension - human-readable name of the authenticator that created the credential
- [ ] `remoteClientDataJSON` extension - lets a remote desktop client supply the complete `clientDataJSON`, so a local authenticator can sign into a site displayed on a remote host; [editor's draft](https://w3c.github.io/webauthn/) only, absent from the published Candidate Recommendation, and Chrome is still at Intent to Prototype
- [ ] `compound` attestation statement format - bundles two or more attestation statements; specified since 2023 but not produced by any authenticator yet, so it is waiting on deployment rather than on effort

### Defined outside WebAuthn

These extensions are registered in the [IANA WebAuthn extension identifiers registry](https://www.iana.org/assignments/webauthn/webauthn.xhtml)
but specified elsewhere, so they are not tied to a WebAuthn level:

- [ ] `credProtect` extension ([CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension) §12.1) - control the UV requirement for credential access
- [ ] `minPinLength` extension (CTAP 2.1 §12.4) - query the authenticator's configured minimum PIN length
- [ ] `payment` extension ([Secure Payment Confirmation](https://www.w3.org/TR/secure-payment-confirmation/) §5) - SPC integration

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
