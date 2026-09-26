# Passki

A simple and secure WebAuthn/Passkey implementation for Rust.

[![Crates.io](https://img.shields.io/crates/v/passki.svg)](https://crates.io/crates/passki)
[![Documentation](https://docs.rs/passki/badge.svg)](https://docs.rs/passki)
[![License](https://img.shields.io/crates/l/passki.svg)](https://github.com/gblach/passki#license)

## Features

- ✨ **Simple API** - Easy-to-use interface for passkey registration and authentication
- 🔐 **Multiple Algorithms** - Support for EdDSA (Ed25519), ES256/ES384 (P-256/P-384),
  and RS256/RS384 (RSA)
- 🛡️ **Security First** - Built-in replay attack protection via signature counters
- 📦 **Framework Agnostic** - No web framework lock-in, works with any HTTP server
- 📨 **Spec JSON Shapes** - Both ceremonies take `credential.toJSON()` as the browser produces it,
  so the front end remaps nothing
- 🔑 **[Extensions](docs/extensions.md)** - Support for `credProps` (discoverable credential reporting), PRF (key
  derivation / E2E encryption), `largeBlob` (blob storage on the authenticator), `credProtect`
  (user verification policy on security keys) and `minPinLength` (PIN policy on managed keys)
- 💡 **[Hints](docs/hints.md)** - Steer the browser's UI toward a security key, this device or a phone, without
  ruling any of them out
- 🌐 **[Related Origins](docs/related-origins.md)** - One passkey across several domains, with a helper for
  the `.well-known/webauthn` file
- 🖼️ **[Cross-origin Iframes](docs/cross-origin-iframes.md)** - Refused by default, with an opt-in allowlist of embedding origins
  checked against `topOrigin`
- 📡 **[Signal API](docs/signal-api.md)** - Payloads that tell the browser when a passkey or a username changed,
  so stale ones stop being offered
- 📜 **[Attestation](docs/attestation.md)** - Statement verification for `packed`, `tpm`, `android-key` and `fido-u2f`,
  with opt-in trust path validation against your own roots
- 🦀 **Pure Rust** - Memory-safe implementation with no unsafe code

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
passki = "0.4"
```

## Quick Start

```rust
use passki::{AuthenticationOptions, Passki, RegistrationOptions, StoredPasskey};

let passki = Passki::new(
    "example.com",              // relying party ID (the domain)
    &["https://example.com"],   // accepted origins
    "Example Corp"              // name shown in the browser prompt
);

// Registration step 1: issue a challenge
let user_id = b"unique_user_identifier_12345"; // at least 16 bytes
let (registration_challenge, registration_state) = passki.start_passkey_registration(
    user_id,
    "alice@example.com",            // username
    "Alice Smith",                  // display name
    RegistrationOptions::default(),
).expect("user_id must be at least 16 bytes");

// Send registration_challenge to the client as JSON, keep registration_state.

// Registration step 2: verify the credential the client created
let mut stored_passkey = passki.finish_passkey_registration(
    &registration_credential,
    &registration_state,
)?;

// Save stored_passkey in your database, associated with the user.

// Authentication step 1: issue a challenge
let (authentication_challenge, authentication_state) = passki.start_passkey_authentication(
    &user_passkeys,
    AuthenticationOptions::default(),
)?;

// Authentication step 2: verify the signature
let result = passki.finish_passkey_authentication(
    &authentication_credential,
    &authentication_state,
    &stored_passkey,
)?;

// Persist the new counter, or replay detection has nothing to compare against.
stored_passkey.counter = result.counter;
```

## Security Considerations

- 🔒 **Always use HTTPS in production** - browsers refuse WebAuthn on insecure origins
- 🔄 **Store the counter** returned by each authentication, or cloned authenticators go undetected
- 🔐 **Require user verification** for sensitive operations
- ⏱️ **Keep ceremony timeouts short**; the state stored between the two steps expires with them
- 🖼️ **Allow only the iframe embedders you trust** with `with_embedding_origins`

## Requirements

- Rust 1.85 or later (Edition 2024)

## Examples

The `examples/` directory has complete registration and authentication flows for several
web frameworks: [Actix-web](examples/actix-web.rs) | [Axum](examples/axum.rs)
| [Poem](examples/poem.rs)
| [Rocket](examples/rocket.rs) | [Warp](examples/warp.rs)

Each one also demonstrates `credProps`, PRF key derivation and the Signal API.

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
- [x] Attestation statement verification (`packed`, `tpm`, `android-key`, `fido-u2f`)
- [x] rpId hash verification in authenticator data
- [x] UP (user present) flag enforcement
- [x] UV (user verified) flag enforcement
- [x] AAGUID exposure
- [x] `authenticatorAttachment` (`platform` / `cross-platform`)
- [x] Attestation trust path validation

### Level 2 (2021)

A substantial expansion, still the most widely implemented level today:

- [x] Discoverable credentials / usernameless flows (empty `allowCredentials`)
- [x] `ResidentKeyRequirement` (`discouraged` / `preferred` / `required`)
- [x] `enterprise` attestation conveyance preference
- [x] Zero-counter authenticator support
- [x] `credProps` extension
- [x] `largeBlob` extension
- [x] `userHandle` in authentication response
- [x] `transports` on credential descriptors

### Level 3 (2026)

A W3C Recommendation since 25 August 2026, though browser support for its newer parts is still
filling in:

- [x] PRF extension (`prf`)
- [x] BE/BS flags (backup eligibility/state)
- [x] Related origin requests
- [x] `RegistrationResponseJSON` and `AuthenticationResponseJSON` request shapes
- [x] Signal API
- [x] `hints` (`security-key` / `client-device` / `hybrid`)
- [ ] `attestationFormats`
- [x] `evalByCredential` in the `prf` extension
- [ ] `compound` attestation statement format
- [x] Cross-origin ceremonies in iframes, verifying `topOrigin`

### Defined outside WebAuthn

These extensions are registered in the [IANA WebAuthn extension identifiers
registry](https://www.iana.org/assignments/webauthn/webauthn.xhtml) but specified elsewhere, so they
are not tied to a WebAuthn level:

- [x] `credProtect` extension ([CTAP
  2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension)
  §12.1)
- [x] `minPinLength` extension ([CTAP
  2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-minpinlength-extension)
  §12.4)
- [ ] `payment` extension ([Secure Payment
  Confirmation](https://www.w3.org/TR/secure-payment-confirmation/) §5)

## License

This project is licensed under the [Apache License, Version
2.0](http://www.apache.org/licenses/LICENSE-2.0) ([LICENSE](LICENSE)).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
