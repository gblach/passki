# Passki

A simple, secure, and easy-to-use WebAuthn/Passkey implementation for Rust.

[![Crates.io](https://img.shields.io/crates/v/passki.svg)](https://crates.io/crates/passki)
[![Documentation](https://docs.rs/passki/badge.svg)](https://docs.rs/passki)
[![License](https://img.shields.io/crates/l/passki.svg)](https://github.com/gblach/passki#license)

## Features

- ✨ **Simple API** - Easy-to-use interface for passkey registration and authentication
- 🔐 **Multiple Algorithms** - Support for EdDSA (Ed25519), ES256 (P-256), and RS256 (RSA)
- 🛡️ **Security First** - Built-in replay attack protection via signature counters
- 📦 **Zero Runtime Dependencies** - Only cryptography libraries, no web framework lock-in
- ✅ **WebAuthn Level 2 Compliant** - Follows the latest W3C specification
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
).expect("user_id must be at least 16 bytes");

// Send registration_challenge to client (as JSON)
// Client uses WebAuthn API to create credential

// Step 2: Receive credential from client and complete registration
let stored_passkey = passki.finish_passkey_registration(
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
- **RS256** (RSASSA-PKCS1-v1_5 with SHA-256) - Algorithm ID: -257

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

Check out the `examples/` directory for complete working examples:

- `actix-web.rs` - Full integration with Actix-web framework showing registration and authentication flows
- `axum.rs` - Full integration with Axum web framework showing registration and authentication flows
- `poem.rs` - Full integration with Poem web framework showing registration and authentication flows

Run an example:

```bash
cargo run --example actix-web
# or
cargo run --example axum
# or
cargo run --example poem
```

Then visit `http://localhost:3000` in your browser.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)
or http://www.apache.org/licenses/LICENSE-2.0).

## Acknowledgments

Passki is built on top of excellent Rust cryptography libraries:

- [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) - EdDSA signatures
- [p256](https://github.com/RustCrypto/elliptic-curves) - ECDSA with P-256
- [rsa](https://github.com/RustCrypto/RSA) - RSA signatures
- [ciborium](https://github.com/enarx/ciborium) - CBOR encoding/decoding

## Resources

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance](https://fidoalliance.org/)
- [WebAuthn Guide](https://webauthn.guide/)
