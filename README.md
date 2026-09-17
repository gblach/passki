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
- 🔑 **Extensions** - Support for `credProps` (discoverable credential reporting), PRF (key
  derivation / E2E encryption), `largeBlob` (blob storage on the authenticator), `credProtect`
  (user verification policy on security keys) and `minPinLength` (PIN policy on managed keys)
- 🌐 **Related Origins** - One passkey across several domains, with a helper for
  the `.well-known/webauthn` file
- 🖼️ **Cross-origin Iframes** - Refused by default, with an opt-in allowlist of embedding origins
  checked against `topOrigin`
- 📡 **Signal API** - Payloads that tell the browser when a passkey or a username changed,
  so stale ones stop being offered
- 📜 **Attestation** - Statement verification for `packed`, `tpm`, `android-key` and `fido-u2f`,
  with opt-in trust path validation against your own roots
- 🦀 **Pure Rust** - Memory-safe implementation with no unsafe code

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
passki = "0.3"
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
);

// Authentication step 2: verify the signature
let result = passki.finish_passkey_authentication(
    &authentication_credential,
    &authentication_state,
    &stored_passkey,
)?;

// Persist the new counter, or replay detection has nothing to compare against.
stored_passkey.counter = result.counter;
```

## Supported Algorithms

Passki supports the following COSE algorithms:

- **EdDSA** (Ed25519) - Algorithm ID: -8
- **ES256** (ECDSA with P-256 and SHA-256) - Algorithm ID: -7
- **ES384** (ECDSA with P-384 and SHA-384) - Algorithm ID: -35
- **RS256** (RSASSA-PKCS1-v1_5 with SHA-256) - Algorithm ID: -257
- **RS384** (RSASSA-PKCS1-v1_5 with SHA-384) - Algorithm ID: -258

## AAGUID

`StoredPasskey::aaguid` is the 16-byte identifier of the authenticator model - which YubiKey, which
password manager. Look it up in the [FIDO Metadata Service](https://fidoalliance.org/metadata/)
or a community AAGUID list.

All zero is the common case, and means there is no model to look up: under the default
`AttestationConveyancePreference::None` the browser zeroes the AAGUID before passing the credential
on. A non-zero value is worth acting on only once it has been validated, which is what
[Attestation](#attestation) sets up.

The same `StoredPasskey` also carries `be` (backup eligible - the credential is synced rather than
bound to one device) and `bs` (currently backed up), both straight from the authenticator data
flags.

## Extensions

### credProps

The `credProps` extension reports whether the authenticator created a discoverable (resident)
credential - one stored on the device and usable in passwordless flows. Request it during
registration; the result is stored in `StoredPasskey::rk`.

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

The [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) lets a passkey derive
deterministic secret bytes from the authenticator's internal HMAC-secret. This is useful
for end-to-end encryption, per-user key derivation, and other scenarios where you need a stable
secret tied to a specific passkey. Passki passes the outputs through without processing them.

```rust
use passki::{
    AuthenticationExtensions, AuthenticationOptions, Passki, PrfEval, PrfInput,
    RegistrationExtensions, RegistrationOptions,
};

// During registration, probe for PRF support
let mut extensions = RegistrationExtensions::default();
extensions.prf = Some(PrfInput::default());

let mut options = RegistrationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, options,
)?;
// Check client_extension_results.prf.enabled in the credential before calling finish
// to know whether the authenticator supports PRF

// During authentication, request a PRF derivation for a given context
let mut extensions = AuthenticationExtensions::default();
let mut prf = PrfInput::default();
prf.eval = Some(PrfEval {
    first: Passki::base64_encode(b"my-app-encryption-key-context"),
    second: None,
});
extensions.prf = Some(prf);

let mut options = AuthenticationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_authentication(&user_passkeys, options);

// result.prf_first contains the derived key bytes (32 bytes)
// The same passkey + same context always yields the same bytes
```

### largeBlob

The [`largeBlob` extension](https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension) stores
a small opaque blob on the authenticator itself, such as an SSH key or a certificate. Registration
only probes whether the credential can hold one; reads and writes happen in later authentication
ceremonies, one per ceremony, and a write replaces whatever the credential held.

The blob is base64url in both directions, like the PRF inputs and outputs: encode what you write,
and `AuthenticationResult::large_blob` hands back the decoded bytes.

```rust
use passki::{
    AuthenticationExtensions, AuthenticationOptions, LargeBlobAuthenticationInput,
    LargeBlobRegistrationInput, LargeBlobSupport, Passki, RegistrationExtensions,
    RegistrationOptions,
};

// During registration, ask for a credential that can store a blob
let mut extensions = RegistrationExtensions::default();
extensions.large_blob = Some(LargeBlobRegistrationInput {
    support: LargeBlobSupport::Preferred,
});

let mut options = RegistrationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, options,
)?;

let passkey = passki.finish_passkey_registration(&credential, &state)?;
// passkey.large_blob_supported == Some(true) → the credential can hold a blob
// Store it: the authenticator only reports this at registration

// During authentication, write a blob
let mut extensions = AuthenticationExtensions::default();
extensions.large_blob = Some(LargeBlobAuthenticationInput::Write(
    Passki::base64_encode(b"ssh-ed25519 AAAA..."),
));

let mut options = AuthenticationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_authentication(&user_passkeys, options);
// result.large_blob_written == Some(true) → the blob was stored

// A later ceremony reads it back
let mut extensions = AuthenticationExtensions::default();
extensions.large_blob = Some(LargeBlobAuthenticationInput::Read);
// result.large_blob contains the decoded bytes
```

`LargeBlobSupport::Required` fails the registration when the authenticator cannot store a blob;
`Preferred` creates the credential either way and reports what it got.

### credProtect

The [`credProtect`
extension](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension)
(CTAP 2.1 §12.1) sets when a credential on a security key may be used at all:

| Policy                                         | Without user verification, the credential is                  |
| ---------------------------------------------- | ------------------------------------------------------------- |
| `UserVerificationOptional`                     | usable, as with no policy                                     |
| `UserVerificationOptionalWithCredentialIdList` | usable only when named in `allowCredentials`, so not listable |
| `UserVerificationRequired`                     | unusable                                                      |

The authenticator reports the level it applied in the signed authenticator data, and only
at registration, so passki stores it in `StoredPasskey::cred_protect`. It may be stricter than
the one requested. Chrome asks for a level on its own when creating a discoverable credential
on a security key, so the field can be set even when you requested nothing.

```rust
use passki::{CredentialProtectionPolicy, RegistrationExtensions, RegistrationOptions};

let mut extensions = RegistrationExtensions::default();
extensions.credential_protection_policy =
    Some(CredentialProtectionPolicy::UserVerificationRequired);
extensions.enforce_credential_protection_policy = Some(true);

let mut options = RegistrationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, options,
)?;

let passkey = passki.finish_passkey_registration(&credential, &state)?;
// passkey.cred_protect == Some(UserVerificationRequired) → the authenticator applied it
// Store it: the authenticator only reports this at registration
```

With `enforce_credential_protection_policy` set, the browser should refuse to create
the credential with a weaker policy, and `finish_passkey_registration` checks it again: it returns
`PasskiError::CredentialProtectionNotApplied` when the authenticator reports a weaker level or none.
Authenticators that never report the extension, which can include platform passkeys, then cannot
register at all. Enforcing `UserVerificationOptional` has no effect, since every credential
satisfies it.

A passkey stored with `UserVerificationRequired` must carry the UV flag in every later
authentication. `finish_passkey_authentication` rejects one without it with
`PasskiError::UserVerificationRequired`, even when the ceremony asked only for `Preferred`.

### minPinLength

The [`minPinLength`
extension](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-minpinlength-extension)
(CTAP 2.1 §12.4) reports the shortest PIN a security key accepts, in Unicode code points.
The key answers only relying parties on a list configured into it, so this is for organizations
that provision their own keys and want to check the PIN policy still meets their requirements.
Any other relying party gets no answer.

```rust
use passki::{RegistrationExtensions, RegistrationOptions};

let mut extensions = RegistrationExtensions::default();
extensions.min_pin_length = Some(true);

let mut options = RegistrationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, options,
)?;

let passkey = passki.finish_passkey_registration(&credential, &state)?;
// passkey.min_pin_length == Some(8) → the key demands a PIN of at least 8 characters
// Store it: the authenticator only reports this at registration
```

The length is read from the signed authenticator data. It can only grow afterwards, until the key
is reset, which also wipes the credential.

## Related Origins

A passkey belongs to one `rp_id`, and browsers normally require the calling page's domain to match
it. Related origin requests lift that restriction for a fixed list of domains, so one credential
covers `example.com`, `example.co.uk` and `example.de` rather than making the user register once
per domain.

The browser does the checking. When a WebAuthn call arrives from an origin whose registrable domain
does not match the `rp_id`, it fetches `https://<rp_id>/.well-known/webauthn` and continues only
if the calling origin is listed there.

Browsers honour at most five distinct *labels* from that file, a label being the name before
the effective top level domain. So `example.com`, `example.co.uk` and `example.de` cost one label
between them and a country-domain rollout has room to spare, while five unrelated brand names
use up the budget.

The server does two things: list every origin when constructing `Passki`, and serve the file.

```rust
use passki::Passki;

let passki = Passki::new(
    "example.com",                                      // one rp_id for every domain
    &["https://example.com", "https://example.co.uk"],  // every origin allowed to call
    "Example Corp",
);

// Serve as application/json from https://example.com/.well-known/webauthn
let well_known = serde_json::to_string(&passki.related_origins())?;
// {"origins":["https://example.co.uk"]}
```

`https://example.com` is missing from that payload on purpose: the specification says to leave out
origins the `rp_id` already reaches, which is every origin on the `rp_id` host or a subdomain
of it. A relying party on a single domain therefore gets an empty list and needs no file at all.

Verification needs nothing special. Every ceremony carries the same `rp_id`, whichever domain
it came from, and Passki accepts any origin on the list - so a credential registered
on `example.co.uk` authenticates on `example.com`. Send the same `rp_id` in the challenge from
every domain; do not substitute the calling domain.

Build a `RelatedOrigins` directly if the published list should be narrower than the origins
the server accepts.

## Cross-origin Iframes

A page of yours embedded in an iframe on someone else's site may run a ceremony, so a checkout
widget or an embedded sign-in can use a passkey without a popup. Passki refuses this by default:
a frame on another site asking for a passkey is the shape of a clickjacking attack, where the user
believes they are confirming something else entirely.

Three parties have to agree before it works. The embedding page grants the frame
`publickey-credentials-get` or `publickey-credentials-create` through permissions policy, and
`create()` additionally needs the user to have interacted with the frame first:

```html
<iframe src="https://example.com/signin"
        allow="publickey-credentials-get https://example.com"></iframe>
```

The browser then writes `crossOrigin: true` and a `topOrigin` naming the embedding page into
the client data. And the server names the embedding origins it expects:

```rust
use passki::Passki;

let passki = Passki::new("example.com", &["https://example.com"], "Example Corp")
    .with_embedding_origins(&["https://partner.example"]);
```

That last step is the one that is yours to make. A permissions policy is the embedder's decision
alone, so any site that embeds you can grant itself the permission; only the `topOrigin` check says
whether you meant to be embedded there. Ceremonies from an iframe on any other site keep failing
with `CrossOriginNotAllowed` or `TopOriginMismatch`.

The frame's own origin is still checked against the origins given to `Passki::new`, exactly as for
a top-level page, and `ClientData::top_origin` carries the embedding origin if you want to log it
or vary what the ceremony is allowed to authorize.

`create()` in a cross-origin iframe is newer than `get()`: Chrome ships it, Firefox has it open,
so treat registration from a frame as the part to feature-detect.

## Signal API

Your database and the user's password manager drift apart: a passkey you deleted is still offered
at sign-in, a changed email still shows in the picker. Signals close that gap.

Passki only builds the payload - it sends nothing, and there is no endpoint to add. Two hops carry
it the rest of the way:

1. **Server to page.** Put the payload in the response body the ceremony already returns.
2. **Page to browser.** The page passes it to the matching `PublicKeyCredential` method. That is
   a browser API, like `navigator.credentials.get()`, not a request to your server: the browser
   updates the passkeys held on that device, and nothing comes back.

| Build one when                                            | The page calls                   | The passkey store then                    |
| --------------------------------------------------------- | -------------------------------- | ----------------------------------------- |
| A sign-in offered a credential missing from your database | `signalUnknownCredential()`      | hides that passkey                        |
| A sign-in succeeded, or the user's passkeys changed       | `signalAllAcceptedCredentials()` | hides every passkey missing from the list |
| The username or display name changed                      | `signalCurrentUserDetails()`     | relabels the account in the picker        |

Every signal pushes server state outward. Nothing reports the other direction: when a user deletes
a passkey in their password manager, your database is not told, and the first signal above is for
the opposite case - the device still holds a passkey your database has lost.

```rust
// Hop 1, on the server: build a payload and return it with whatever the handler already sends.
let signal = passki.signal_unknown_credential(&credential_id);
let signal = passki.signal_all_accepted_credentials(user_id, &user_passkeys);
let signal = passki.signal_current_user_details(user_id, "alice@example.com", "Alice Smith");
```

```js
// Hop 2, on the page: read that same response, hand the payload to the browser.
const result = await finishRes.json();
await PublicKeyCredential.signalAllAcceptedCredentials?.(
    result.signals.all_accepted_credentials,
);
```

The payload's own keys - `rpId`, `allAcceptedCredentialIds` and the rest - are the ones the browser
requires, so pass the object through untouched. What you file it under in your response is yours
to name; the examples collect up to three of them in a `signals` object.

Give `signal_all_accepted_credentials` every passkey the user still has: whatever the list omits
gets hidden, so an empty list hides all of them. It also reveals how many passkeys the account has,
so return it only to that user, signed in. `signal_unknown_credential` names nobody, which is what
makes it safe on a failed sign-in.

Signals are advisory. Firefox implements none of these methods and Google Password Manager keeps
names the user edited themselves, so feature-detect every call and never fail a sign-in over one.

## Attestation

Attestation is the authenticator proving its make and model - "genuine YubiKey 5 NFC" rather than
"some passkey". Skip this section unless your policy depends on the hardware; most applications
accept any passkey, and the defaults are already right for that.

### Why the AAGUID needs it

By default the AAGUID is self-asserted. It comes out of `authData`, which the client controls.
A malicious client can claim any AAGUID and mint an attestation certificate to match, and every
check Passki performs by default will pass - those checks verify the statement against
the certificate the statement itself supplied, which settles internal consistency and nothing else.

Trust path validation closes the gap: the `x5c` chain is validated against root certificates
you supply out of band. Same shape as TLS - the peer sends leaf and intermediates, you hold
the roots.

Two things are needed, and either one alone is useless:

1. `AttestationConveyancePreference::Direct`, so the browser sends a statement at all
2. `Passki::with_attestation_trust`, so there is something to validate it against

### Setup

```rust
use passki::{
    AttestationConveyancePreference, AttestationTrustPolicy, AttestationType, Passki,
    RegistrationOptions,
};

const YUBICO_ROOT: &[u8] = include_bytes!("../roots/yubico-u2f-root.der");

let passki = Passki::new("example.com", &["https://example.com"], "Example Corp")
    .with_attestation_trust(&[YUBICO_ROOT], AttestationTrustPolicy::VerifyWhenPresent)?;

let mut options = RegistrationOptions::default();
options.attestation = AttestationConveyancePreference::Direct;

let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, options,
)?;
```

Requesting attestation makes some browsers show the user an extra consent prompt.

### Result

`finish_passkey_registration` either fails, or returns a `StoredPasskey` whose `attestation_type`
records what the statement was worth:

```rust
let passkey = passki.finish_passkey_registration(&credential, &state)?;

match passkey.attestation_type {
    AttestationType::Basic | AttestationType::AttCa => allow_model(passkey.aaguid),
    _ => treat_as_unattested(),
}
```

| `attestation_type` | Meaning                                                                       |
| ------------------ | ----------------------------------------------------------------------------- |
| `None`             | `fmt` was `none`. No statement to assess.                                     |
| `SelfAttested`     | The credential key signed its own statement. Proves possession, not model.    |
| `Unverified`       | An `x5c` chain arrived but the policy is `Ignore`, so it was never validated. |
| `Basic` or `AttCa` | The chain validated up to one of your roots. `aaguid` is attested.            |

`Basic` and `AttCa` differ in whether the vendor issues one certificate per production batch
or one per device. Both mean the chain validated, so treat them alike.

### Policies

| Policy              | Statement with `x5c` (security key)               | Statement without `x5c` (synced passkey) |
| ------------------- | ------------------------------------------------- | ---------------------------------------- |
| `Ignore` (default)  | Accepted as `Unverified`                          | Accepted                                 |
| `VerifyWhenPresent` | Must chain to a root, else `UntrustedAttestation` | Accepted                                 |
| `Required`          | Must chain to a root, else `UntrustedAttestation` | `MissingAttestationChain`                |

`Ignore` preserves pre-0.3 behaviour exactly. `Required` is effectively "security keys only": iCloud
Keychain, Google Password Manager and 1Password return `none` attestation regardless of what
is requested, so it excludes every phone and laptop passkey.

Anchors act as a vendor whitelist. Install only the Yubico root and a genuine Feitian
key is rejected, because its chain ends at a root you do not have.

### Trust anchors

Anchors are DER root certificates you supply. Passki bundles none and performs no network I/O.

For a fixed set of approved models, embed the vendor roots with `include_bytes!`. For broad coverage
there is the FIDO Metadata Service, which publishes roots for every certified
authenticator - but consuming it means fetching and verifying a signed JWT on a refresh schedule,
which belongs in your application rather than in this crate.

### What validation covers

Name chaining, the signature of every link, `notBefore`/`notAfter`, `basicConstraints` (CA flag
and `pathLenConstraint`), and `keyUsage`/`keyCertSign` when present. An anchor is trusted
by configuration, so its own validity period is not re-checked.

Revocation is not checked: attestation chains have no CRL or OCSP to consult. Certificate signatures
are supported for ECDSA P-256/P-384 with SHA-256/384, RSA PKCS#1 v1.5 with SHA-256/384, and Ed25519;
RSASSA-PSS is not.

## Security Considerations

- 🔒 **Always use HTTPS in production** - browsers refuse WebAuthn on insecure origins
- 🔄 **Store the counter** returned by each authentication, or cloned authenticators go undetected
- 🔐 **Require user verification** for sensitive operations
- ⏱️ **Keep ceremony timeouts short**; the state stored between the two steps expires with them
- 🖼️ **Cross-origin ceremonies are refused by default**; a `crossOrigin` client data flag fails
  verification unless the embedding origin is on the allowlist you install with
  `with_embedding_origins`

## Requirements

- Rust 1.85 or later (Edition 2024)
- HTTPS in production (required by WebAuthn specification)

## Examples

The `examples/` directory has complete registration and authentication flows for several
web frameworks: [Actix-web](examples/actix-web.rs) | [Axum](examples/axum.rs)
| [Poem](examples/poem.rs)
| [Rocket](examples/rocket.rs) | [Warp](examples/warp.rs)

All examples request both `credProps` and PRF during registration. Registration reports whether
a resident key was created; authentication accepts an optional key context string (`prf_salt`)
to derive a 32-byte key.

They also demonstrate the Signal API. Registration and a successful sign-in return the account's
current passkey list and display name; a sign-in with a credential the server does not hold answers
with the unknown-credential signal instead, which is what a stale passkey in the browser's picker
looks like. The page feature-detects each `PublicKeyCredential.signal*` method, since Firefox has
none of them.

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
- [ ] `RegistrationResponseJSON` and `AuthenticationResponseJSON` request shapes
- [x] Signal API
- [ ] `hints` (`security-key` / `client-device` / `hybrid`)
- [ ] `attestationFormats`
- [ ] `evalByCredential` in the `prf` extension
- [ ] `authenticatorDisplayName` in the `credProps` extension
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [Apache License, Version
2.0](http://www.apache.org/licenses/LICENSE-2.0) ([LICENSE](LICENSE)).

## Acknowledgments

Passki is built on top of [aws-lc-rs](https://github.com/aws/aws-lc-rs) for cryptographic
operations.

## Resources

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-3/)
- [FIDO Alliance](https://fidoalliance.org/)
- [WebAuthn Guide](https://webauthn.guide/)
