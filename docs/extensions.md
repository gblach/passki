# Extensions

## credProps

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

## PRF

The [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) lets a passkey derive
deterministic secret bytes from the authenticator's internal HMAC-secret. This is useful
for end-to-end encryption, per-user key derivation, and other scenarios where you need a stable
secret tied to a specific passkey. Passki passes the outputs through without processing them.

```rust
use passki::{
    AuthenticationExtensions, AuthenticationOptions, Passki, PrfAuthenticationInput, PrfEval,
    PrfRegistrationInput, RegistrationExtensions, RegistrationOptions,
};

// During registration, probe for PRF support
let mut extensions = RegistrationExtensions::default();
extensions.prf = Some(PrfRegistrationInput::default());

let mut options = RegistrationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, options,
)?;
// Check client_extension_results.prf.enabled in the credential before calling finish
// to know whether the authenticator supports PRF

// During authentication, request a PRF derivation for a given context
let mut extensions = AuthenticationExtensions::default();
let mut prf = PrfAuthenticationInput::default();
prf.eval = Some(PrfEval {
    first: Passki::base64_encode(b"my-app-encryption-key-context"),
    second: None,
});
extensions.prf = Some(prf);

let mut options = AuthenticationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_authentication(&user_passkeys, options)?;

// result.prf_first contains the derived key bytes (32 bytes)
// The same passkey + same context always yields the same bytes
```

A user with passkeys on several devices gets several credentials in `allowCredentials`, and `eval`
alone cannot say which input belongs to which. `eval_by_credential` maps a credential ID to its own
inputs; the entry naming the credential the user picks wins, and a credential with no entry falls
back to `eval`.

```rust
use passki::{
    AuthenticationExtensions, AuthenticationOptions, Passki, PrfAuthenticationInput, PrfEval,
};

// salt_for is your own lookup: the context this credential's data was encrypted under.
let mut prf = PrfAuthenticationInput::default();
prf.eval_by_credential = user_passkeys
    .iter()
    .map(|passkey| {
        let eval = PrfEval {
            first: Passki::base64_encode(&salt_for(&passkey.credential_id)),
            second: None,
        };
        (Passki::base64_encode(&passkey.credential_id), eval)
    })
    .collect();

let mut extensions = AuthenticationExtensions::default();
extensions.prf = Some(prf);

let mut options = AuthenticationOptions::default();
options.extensions = Some(extensions);

let (challenge, state) = passki.start_passkey_authentication(&user_passkeys, options)?;
```

Keys are base64url credential IDs, as `Passki::base64_encode` produces them, and each one must name
a credential in the same `passkeys` list. `start_passkey_authentication` returns
`PrfEvalByCredentialUnknownKey` for a key that names no offered credential and
`PrfEvalByCredentialWithoutAllowCredentials` when the list is empty, which is what the client
would refuse to run. The spec's third rule needs no check: `RegistrationExtensions` takes
`PrfRegistrationInput`, which has no `eval_by_credential` to set.

**Browser support**: PRF itself is Chrome 132+ and Safari 18+. Support for this member specifically
was not confirmed against a real authenticator, so check the outputs before relying on it.

## largeBlob

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

let (challenge, state) = passki.start_passkey_authentication(&user_passkeys, options)?;
// result.large_blob_written == Some(true) → the blob was stored

// A later ceremony reads it back
let mut extensions = AuthenticationExtensions::default();
extensions.large_blob = Some(LargeBlobAuthenticationInput::Read);
// result.large_blob contains the decoded bytes
```

`LargeBlobSupport::Required` fails the registration when the authenticator cannot store a blob;
`Preferred` creates the credential either way and reports what it got.

## credProtect

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

## minPinLength

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
