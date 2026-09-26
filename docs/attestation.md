# Attestation

Attestation is the authenticator proving its make and model - "genuine YubiKey 5 NFC" rather than
"some passkey". Skip this page unless your policy depends on the hardware; most applications
accept any passkey, and the defaults are already right for that.

## AAGUID

`StoredPasskey::aaguid` is the 16-byte identifier of the authenticator model - which YubiKey, which
password manager. Look it up in the [FIDO Metadata Service](https://fidoalliance.org/metadata/)
or a community AAGUID list.

All zero is the common case, and means there is no model to look up: under the default
`AttestationConveyancePreference::None` the browser zeroes the AAGUID before passing the credential
on. A non-zero value is worth acting on only once it has been validated, which is what
[Setup](#setup) configures.

The same `StoredPasskey` also carries `be` (backup eligible - the credential is synced rather than
bound to one device) and `bs` (currently backed up), both straight from the authenticator data
flags.

## Why the AAGUID needs it

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

## Setup

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

## Result

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

## Policies

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

## Trust anchors

Anchors are DER root certificates you supply. Passki bundles none and performs no network I/O.

For a fixed set of approved models, embed the vendor roots with `include_bytes!`. For broad coverage
there is the FIDO Metadata Service, which publishes roots for every certified
authenticator - but consuming it means fetching and verifying a signed JWT on a refresh schedule,
which belongs in your application rather than in this crate.

## What validation covers

Name chaining, the signature of every link, `notBefore`/`notAfter`, `basicConstraints` (CA flag
and `pathLenConstraint`), and `keyUsage`/`keyCertSign` when present. An anchor is trusted
by configuration, so its own validity period is not re-checked.

Revocation is not checked: attestation chains have no CRL or OCSP to consult. Certificate signatures
are supported for ECDSA P-256/P-384 with SHA-256/384, RSA PKCS#1 v1.5 with SHA-256/384, and Ed25519;
RSASSA-PSS is not.
