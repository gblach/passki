# Hints

Hints say which kind of authenticator you expect, so the browser can skip the choices that will not
apply - opening the security key prompt directly instead of offering a QR code first. They are
advisory: a browser may ignore them, and a user holding a different authenticator can still
register or sign in with it.

```rust
use passki::{PublicKeyCredentialHint, RegistrationOptions};

let mut options = RegistrationOptions::default();
options.hints = vec![PublicKeyCredentialHint::SecurityKey];

let (challenge, state) = passki.start_passkey_registration(
    user_id, username, display_name, options,
)?;
```

`AuthenticationOptions` carries the same field. List the hints most preferred first; an empty list
sends no preference at all.

| Hint           | Steers the UI toward                                           |
| -------------- | -------------------------------------------------------------- |
| `SecurityKey`  | a separate portable authenticator, over USB or NFC             |
| `ClientDevice` | the authenticator built into the device the user is already on |
| `Hybrid`       | a phone or tablet, reached over Bluetooth and the network      |

Prefer hints to `authenticator_attachment`. That one is a filter the client cannot ignore, and
where the two disagree it wins, leaving the hint with nothing to do.

**Browser support**: Chrome and Edge 128+. Safari has stated intent, Firefox has given no timeline.
Windows 11 ignores hints outright, because Windows Hello owns the passkey UI, so Chrome on Windows
does not honour them either.
