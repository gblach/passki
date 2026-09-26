# Signal API

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
