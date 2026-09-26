# Related Origins

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
