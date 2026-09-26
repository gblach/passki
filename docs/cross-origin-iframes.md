# Cross-origin Iframes

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
