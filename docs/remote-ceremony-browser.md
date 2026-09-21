# Broker remote ceremony browser contract

Broker reuses its existing `CeremonyBroker` store, Signer client, review manifest,
Axum handlers, admission limits, and adoption path. The remote router is a view
of that same store, attached only to Broker's fixed loopback TLS upstream
`127.0.0.1:18735`. `axum-server`/rustls provides TLS serving; the relay client
forwards opaque Browser TLS to this upstream. Bloom-specific code selects the
exact Signer-approved surface, exchanges one-use launch authority, scopes a
cookie to one ceremony, and reports readiness. No relay input selects an
upstream or wallet operation.

The versioned surface identity and digest belong to `bloom-signer-api`:
`SHA-256("bloom.surface.identity.v1\0" || JCS(SurfaceIdentity))`. Broker treats
the Signer descriptor as authority. A Machine caller may select `local`; the
default resolves to the assigned remote surface only when Signer reports the
same desired/effective revision, ACTIVE lifecycle, valid TLS and routing
readiness. Before any remote identity is assigned, existing local entrypoints
remain usable and the exposure status reports provisioning pending. Once a
remote identity is assigned, an outage fails default preparation with a
retryable error; callers must explicitly select `local` to change origin.
A Signer state change is checked again at ceremony completion.

The remote launch URL is `https://<assigned-host>/ceremony/#cap=<43-character base64url
capability>`. The capability is 32 random bytes. The first-party page removes
the fragment from visible history before network requests, POSTs it to
`/api/session/exchange`, then discards it. Broker stores its SHA-256 verifier,
consumes it once and issues a distinct 32-byte host-only
`__Host-bloom-ceremony-<ceremony-id>` cookie. Cookies are `Secure; HttpOnly;
SameSite=Strict; Path=/` and expire after at most 25 minutes. Server admission
still enforces the absolute five-minute precommit deadline, then retains only
the original recipient's result verifier for at most 15 minutes. Each exchange
also returns a random CSRF proof held in tab memory. Mutations require that
proof, exact Host/Origin, same-origin Fetch Metadata and JSON content type.
All result, acknowledgement and cancellation reads/mutations are scoped to
the matching ceremony cookie. Two concurrent tabs use different cookie names.
The local HTTP ceremony retains its existing token path and header mechanism.

The staged `/.well-known/bloom/relay-health` endpoint returns 204 only on the
remote TLS router with an exact Host. It carries no wallet data and does not
mark the remote surface ACTIVE. Readiness requires the relay client to hold an
authenticated tunnel and an external HTTPS probe of that exact hostname with
ordinary CA verification; Broker then reports the current desired revision to
Signer over its existing authenticated edge. Without a valid certificate or
routing proof, remote commits remain disabled.

Broker owns its production ACME account and key, the hostname certificate and
private key, and renewal. Its `instant-acme` client orders only the exact
Signer-assigned hostname. The relay's scoped DNS client can lease only that
installation's `_acme-challenge` TXT owner; it cannot request another record.
The account URI is published privately under the Broker config directory so
the privileged Signer admin can bind it to the relay before DNS publication.
Account creation starts after assignment even if the administrator has chosen
localhost-only exposure; in that mode no tunnel or remote listener opens and
Broker does not order a hostname certificate.
Broker waits for DNS lease readiness, finalizes the order, checks SAN,
validity, and cert/key match, and reports public certificate metadata for relay
CT comparison. A mismatched pair fails closed. The certificate and private key
are published together as one
owner-only `relay-tls-bundle.json`; failed renewal leaves the previous valid
bundle untouched. Initial tunnel and DNS bearer files and the pinned control
CA are handed off by the
privileged Signer admin; Broker renews each using its scoped token with a
durable operation ID and protected pending replacement. No recurring admin
key use is required. Failure leaves the hosted surface pending or degraded
while explicit local ceremonies remain available.

Cross-surface passkey enrollment uses Signer's four typed two-leg operations.
Broker creates a destination session and an auxiliary source session on the
opposite Signer-approved origin. The source passkey authorizes the exact wallet,
operation, terms, and destination; Signer encrypts a one-use handoff to the
destination tab's pre-registered HPKE key. Destination enrollment requires its
own fresh passkey attestation and PRF assertion. Broker stores neither WKEK nor
the handoff plaintext and returns only Signer's signed final receipt.

The bare `/` route serves only a concise Bloom Broker identification with links
to the website and docs. `neutral_landing_enabled` defaults to true in protected
Broker configuration; false makes `/` return an empty 404. The dedicated
`/ceremony/` route serves remote launches and tab reloads independently; local
launches still use `/ceremony/{token}` and resume at `/ceremony/`. The public recovery
bootstrap endpoint has been removed. Machine starts recovery over its
authenticated Broker edge, and the browser supplies the recovery ID and secret
only inside HPKE input to Signer. The relay gateway admits at most 120 new
browser TLS connections per source IP and 5,000 globally per fixed minute,
before ClientHello parsing, because opaque TLS hides that address from Broker.
Broker ignores untrusted forwarding headers.

Custom code here is limited to Bloom's session binding and lifecycle. The
existing Broker HTTP parser and state machine, rustls TLS, Signer WebAuthn and
HPKE verification, and relay h2 client provide the general infrastructure.
No custom TLS, HTTP/2 framing, certificate parser, WebAuthn verifier, or
cryptographic algorithm is used.
