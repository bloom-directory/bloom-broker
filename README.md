# bloom-broker

Bloom's approval, policy, declared-usage accounting, and ceremony boundary.

## The Broker configuration file

Broker reads one JSON file at startup. It defaults to `/etc/bloom/broker.json`;
`BLOOM_BROKER_CONFIG` selects another path.

`load_config` refuses the file unless it is a **regular file**, **not a
symlink**, and has **no group or other permission bits** — mode `0600` or
stricter. Anything else fails startup before the contents are read, because the
file carries signing seeds. Ownership is not checked, so keeping the file owned
by the account Broker runs as is an operator responsibility, not something
startup enforces. Unknown fields are rejected, and the seed strings are zeroized
once they have been turned into keys.

Every field is required unless called out as optional below, and fields marked
**secret** are private key material: never log them, never place them in a
process environment, and never let a backup or copy widen the file's mode.
Conventions used throughout: a *key ID* is a 1–64 byte lowercase ASCII token, a
*seed* is a 32-byte Ed25519 seed as 64 lowercase hex characters, and a *public
key* is a canonical 32-byte Ed25519 key as 64 lowercase hex characters.

### Paths

| Field | Meaning |
| --- | --- |
| `journal_path` | Broker's durable audit journal (SQLite). |
| `authority_path` | Durable authority state: approvals, policy, declared usage. |
| `ceremony_path` | Durable ceremony state. |
| `signer_socket_path` | Unix socket Broker dials to reach Signer; the peer is still authenticated against the edge-manifest pin. |
| `provenance_catalog_path` | Provenance catalog. Its metadata must describe a root-owned, non-symlink regular file that is not group- or other-writable; link count and size are not part of that check. The contents are then read and refused if they exceed 1 MiB, fail to parse, or fail shape validation. |

### Key material Broker signs with

| Field | Meaning |
| --- | --- |
| `broker_signing_key_id` | Key ID of the key Broker signs its responses with. |
| `broker_signing_seed_hex` | **Secret.** Seed for that key. |
| `audit_key_id` | Key ID of the current audit-journal signing key. |
| `audit_signing_seed_hex` | **Secret.** Seed for that key. |
| `review_manifest_key_id` | Key ID of the ceremony review-manifest signing key. |
| `review_manifest_signing_seed_hex` | **Secret.** Seed for that key. |
| `audit_rotation_previous_key` | Optional object `{ "key_id", "signing_seed_hex" }` — **secret**. Present only while rotating: it lets Broker open a journal still signed by the previous key and roll it forward to `audit_key_id`. Its key ID must differ from `audit_key_id`. |
| `audit_historical_public_keys` | Optional array of `{ "key_id", "public_key_hex" }`. Retired audit **public** keys retained so older journal entries still verify. Reusing one key ID for two different keys fails startup. |

### Trust and identity Broker pins

These are public values Broker verifies against; none of them is secret.

| Field | Meaning |
| --- | --- |
| `installer_key_id`, `installer_public_key_hex` | The installer key whose statements Broker accepts. |
| `signer_ceremony_key_id`, `signer_ceremony_public_key_hex` | Signer's ceremony key. |
| `signer_revocation_key_id`, `signer_revocation_public_key_hex` | Signer's revocation key. |
| `build_digest` | SHA-256 of the running build, 64 lowercase hex characters. Reported in readiness and bound into the network-containment attestation. |

### Policy

| Field | Meaning |
| --- | --- |
| `policy_keys` | Array of `{ "wallet_id", "key_id", "public_key_hex" }`, one entry per wallet whose policy updates Broker will verify. May be empty. |
| `ceremony_limits` | Optional object; see [Configuring ceremony admission limits](#configuring-ceremony-admission-limits). Omitted, the compiled defaults apply. |

### Connection, request, and journal controls

Broker serves two endpoints with independent quotas: the Machine RPC endpoint,
and the control endpoint used by the revoke client. The control endpoint's
fields are the same six under a `control_` prefix.

| Field | Meaning |
| --- | --- |
| `maximum_connections` | Connections accepted concurrently. |
| `maximum_in_flight_mutations` | Mutating requests in flight at once; exhaustion returns `QUOTA_EXCEEDED`. |
| `maximum_requests_per_window` | Requests admitted per rolling window. |
| `request_window_ms` | Length of that window, in milliseconds. |
| `maximum_journal_admissions_per_window` | Journal-writing admissions per rolling window. |
| `journal_window_ms` | Length of that window, in milliseconds. |
| `control_maximum_connections`, `control_maximum_in_flight_mutations`, `control_maximum_requests_per_window`, `control_request_window_ms`, `control_maximum_journal_admissions_per_window`, `control_journal_window_ms` | The same six controls for the control endpoint. |

All twelve are required and must be nonzero; a zero fails startup rather than
opening an unmetered endpoint. Unlike `ceremony_limits`, they have **no
compiled defaults** — the deployment's configuration file is the only source,
so size them for the host rather than copying values from another deployment.

### Optional network containment

Omit `network_containment` entirely to run without a containment guard. When
present, all three fields are required:

| Field | Meaning |
| --- | --- |
| `status_path` | Path to the containment attestation Broker reads. |
| `login_uid` | UID the attestation must name; must be nonzero. |
| `maximum_age_ms` | Maximum accepted age of the attestation, in milliseconds; must be nonzero. |

Broker accepts the attestation only if it is a non-symlink regular file owned by
root with mode `0644` and a single link, is no older than `maximum_age_ms`,
and matches the configured `login_uid` and `build_digest`. While it does not
validate, preparation, signing, and policy-commit requests are refused and
readiness reports `network_containment_unavailable`; read-only methods are
unaffected.

### Path environment variables

These select paths and activation names only. No environment variable can
introduce or replace key material, and only `ceremony_limits` is configurable
from the environment.

| Variable | Default |
| --- | --- |
| `BLOOM_BROKER_CONFIG` | `/etc/bloom/broker.json` |
| `BLOOM_BROKER_IDENTITY` | `/var/run/bloom/broker-identity.json` |
| `BLOOM_EDGE_MANIFEST` | `/etc/bloom/edge-manifest.json` |
| `BLOOM_AUTHORITY_EDGE_HISTORY` | `/etc/bloom/authority-edge-history.json` |
| `BLOOM_BROKER_AUDIT_CHECKPOINT_DIR` | `/var/db/bloom/broker/audit-checkpoints` |
| `BLOOM_BROKER_RELAY_STATE_DIR` | Broker configuration directory; when `remote_tls` is omitted, selects the directory for the relay TLS bundle, control CA, and tunnel/DNS credentials. Must be absolute. |
| `BLOOM_SESSION_SOCKET` | `/var/run/bloom/session/session.sock` |
| `BLOOM_BROKER_SOCKET`, `BLOOM_BROKER_CONTROL_SOCKET` | No default; both are required by the service profile. |
| `BLOOM_BROKER_STARTUP_STATUS` | No default; when set, Broker writes a startup-conflict diagnostic there. |
| `BLOOM_BROKER_CEREMONY_ACTIVATION_NAME` | `broker-ceremony` (non-macOS; macOS binds the canonical ceremony listener). |

## Configuring ceremony admission limits

Broker's four global ceremony admission limits are non-secret and configurable
per deployment. They are one policy for the whole process: nothing is selected
per wallet or per ceremony kind, so no request can widen the quota that judges
it. Values are merged and validated *before* any durable state is opened, so a
mistyped quota fails startup instead of silently widening admission, and the
effective policy is printed at startup.

Precedence is compiled defaults, then the `ceremony_limits` object in the
Broker configuration file, then environment overrides. Every key is optional at
each layer; unmentioned keys keep the value from the layer below.

| `ceremony_limits` key | Environment override | Default | Meaning |
| --- | --- | --- | --- |
| `maximum_concurrent_sessions` | `BLOOM_BROKER_CEREMONY_LIMITS__MAXIMUM_CONCURRENT_SESSIONS` | `16` | Simultaneously live ceremony sessions (1–1024). |
| `creation_window_ms` | `BLOOM_BROKER_CEREMONY_LIMITS__CREATION_WINDOW_MS` | `300000` | Rolling window shared by both creation quotas, in ms (1–86400000). |
| `maximum_creations_per_wallet` | `BLOOM_BROKER_CEREMONY_LIMITS__MAXIMUM_CREATIONS_PER_WALLET` | `12` | Authenticated creations per wallet per window (1–1024). |
| `maximum_anonymous_registrations` | `BLOOM_BROKER_CEREMONY_LIMITS__MAXIMUM_ANONYMOUS_REGISTRATIONS` | `4` | Unauthenticated wallet registrations per window (1–1024). |

```json
{
  "ceremony_limits": {
    "maximum_concurrent_sessions": 16,
    "creation_window_ms": 300000,
    "maximum_creations_per_wallet": 12,
    "maximum_anonymous_registrations": 4
  }
}
```

### Changing limits safely

For a durable deployment change, edit the protected configuration file and
restart Broker through the deployment's service manager. Do not rewrite any of
the secret fields while changing this object.

```sh
CONFIG=/etc/bloom/broker.json       # or the path selected by BLOOM_BROKER_CONFIG
cp -p "$CONFIG" "${CONFIG}.bak"    # retain the protected backup mode
${EDITOR:-vi} "$CONFIG"            # replace or add only the ceremony_limits object
chmod 600 "$CONFIG"
stat -c '%a %F' "$CONFIG"          # expected: 600 regular file
# Restart the Broker with this deployment's service manager, then inspect its startup log.
# It prints: Bloom Broker ceremony admission limits: ...
```

Broker reads configuration at startup, so an edit alone changes nothing until
the process restarts. A malformed object, unknown key, zero, or out-of-range
value fails startup rather than changing admission behavior silently. Keep the
old process and the protected backup available until the restarted process has
logged its effective values successfully.

For a temporary launch-only override, set the relevant variables in the
environment of the Broker process. These do not modify the JSON file and are
lost at the next launch unless the service configuration supplies them again:

```sh
BLOOM_BROKER_CEREMONY_LIMITS__MAXIMUM_CREATIONS_PER_WALLET=6 \
BLOOM_BROKER_CEREMONY_LIMITS__CREATION_WINDOW_MS=60000 \
bloom-broker
```

For example, a one-off concurrency cap is:

```sh
BLOOM_BROKER_CEREMONY_LIMITS__MAXIMUM_CONCURRENT_SESSIONS=8 bloom-broker
```

The prefix is separated by a single underscore and nested keys by a doubled
one, so existing `BLOOM_BROKER_*` variables keep their spelling. Zero,
out-of-range, unparsable, and unknown keys are all refused at startup with an
error naming the field and its override. Only `ceremony_limits` is merged this
way: the rest of the configuration file carries signing seeds and keeps its
direct, zeroized decode path, so no environment variable can introduce or
replace key material.

### Retry contract

A creation refused by a **rolling** quota returns `CEREMONY_RATE_LIMITED` with
structured `rate_limit` metadata:

```json
{
  "code": "CEREMONY_RATE_LIMITED",
  "message": "wallet ceremony rolling creation quota is exhausted",
  "rate_limit": { "retry_after_ms": 61000, "limit": 12, "window_ms": 300000 }
}
```

`limit` and `window_ms` are the effective values of the quota class that
rejected the request; `retry_after_ms` is the exact wait until the creation
whose expiry frees the next slot leaves the window, so waiting it out is sufficient
and callers need no extra margin. Callers wait and retry the **same** operation
identity — never parse the message, and never invent a replacement operation.
The field is refused if it appears on any other code or carries values outside
its own window.

Each wallet permits one live ceremony. Petals and agents must finish or cancel
an approval ceremony before requesting the next route ceremony. An overlapping
request returns `CEREMONY_RATE_LIMITED`; its `retry_after_ms` is the remaining
lifetime of the live ceremony. Completion can free the slot earlier. Preserve
the operation identity when retrying and do not busy-loop on this error.

Global concurrency exhaustion is a different class: it returns `QUOTA_EXCEEDED` with
**no** retry hint, because nothing ages out on a schedule — only when a live
ceremony ends.

### Why `rate_limit` needs protocol 1.4

`rate_limit` is an optional field, but it could not be added under 1.3, because
every decoder in this protocol is **strict**: an unknown field fails the whole
frame rather than being ignored. A 1.3 peer handed a `CEREMONY_RATE_LIMITED`
carrying `rate_limit` would reject the entire error instead of reading the retry
hint inside it — turning a routine, retryable rejection into an unreadable one.

There is no way to make that safe by omitting the field selectively, so the
negotiated range moves as a unit instead. Broker accepts **1.4 only**
(`BROKER_API_MINOR_MIN == BROKER_API_MINOR_MAX == 4`), which means:

- A **1.3 peer is rejected during the hello**, with `UNSUPPORTED_VERSION`,
  before any request is served and before any durable work is done. It never
  reaches a point where a response could carry `rate_limit`.
- Consequently no *accepted* peer can be handed a field its decoder would
  refuse — the version gate, not per-response suppression, is what upholds this.

Upgrading a 1.3 Machine is therefore required, not optional; a 1.3 peer does not
degrade to a subset of functionality, it fails to connect at all.

## Opt-in ACME staging lifecycle probe

The ignored `remote_material::tests::letsencrypt_staging_issuance_and_renewal`
test exercises Broker's real DNS-01 issuance and atomic renewal path against a
disposable Relay allocation and Let's Encrypt staging. It does not start Broker,
Signer, Machine, or an installed Triad, and it does not bind a local ceremony
port. The allocation is permanently tombstoned when the test retires it.

Run it only against a reviewed disposable Relay deployment configured to accept
Let's Encrypt staging account URIs, with public enrollment temporarily admitting
the runner and both serving and challenge DNS workers healthy. The two input
files must be regular owner-only files: the pinned Relay control CA PEM and the
Relay receipt verification key as 64 lowercase hexadecimal characters.

```sh
BLOOM_BROKER_ACME_STAGING_SMOKE=1 \
BLOOM_RELAY_SMOKE_CONTROL_CA_FILE=/restricted/control-ca.pem \
BLOOM_RELAY_SMOKE_RECEIPT_PUBLIC_KEY_FILE=/restricted/receipt-public-key.hex \
cargo test -p bloom-broker --bin bloom-broker --locked \
  remote_material::tests::letsencrypt_staging_issuance_and_renewal \
  -- --ignored --exact --nocapture
```

The test creates the ACME account and all private material in a mode `0700`
temporary directory, publishes only the account URI and certificate metadata,
forces a second order through a private test-only renewal threshold, and attempts
signed retirement after success, failure, or a handled Ctrl-C. Let's Encrypt's
[staging environment](https://letsencrypt.org/docs/staging-environment/) uses
separate accounts and untrusted test roots. The probe checks the staging account
URI and issuer and never installs those roots into a system or application trust
store. Abrupt process termination can prevent immediate retirement; DNS leases
remain bounded by Relay expiry. Before concluding an interrupted run, the operator
must verify signed retirement, DNS cleanup, and the permanent hostname tombstone.

## Local wallet onboarding

After registration, the local browser shows the wallet name, initial EVM and
Solana account addresses, copy controls and a separate **Back up wallet** action.
**Later** returns to the persistent `/wallet/<wallet-id>` page without claiming
a backup was made. Bookmark that page to revisit addresses and backup after the
registration capability has been consumed. It also works for already-created
BIP-39 wallets on this host.

The local wallet API exposes public account projections for an exact wallet ID;
it does not list wallets or return secret material. It requires the configured
localhost Host and same-origin Fetch Metadata. Preparing backup additionally
requires the exact Origin and JSON content type. Hosted listeners reject these
owner-page routes; a persistent authenticated hosted-wallet UI remains outside
this local flow. Ceremony capabilities and terminal invalidation are unchanged.

**Back up wallet** prepares the existing wallet-export ceremony. Signer requires
a fresh passkey proof; registration approval cannot export a phrase. Pending
backup requests resume on repeat clicks; cancellation allows a new request after
the existing cooldown. The recovery phrase restores the wallet in compatible
wallet software, while the passkey authorizes operations in Bloom. Neither
viewing a phrase nor returning to the wallet establishes that a backup was saved.

`scripts/test-wallet-onboarding.mjs` runs create → addresses → Later/refresh →
backup/cancel → fresh backup approval → return against a running isolated Triad
with a Chromium virtual passkey. It captures only address and pre-export review
screens. It never records video/traces, reads phrase text, logs it or screenshots
it. Required environment inputs are listed at the top of the script; do not run
against custody or a production wallet. The service test independently covers
the real Signer registration/export path and local-origin/body boundaries.

## Durable-clock recovery and repair

Broker's approval and ceremony lifetimes are measured against a durable clock,
so it will not issue or honour them while that clock is untrusted. Linux always
rejects rollback below the persisted effective-time floor. Within one confirmed
boot it also rejects an unexplained wall-clock step beyond the compiled limit
by comparing it with a persisted, suspend-aware monotonic anchor.

A **process stop, crash, or restart** recovers automatically. The absolute
monotonic anchor survives in Broker's journal, so same-boot downtime is credited
even when the new process's relative sampler starts at zero. Suspend time is
credited by the same kernel clock.

After a **confirmed host reboot**, the old and new monotonic anchors are in
different domains and cannot measure powered-off time. Broker therefore accepts
a nondecreasing host wall clock and establishes a new anchor without operator
repair. This is an explicit availability tradeoff: a privileged actor who can
change the host clock across a reboot can expire time-bounded state early, but
cannot move effective time backwards to extend existing lifetimes. Correct host
time at boot is part of the deployment boundary now that Linux has no Chrony
dependency.

Missing legacy boot-epoch state is not treated as proof of reboot. An
unexplained large forward step on that one-time upgrade path remains
`FORWARD_JUMP_REJECTED` until an operator vouches for the clock.

Repair is an explicit, audited operator action taken at startup, and mirrors
Signer's:

```text
BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS=<unix-ms> bloom-broker …
```

`<unix-ms>` may not be earlier than the current effective time. Repair is
unavailable on profiles that do not use the durable guard, currently macOS. If
the repair would expire live approvals, Broker refuses on the first attempt and
prints the accepted time, the affected approvals, and a confirmation digest
over both; re-run with

```text
BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS=<unix-ms> \
BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST=<digest> bloom-broker …
```

to commit. The digest is bound to that accepted time and that exact approval
set, so it cannot be reused if either changes.

Signer and Broker keep independent clocks. An ordinary confirmed reboot allows
each to recover from a nondecreasing wall clock. If either service rejects a
rollback, same-boot jump, or unknown-domain jump, that affected service must be
repaired independently; repairing only one does not clear the other's fault.


## Owner-reviewed Petal sessions

Persona onboarding reuses Petal Sealed Approvals. The first automatic scope is
fee-free Polymarket BUY orders on Polygon with positive `polygon:pusd` debits.
SELLs, allowances, funding, withdrawals, native transfers and other classes do
not inherit that session. Native `SystemSession` draft terms are refused.

Machine–Broker uses protocol 1.9 for Broker-owned session descriptors. The
Broker–Signer edge remains production protocol 1.6. No session-budget API,
asset conversion, economic ledger or new selector is added to Signer.

Broker owns per-action, lifetime, rolling and shared economic accounting. It
reconstructs the order from the full prepared witness, compares it to the actual
signing preimage and checks the declared debit against the signed gross BUY
maker amount before reserving capacity. Missing evidence, SELLs, changed
amounts, unexpected assets and fees fail closed. This proves the signed order
terms, not venue execution, deposit-wallet ownership or settlement.

The immutable `session_budget` stays on the north edge and in Broker's durable
approval metadata and signed review. Its canonical digest and original request
nonce derive the existing 128-bit Signer request nonce under the
`bloom-broker-session-nonce/v1` domain. The approval ID hashes the ordinary
Signer enforcement projection. Changing or removing economics changes that
identity; both edges still agree on the approval ID. Budgetless approvals keep
their existing canonical identities. The complete descriptor is shown in the
signed Broker review, whose digest Signer binds opaquely to owner activation.
Signer continues to enforce its existing key/selector/suite, operation and
signature counts, rates, expiry, revocation and replay checks. It does not
independently guarantee economic containment of a compromised Broker.

Broker reserves shared capacity in the same SQLite transaction as the signing
operation. Reserved, committed and ambiguous operations continue to count;
only definitively released operations stop counting. Replays retrieve their
original result without another reservation. Different member approvals share
one Broker ledger; their Signer counters remain approval-local. Shared
signature-count enforcement in Signer is not claimed.

Nominal units are owner-reviewed collateral conventions, not live USD prices.
Keep the Broker journal and its accounting history intact. Restoring or losing
that history must never be treated as unused allowance. Signer archive recovery
does not restore Broker budgets, and this feature makes no new cross-service
restore guarantee. Existing startup/audit/recovery fences remain in force.

The candidate uses the production Signer rather than the experimental #68.
Land the reviewed Broker, repin Machine to its landed commit, and publish/adopt
the combined Polymarket review/accounting package with immutable archive hashes
and installer provenance before enabling the default flow. Local source tests
do not establish installed-release compatibility.

## Reusable operation profiles

`bloom_broker_api::reusable_signing_profiles()` is the shared eligibility catalog
for automatic onboarding. Each entry names a protocol operation class, effects
schema, crypto suite, exact budget assets and a compiled Broker verifier.
Machine matches it against the **installed package hash** and installer-signed
route provenance, then proposes owner-reviewed terms. Neither a package name
nor `economic_effects_schema = 1` alone makes a route eligible. The catalog does
not grant authority and does not replace wallet policy or approval activation.

Polymarket BUY is the first profile. Its adapter still reconstructs and compares
the signed order bytes, owner, chain and gross collateral debit. SELL shares,
fees, credential creation and continuing permissions do not acquire this BUY
permission. Other integrations remain unchanged; generic explicit selections
retain their existing assurance and approval contract. A new automatically
advertised protocol profile requires a Broker-owned verifier and adversarial
signed-byte tests, rather than another app-name branch in onboarding.

This is additive compiled metadata, not a new wire format. Effects-v1 claims,
route WIT, approval selectors and Signer custody are unchanged. Supported
semantic checks do not promote `machine_asserted` to proof-based assurance or
prove token-contract behavior, venue settlement, prices or market identity.
