# bloom-broker

Bloom's approval, policy, declared-usage accounting, and ceremony boundary.

The architecture is maintained in Bloom's
[public architecture documentation](https://github.com/bloom-directory/bloom/tree/triad-architecture/docs/architecture).

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
    "creation_window_ms": 60000,
    "maximum_creations_per_wallet": 3
  }
}
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
rejected the request; `retry_after_ms` is the exact wait until the oldest
creation holding that quota leaves the window, so waiting it out is sufficient
and callers need no extra margin. Callers wait and retry the **same** operation
identity — never parse the message, and never invent a replacement operation.
The field is absent on older peers and is refused if it appears on any other
code or carries values outside its own window.

Concurrency exhaustion is a different class: it returns `QUOTA_EXCEEDED` with
**no** retry hint, because nothing ages out on a schedule — only when a live
ceremony ends.

## Recovering a fail-closed clock after a restart

Broker's approval and ceremony lifetimes are measured against a durable clock,
so it will not issue or honour them while that clock is untrusted. Any elapsed
time Broker cannot account for is rejected rather than assumed benign.

A **process** restart is credited automatically from the persisted absolute
monotonic anchor. A **reboot** is not: the kernel's suspend-aware clock restarts
at zero, so the persisted anchor belongs to a domain that no longer exists. If
the wall clock has moved on by more than the maximum forward step, the next
observation is `FORWARD_JUMP_REJECTED` and requests fail with `CLOCK_UNTRUSTED`
until an operator repairs the clock. Accepting the jump instead would be
indistinguishable from an attacker moving the clock to expire approvals or
extend a grant.

Repair is an explicit, audited operator action taken at startup, and mirrors
Signer's:

```text
BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS=<unix-ms> bloom-broker …
```

`<unix-ms>` may not be earlier than the current effective time, and repair is
unavailable when the host wall clock is authoritative rather than the trusted
time source. If the repair would expire live approvals, Broker refuses on the
first attempt and prints the accepted time, the affected approvals, and a
confirmation digest over both; re-run with

```text
BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS=<unix-ms> \
BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST=<digest> bloom-broker …
```

to commit. The digest is bound to that accepted time and that exact approval
set, so it cannot be reused if either changes.

Signer and Broker keep independent clocks. A reboot leaves **both** untrusted,
so both need repairing before the triad will serve; repairing only one leaves
the other refusing requests.
