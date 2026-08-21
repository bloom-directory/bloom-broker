# bloom-broker

Bloom's approval, policy, declared-usage accounting, and ceremony boundary.

The architecture is maintained in Bloom's
[public architecture documentation](https://github.com/bloom-directory/bloom/tree/triad-architecture/docs/architecture).

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
