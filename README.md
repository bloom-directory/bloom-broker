# bloom-broker

Bloom's approval, policy, declared-usage accounting, and ceremony boundary.

The architecture is maintained in Bloom's
[public architecture documentation](https://github.com/bloom-directory/bloom/tree/triad-architecture/docs/architecture).

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
