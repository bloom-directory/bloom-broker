# W2 journal decisions

- SQLite transactions are the W2 durability and concurrency boundary. Approval
  transitions, operation transitions, accounting reservations, result
  publication, and audit entries commit together where the specification
  requires one durable effect.
- Operation retries persist a binding digest over the first unsigned
  `bloom.sign-request/1` after removing only `attempt_id`, `attempt_digest`,
  Broker boot epoch, and attempt validity timestamps. Every other field must
  remain byte-for-byte canonical across attempts.
- Batch child operation IDs are
  `SHA-256("bloom-batch-child/v1" || parent_operation_id || u32be(index))`.
  Child IDs are globally unique and batches contain 1–32 children.
- Rate-limited reservations use the journal-owned durable effective time.
  Uninitialized, untrusted, or rollback-frozen time denies admission.
  Forward jumps beyond the configured step retain monotonic effective time
  and are audited. Explicit repair cannot move time backward.
- Audit entries hash the previous entry and canonical payload, then require an
  injected Broker-owned signer to sign the entry hash under
  `bloom-broker-audit-signature/v1`. Opening a journal without an audit signer
  is not representable by the API.
- The production authority and ceremony stores share the journal SQLite
  connection. This is required because SQLite cannot provide the §20 atomic
  local-effect-plus-audit guarantee across the former independent WAL files.
  On first open, populated legacy authority and ceremony databases are copied
  into the journal database in a single audited transaction. A durable source
  marker makes the migration idempotent; conflicts fail closed, and the legacy
  source file is retained unchanged as a rollback artifact.
- The complete chain is verified at startup and under the database lock before
  every security mutation. Any payload, hash, link, sequence, signature, or
  signing-key-ID failure latches mutation denial without disabling reads and
  status. Required peer/OS checkpoint persistence may explicitly set the same
  latch.
- A corrupt or signing-key-mismatched existing journal does not prevent the
  Broker from constructing its durable read/status projections. Startup keeps
  the journal latch set, skips clock observation, provenance synchronization,
  completion replay, and reconciliation, and reports
  `audit_journal_degraded`. Every security mutation remains denied. Invalid
  configuration that cannot define a unique keyring still fails startup.
- External audit-head sequences are entry counts: an empty chain is `(0,
  zero_hash)`, while database entry sequence `N` is exposed as checkpoint
  sequence `N + 1`. This avoids ambiguity and makes the first mutation advance
  the monotonic checkpoint from zero to one.
- Audit-key rotation is a local packaging operation, not a wire RPC. The
  journal appends `audit.key_rotated` under the old key and embeds a
  replacement-key possession signature over the old key ID, new key ID, and
  prior head. Verification permits a key-ID change only at that cross-signed
  transition. A restarted package must supply an audit verifier/keyring that
  retains the historical public keys; supplying only the new key fails closed.
  Production startup accepts those pins in
  `audit_historical_public_keys`. For the single startup that advances an
  existing old-key tail, packaging supplies `audit_rotation_previous_key`
  alongside the new current key. Broker first verifies the complete old chain,
  commits the cross-signed rotation, and verifies the resulting chain before
  serving. Packaging removes the previous private seed after that successful
  startup; later starts need only the new signing key and retained historical
  public pins. Conflicting pins, missing history, and a tail that does not end
  at the declared previous key all fail closed.
- Ceremony state is published to the in-memory browser projection only after
  the session row and `ceremony.session_persisted` audit entry commit. Policy
  installs similarly preserve custody/policy operation identity and ceremony,
  validation, and commit receipt digests in `policy.installed`. Exact policy
  rereads are non-mutating and remain available under the audit-degraded latch.
- Publication audit events bind the canonical `SigningResult` digest,
  operation identity, and both Signer and Broker receipt digests. Batch events
  bind the same fields for the parent and every ordered child. Approval
  activation binds the complete canonical Signer activation receipt digest
  alongside its approval and activation operation. Full-chain verification
  cross-checks these signed correlations against the persisted result and
  receipt rows, so post-commit row substitution latches the Broker read-only.
