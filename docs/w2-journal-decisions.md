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
