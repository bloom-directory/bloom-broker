# Recurring token allowances

Broker enforces exact raw-unit accounting for owner-reviewed assets, not USD value. Pricing adapters, quote APIs, valuation evidence and nominal conversion have been removed. `SessionTokenPolicy` v3 binds display metadata, scope templates and backstop allocations. Each Machine default budget belongs to one Petal/account; routes share that budget and tokens have independent action/rolling limits.

Trader uses a rolling 24-hour window; Degen uses seven days. Windows replenish without expiring authority. `u64::MAX` expiry explicitly denotes a standing reusable approval and requires a wallet policy permitting standing validity. Exact approvals remain finite. Local keys still require activation/unlock after locking or restart; unlocking never resets usage. Signer retains custody and structural backstops and receives no token ledger.

Generic effects remain Petal/Machine assertions. Broker validates provenance, account/network bindings, supported permission classifications and declared amounts; it cannot prove arbitrary signed-byte exposure. Native transfer and Polymarket BUY verification remain mandatory where supported. Continuing approvals/delegations require separate owner approval.

The durable journal still atomically reserves, authenticates quantities/time/identity, retains ambiguous signatures, reconciles retries and fences stopped grants. Old USD grant formats fail closed; do not delete historical audit or recovery files to make them parse. Use a fresh isolated dev home for the incompatible candidate.

The full product contract and quantity presets are in Machine's `docs/specs/2026-10-26-generic-evm-svm-sessions.md`.

An owner can unlock retained local authority with `bloom wallet persona rearm WALLET` (`--approval ID` selects a specific grant). This reuses the sealed-approval passkey ceremony with the unchanged standing terms and a signed rearm purpose. It preserves both Broker usage and Signer counters, refuses stopped/revoked or changed terms, and retains an operation identity across retries. It does not add a wallet-unlock ceremony kind or silently create replacement authority.
