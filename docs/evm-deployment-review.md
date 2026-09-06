# Exact EVM deployment review

Machine/Broker protocol 1.5 adds `evm_review_payloads` to
`sealed_approval.prepare`. Upgrade both services together: strict 1.4 decoders
cannot accept this field, and 1.5 refuses native `transaction.confirm`,
`transaction.replace`, and `transaction.cancel` preparations without payloads.
Signer protocol and the Sealed Approval selector remain unchanged.

For native EVM preparations Broker checks the supplied SHA-256 payload digests
and Keccak signing hashes against the exact selector, decodes canonical legacy
or EIP-1559 signing preimages, and re-encodes them to reject signed, malformed,
trailing, or noncanonical data. The sender comes from Signer's public key for
the exact approval key. Broker includes decoded chain ID, sender, destination,
nonce, value, gas, fees, and payload commitments in its signed owner review.
Creation shows an initcode commitment and conditional CREATE address prediction;
constructor behavior and resulting ownership remain unverified. Factory calls
remain calls, with no invented created address.

Direct creation requires the owner to add this explicit numeric-chain entry to
the canonical wallet policy through its existing policy-update ceremony:

```json
{"chain":"evm-31337","destination":"exact"}
```

This entry permits preparation of exact native EVM deployment approvals on
chain ID 31337; every transaction still requires its own exact owner approval.
It is not a reusable Petal allowance or a general signing capability. Machine's
deployment workflow also uses this opt-in for dependent initialization/factory
calls. Ordinary call policy enforcement retains its existing authority path and
Machine's chain-scoped advisory destination checks. Chain aliases supplied by
Machine cannot substitute for the numeric creation scope.

The full preimages are verification inputs; Machine's prose is not the source
of these transaction facts. The signed review manifest includes the decoded
section through its existing attributed-item and canonical-plan commitments.
Payload omission on non-native approval classes preserves their existing flow.
