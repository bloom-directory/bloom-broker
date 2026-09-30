# Exact EVM transaction review

Machine/Broker protocol 1.6 adds `evm_review_payloads` to
`sealed_approval.prepare`. Upgrade Machine and Broker together: older strict
decoders reject the field, and Broker 1.6 refuses `transaction.confirm`,
`transaction.replace`, and `transaction.cancel` preparations without it.
Signer protocol and the Sealed Approval selector are unchanged.

## What Broker checks

- Each payload matches the exact selector's SHA-256 digest and Keccak hash, in
  order. One payload obeys the single signing-payload limit; several obey the
  batch limits (1–32 children, 64 KiB each, 512 KiB total).
- Each payload is a canonical unsigned legacy or EIP-1559 signing preimage with
  a nonzero chain ID and no access list. Signed, trailing, or noncanonical bytes
  are rejected.
- The request carries no Petal or system claim. Nothing compares a claim to the
  decoded transaction, and authorization accepts system claims only for Solana.
- The sender is derived from Signer's public key for the approval key.

The signed owner review shows chain, sender, destination, value, nonce, gas
limit, fees, payload keccak, and calldata size and keccak. It states that
contract execution effects are not verified. Native transaction approvals are
single-use and cannot be renewed.

## Direct contract creation

A transaction with no recipient (direct CREATE) is refused unless the wallet
policy contains an entry for its numeric chain, added through the policy-update
ceremony:

```json
{"chain":"evm-31337","destination":"exact"}
```

The entry is read from the policy version the approval terms are bound to.
Chain aliases such as `anvil` do not match it. It does not cover contracts
deployed by factory calls: those are ordinary calls, and Broker does not infer
their effects.

## Rollback

A manifest without an EVM review serializes to the same bytes as before this
field existed. A rollback while a ceremony that carries an EVM review is
pending cannot read that ceremony; ceremonies expire after ten minutes.
