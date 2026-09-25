# EVM clear signing: the supported subset

Broker shows the actual recipient and amount of an ERC-20 `transfer`, and the
spender and requested total of an `approve`, before the owner signs. It does
that by reading a **flattened ERC-7730 descriptor** out of a **signed local
catalog**, decoding the exact calldata with one generic ABI path, and applying
wallet safety rules the descriptor cannot switch off.

Adding a contract inside this subset is catalog data. Changing what Bloom
promises about a call is code.

## What the assurance means

The class is `trusted_description`. The catalog publisher is trusted to
describe the listed deployment accurately, and a signature authenticates that
assertion. It is **not** proof of execution, contract safety, or the absence
of an upgrade after the publisher's observation. Broker never fetches
anything, reads no chain state, and resolves no proxy.

## The admitted ERC-7730 subset

Taken from released v2, `ethereum/ERCs@2528d6a0cd463d7309464a33889774368ab52df3`
(`assets/erc-7730/erc7730-v2.schema.json`, SHA-256
`53c0fe0ed07c3e032fc3bfabb105585b6648b2adae4858fbf45b3a09dfe691f5`). This is a
published subset, not full ERC-7730 conformance.

**Accepted**

- `context.contract.deployments` naming the catalog entry's own chain and
  address.
- `metadata.owner`, `metadata.contractName`, `metadata.enums`.
- `display.formats`, keyed by a function signature with named parameters.
- Named static scalar arguments: `address`, `bool`, `uintN` (canonical widths)
  and `bytesN`.
- Direct named field paths, optionally spelled `#.name`.
- Always-visible fields in six formats: `raw`, `addressName`, `tokenAmount`,
  `amount`, `date`, `enum`.
- `intent` as a plain string. It is supplemental text beside the facts; Bloom
  writes the heading and the warnings.

**Refused, with the descriptor made unusable rather than partly rendered**

- Unresolved `includes`, a deployment binding that does not match the entry,
  inline `abi`, and `factory` bindings.
- `interpolatedIntent`, `display.definitions`, `$ref` field references, field
  groups, `value` constants, `separator`, `encryption`.
- Hidden or conditional fields (`visible` other than `"always"`).
- `tokenAmount` parameters other than `tokenPath` — in particular `threshold`
  and `message`, which is how the registry's ERC-20 template labels a large
  *finite* allowance "unlimited". An admitted derivative must drop them;
  Bloom's own maximum-U256 rule owns that warning.

  `tokenPath` itself takes either `"@.to"`, meaning the contract being called
  is the token, or the name of an address argument of the same call. In the
  second form the address that was actually decoded is looked up in the signed
  catalog, so a call naming a token the catalog does not describe is
  unsupported rather than shown with borrowed decimals, and that token's entry
  becomes part of the frozen evidence: withdrawing or changing it invalidates
  the review. A token path that names a non-address argument, or no argument
  at all, is refused at admission.
- `date` with `blockheight` encoding, which cannot be converted offline.
- `enum` references outside a local `$.metadata.enums` map, and any value the
  map does not label.
- `metadata.token`, `metadata.constants`, `metadata.maps`: units come from the
  signed catalog, not from the document.
- Any argument left off the screen. Every decoded leaf must be covered by a
  visible field naming its actual path.
- Dynamic types (`string`, `bytes`, arrays) and signed integers.
- **Tuples**, deferred from this milestone rather than ruled out. The
  limitation was measured against the pinned parser, not assumed:
  `alloy_json_abi::Function::parse` rejects
  `settle((address beneficiary, uint256 amount) terms, bool finalize)`
  outright, and parses `settle((address,uint256) terms, bool finalize)` with
  its components unnamed. So a field path like `terms.beneficiary` has nothing
  to resolve against *through a signature key*. How to carry component names
  is an open representation decision — a richer format key, the contract's
  JSON ABI as a second signed input, or positional paths — and nothing here
  forecloses any of them. It belongs with the router slice, which is the first
  thing that needs it; Uniswap's `exactInputSingle` is exactly this shape.

`addressName` name sources are inert: no ENS request, no account-type
assertion, no sentinel substitution. The raw address is what is shown.

## Safety rules over the generic result

These inspect the decoded values; they do not select a different decoder.

| Class | Rules |
| --- | --- |
| `transfer` | Must be canonical `transfer(address,uint256)`. Zero recipient refused; the token contract is not a valid recipient of its own transfer; signed decimals required; a zero amount is displayed honestly. |
| `allowance` | Must be canonical `approve(address,uint256)`. Zero spender refused; zero means clearing the allowance; a finite value sets a total, not an increment; exact U256 maximum is unlimited and is denied unless policy allows it. |
| `other` | Neutral heading, supplemental intent, every argument shown, no economic guarantee invented. |

The class is signed and checked in both directions. `approve` relabelled
"Login" and signed as `other` is refused, and an unrelated three-argument call
signed as `transfer` is refused.

## Catalog

One snapshot, Ed25519-signed under `bloom-clear-signing-catalog/v1` over the
JCS encoding of everything except the signatures. Entry key is
`(chain_id, contract_address)`, lowercase; entries are sorted and unique.

Bounds: 1 MiB per catalog, 1,024 entries, 8 signatures, 64 KiB per descriptor,
16 admitted functions per entry, 32 arguments per function, 256 scalar values
per label or intent, 64 labels per enum map, 16 ASCII token symbol, 64 scalar
values and 256 bytes of token name.

Sequence must increase. The same sequence with the same content is an
idempotent retry; the same sequence with different content is refused. A newer
complete snapshot replaces the entry set, so omission withdraws an entry. A
later valid snapshot may re-add it: that is another assertion by a publisher
the wallet already trusts, not a revocation being reversed.

Proxy facts are only `upgradeable`, `implementation_hash` and `observed_at_ms`.
Broker keeps them for comparison and shows the observation age; it cannot
certify the current implementation. Proxy resolution stays with the publisher,
which is what makes deployment-specific schemes such as Circle's ZeppelinOS
[FiatToken proxy](https://github.com/circlefin/stablecoin-evm/blob/master/doc/tokendesign.md)
workable.

## Wallet policy

An optional closed extension on the canonical wallet policy, changed through
the existing policy ceremony:

```text
catalog_id, trusted_keys, signature_threshold (default 1),
maximum_observation_age_ms (default 86_400_000),
opaque_exact_allowed (default false),
unlimited_allowance_allowed (default false),
verifier (id + source digest)
```

Omitting it preserves the previous serialization exactly and leaves the wallet
on the existing envelope review, which is not advertised as clear signing.

The threshold counts distinct trusted keys, so a publisher repeating one key
cannot reach two. Stored catalog bytes are not trusted on their own: every
review re-verifies the snapshot under the reviewed wallet's own policy, so a
key rotation stops the stored snapshot authorizing anything without deleting
it.

## Modes and expiry

One mode per batch. In an enabled wallet, omission means `clear` for contract
calls; native sends and deployments keep their existing exact envelope review.
One member Bloom cannot describe blocks the whole batch — there is no split,
no mixed badge and no downgrade. `opaque_exact` must be requested explicitly,
needs `opaque_exact_allowed`, and carries the inability-to-explain warning in
the signed manifest. A wallet without the extension refuses a requested mode
rather than ignoring it.

Approval expiry is capped at

```text
min(requested/policy expiry, catalog expiry,
    each used entry.observed_at_ms + maximum_observation_age_ms)
```

Exceeding it returns the permitted instant before a ceremony exists, so the
caller regenerates terms under the existing operation-conflict rules. At
activation and at each signing authorization the frozen evidence is re-read
against the current catalog and policy: a withdrawal, a changed entry
(including a changed observation time), a changed catalog identity or a changed
verifier source digest invalidates an unsigned review. A newer catalog never
extends an approval, and a signature already produced cannot be recalled.

## Unlimited allowances

Denied by default. A maximum-U256 request explains the denial and names one
action: change the wallet policy. That is **one existing wallet-policy
ceremony** — setting `unlimited_allowance_allowed` in the canonical policy
document and running the ordinary update. Enabling it is a visible authority
change: the policy authority diff both services compute carries the
clear-signing settings before and after, so the ceremony shows the owner what
the update actually grants rather than an empty diff.

After the policy commits, the staged allowance is reprepared and gets its own
ordinary exact approval ceremony. These are two different authorizations, and
the second is never automatic.

Demonstrated so far: the default denial, against real services on a
disposable chain, with the message above. The enabling ceremony and the
reprepared allowance that follows it have been implemented but not yet
demonstrated with an owner approval.

## Operating it

`clear_signing_catalog_path` in the Broker configuration points at a signed
snapshot. Replacing that file and restarting Broker is the whole import
surface: no network fetch, no refresh command, no second audit family. A
snapshot no enrolled wallet trusts is logged and not installed; Broker still
starts, because wallets that never enabled clear signing are unaffected.

`broker.capabilities` reports the stored catalog's identity, sequence, content
digest, expiry, entry count, oldest observation and the compiled verifier's
digest. Per-wallet trust is in the wallet's policy, which `policy.read`
already returns.

## Publishing a catalog

`bloom-clear-signing-catalog` resolves includes, runs the exact admission
Broker runs, hashes each flattened descriptor, sorts the entries and signs:

```sh
bloom-clear-signing-catalog schema-pin
bloom-clear-signing-catalog build source.json \
  --key publisher.hex --key-id publisher-1 --out catalog.json
bloom-clear-signing-catalog verify catalog.json \
  --key-id publisher-1 --public-key <hex>
```

A catalog that builds is one Broker can read: a descriptor instruction outside
the subset fails at publication rather than in front of an owner. Validating
the *source* document against the full upstream schema remains the publisher's
job with upstream tooling; Bloom's admission is narrower for everything Bloom
displays.

## Durable-state compatibility

Storing a policy that carries the extension raises the store's minimum state
version to 2 in the same transaction. A build below that floor refuses to open
the store before it mutates anything.

A build predating the floor has no floor to read. It fails one step later
instead: its strict decoder rejects the unknown `clear_signing` field while
loading the policy. That is fail-closed rather than silent, but it is a
different message, and rollback is never made to work by dropping the field.
The same rule applies to backup and restore.
