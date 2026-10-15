# EVM clear signing: the supported subset

Broker always decodes the exact address and raw integer in canonical ERC-20
`transfer(address,uint256)` and `approve(address,uint256)` calldata. This
**structural review** needs no catalog. It does not claim that the destination
is a token: any contract can implement the same four-byte selector.

When a **signed local catalog** covers the deployment, Broker upgrades that
reading with a trusted token identity, decimals and human units. Other
catalogued calls use a flattened ERC-7730 descriptor and the same strict ABI
rules.

Adding a contract inside this subset is catalog data. Changing what Bloom
promises about a call is code.

## Assurance levels

`structural_calldata` means Broker verified the canonical selector, length,
address padding and exact raw arguments from the signing preimage. The page
names the contract, recipient or spender and raw integer, and warns that token
behavior is unverified. Structural review never supplies a trusted symbol,
human units or reusable authority.

`trusted_description` means the catalog publisher is trusted to
describe the listed deployment accurately, and a signature authenticates that
assertion. It is **not** proof of execution, contract safety, or the absence
of an upgrade after the publisher's observation. Broker never fetches
anything, reads no chain state, and resolves no proxy.

A review that read any address through an [instance entry](#instance-entries)
has the class `structural_description` instead. The description is trusted in
the same way, but nothing establishes that the address runs the contract it
describes.

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
  and `bytesN`; dynamic `bytes`; and dynamic arrays of one static scalar
  (`address[]`, `uint256[]`, ...).
- Direct named field paths, optionally spelled `#.name`. An array argument is
  addressed as `name.[]` and shown one element per line; nothing else may use
  `.[]`.
- Always-visible fields in seven formats: `raw`, `addressName`, `tokenAmount`,
  `amount`, `date`, `enum`, and `calldata` (see [Embedded calls](#embedded-calls)).
  `bytes` takes `raw` or `calldata`. `tokenAmount` does not apply per element.
- `visible: {"mustMatch": [...]}` on a scalar or `bytes` argument. The field is
  not shown, because the signed description fixes it: any other value makes the
  call unsupported. A `mustMatch` field carries only `path`, `label` and the rule.
- `intent` as a plain string. It is supplemental text beside the facts; Bloom
  writes the heading and the warnings.

**Refused, with the descriptor made unusable rather than partly rendered**

- Unresolved `includes`, a deployment binding that does not match the entry,
  inline `abi`, and `factory` bindings.
- `interpolatedIntent`, `display.definitions`, `$ref` field references, field
  groups, `value` constants, `separator`, `encryption`.
- Hidden or conditional fields (`visible` other than `"always"` or a lone
  `mustMatch`), and `mustMatch` on an array.
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
- `string`, fixed-size and nested arrays, and signed integers.
- `calldata` parameters other than `calleePath` and `amountPath`. `selector`,
  `spender` and `chainId` would each change how the inner call is read.
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

## Embedded calls

A `calldata` field reads a call carried inside this one. `calleePath` names the
contract it calls, as `"@.to"` or an address argument. The optional
`amountPath` names a uint argument holding the native value it sends. The inner
call is reviewed exactly as a top-level call:

- An inner call Bloom cannot read makes the whole call unsupported.
- Its policy refusals refuse, so an unlimited allowance inside a Safe is
  denied as it is outside one.
- Its catalog entries become frozen evidence.

The page shows one heading line, `<function> on <contract>`, then the inner
call's fields labelled under it (`Safe transaction · Amount`). The inner
call's warnings are prefixed the same way.

Empty inner calldata is a plain value transfer, shown as `Send <amount> to
<callee>`, or `No call` when the amount is zero. Calls nest at most two deep.

## Instance entries

Some contracts exist once per user: every Safe is its own proxy, so no catalog
can list them. ERC-7730 binds such a descriptor to the implementation and
expects the wallet to resolve the proxy. Broker reads no chain state, so it
cannot resolve one. An entry may instead set `applies_to_instances`:

- An address with no entry of its own is read by that entry's functions,
  matched by selector.
- An address that has an entry is only ever read by that entry, so a listed
  token is never read as a Safe.
- On one chain, two instance entries may not admit the same selector.
- An instance entry carries no token metadata and admits only `other`
  functions, so it cannot lend a token's identity to unlisted addresses.

Such a call gets the structural assurance and a warning that Bloom has not
verified the address is that contract. Its evidence records the address it was
read for, so removing the flag withdraws the reading.

The address not being verified is bounded by an existing rule: an admitted
call carries no native value. A call to an address that is not what it claims
can spend only gas and whatever allowances this wallet already gave that
address.

## Safe

`crates/bloom-evm-clear-signing/catalogs/safe` holds Bloom's Safe descriptors.
They are derived from `registry/safe` in LedgerHQ/clear-signing-erc7730-registry.
`entries.json` lists every entry, in the publisher source format except for
`observed_at_ms`, which the publisher stamps when it checks the code hashes.

The entries cover the official Safe singletons and proxy factories (1.3.0,
1.4.1, 1.5.0) on chains 1, 10, 100, 137, 8453 and 42161, with their runtime
code hashes. Safe 1.4.1, the version the Safe Petal deploys, is the instance
entry on each chain. Its `execTransaction` and owner-management functions are
identical in 1.3.0 and 1.5.0.

`mustMatch` holds the Safe safety rules:

- `operation` must be a call, so delegatecalls, and with them `MultiSend`
  batches, are refused.
- No gas refund: `gasPrice`, `gasToken` and `refundReceiver` must be zero.
- A new Safe uses an official singleton, has no setup call, no setup payment,
  and either an official fallback handler or none.

Owner signatures are shown raw and are not checked by Bloom.

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
per label or intent, 64 labels per enum map, 64 values per `mustMatch`, 64
elements per array argument, two nested calls, 16 ASCII token symbol, 64 scalar
values and 256 bytes of token name. `bytes` longer than 128 bytes are shown by
length and keccak-256.

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

Omitting it preserves the previous policy serialization. The wallet still gets
structural review for canonical transfers and approvals, but trusts no catalog,
permits no catalog-based authority and cannot request a clear or opaque mode.

The threshold counts distinct trusted keys, so a publisher repeating one key
cannot reach two. Stored catalog bytes are not trusted on their own: every
review re-verifies the snapshot under the reviewed wallet's own policy, so a
key rotation stops the stored snapshot authorizing anything without deleting
it.

## Modes and expiry

One mode applies to a batch. In an enabled wallet, omission means `clear` for
contract calls; native sends and deployments keep their existing exact
envelope review. A canonical transfer or approval may fall back to structural
review when its deployment is absent, withdrawn or stale. A mixed batch labels
the weaker members and freezes catalog evidence only for the trusted members.
Any other unreadable member still blocks the batch.

`opaque_exact` must be requested explicitly, needs `opaque_exact_allowed`, and
carries the inability-to-explain warning in the signed manifest. It covers
only calls Bloom cannot read: neither a catalog-backed nor a structurally
decoded call can be approved unread. A wallet without the extension refuses a
requested mode rather than ignoring it.

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

For a wallet with clear signing enabled, maximum U256 is denied by default. A
request explains the denial and names one action: change the wallet policy.
That is **one existing wallet-policy
ceremony** — setting `unlimited_allowance_allowed` in the canonical policy
document and running the ordinary update. Enabling it is a visible authority
change: the policy authority diff both services compute carries the
clear-signing settings before and after, so the ceremony shows the owner what
the update actually grants rather than an empty diff.

After the policy commits, the staged allowance is reprepared and gets its own
ordinary exact approval ceremony. These are two different authorizations, and
the second is never automatic.

A wallet without the clear-signing extension has no unlimited-allowance policy
to enforce. Broker still decodes the maximum value, displays the strong warning
and permits only that exact owner approval; it creates no reusable authority.

The rule is narrow. It matches only canonical `approve(address,uint256)` with
the exact U256 maximum. A requester can ask for one less, and that is shown as
a finite allowance with its exact amount, not refused. Other calls that grant
spending power, such as `increaseAllowance`, `setApprovalForAll` or Permit2's
`approve`, are not recognised as allowances: a publisher that admits one signs
it as `other`, which gets no allowance warning and no unlimited gate.

Demonstrated so far: the default denial, against real services on a
disposable chain, with the message above. The enabling ceremony and the
reprepared allowance that follows it have been implemented but not yet
demonstrated with an owner approval.

## Operating it

`clear_signing_catalog_path` in the Broker configuration points at a signed
snapshot. Replacing that file and restarting Broker is the whole import
surface: no network fetch, no refresh command, no second audit family. A
snapshot no enrolled wallet trusts is logged and not installed; Broker still
starts, because wallets that never enabled clear signing are unaffected. The
same holds for a snapshot every pinning wallet refuses, such as an old file after
a publisher key rotation or a rolled-back sequence: the stored catalog stays as
it was and the log names the reason. After a rotation, re-signing the same
sequence with the new key replaces the stored signatures.

Broker stores one catalog per catalog identity, so a wallet that pins
`bloom-tokens` and a wallet that pins `staging-catalog` do not evict each
other, and the sequence watermark that refuses a rollback is per identity too.
A wallet reads only the catalog its policy pins; another identity's snapshot
reads to it the same as having none.

`broker.capabilities` reports, for each stored catalog, its identity,
sequence, content digest, expiry, entry count, oldest observation and the
compiled verifier's digest. Per-wallet trust is in the wallet's policy, which
`policy.read` already returns.

## Publishing a catalog

`bloom-clear-signing-catalog` resolves includes, runs the exact admission
Broker runs, hashes each flattened descriptor, sorts the entries and signs:

```sh
# The pinned ERC-7730 v2 schema commit and digest this build requires.
bloom-clear-signing-catalog schema-pin
# Validate the sources against that schema and write the report `build` needs.
publish/validate-descriptors.sh erc7730-v2.schema.json descriptor.json > report.json
bloom-clear-signing-catalog build source.json \
  --key publisher.hex --key-id publisher-1 \
  --schema-report report.json --out catalog.json
bloom-clear-signing-catalog verify catalog.json \
  --key-id publisher-1 --public-key <hex>
```

Schema validation is a required step, not an optional one: `build` refuses to
publish without a report that names the pinned schema commit and digest and
covers every descriptor file the build reads by SHA-256, including every file
reached through `includes`. Validation itself is upstream JSON Schema tooling
rather than ours, which is why it is a separate script and a report rather
than a flag.

A catalog that builds is one Broker can read: a descriptor instruction outside
the subset fails at publication rather than in front of an owner. Bloom's
admission is narrower than the schema for everything Bloom displays, so both
checks run and neither replaces the other.

## Durable-state compatibility

Storing a policy that carries the extension raises the store's minimum state
version to 2 in the same transaction. A build below that floor refuses to open
the store before it mutates anything.

A build predating the floor has no floor to read. It fails one step later
instead: its strict decoder rejects the unknown `clear_signing` field while
loading the policy. That is fail-closed rather than silent, but it is a
different message, and rollback is never made to work by dropping the field.
The same rule applies to backup and restore.

An expired catalog cannot explain calls, so an explicitly requested opaque review
may proceed when wallet policy permits it. A refused signed catalog leaves Broker
running; an unsafe or unreadable unsigned theme stops startup because it controls
what the owner sees. Theme and catalog files are opened without following symlinks,
and permissions are checked on the same file handle that is read.
