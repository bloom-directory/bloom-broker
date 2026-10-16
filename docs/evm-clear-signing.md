# EVM clear signing: the supported subset

Broker always decodes the exact address and raw integer in canonical ERC-20
`transfer(address,uint256)` and `approve(address,uint256)` calldata. This
**structural review** needs no catalog. It does not claim that the destination
is a token: any contract can implement the same four-byte selector.

When Broker's **catalog** lists the deployment, Broker upgrades that reading
with the token's name, decimals and human units. Other catalogued calls use a
flattened ERC-7730 descriptor and the same strict ABI rules.

The catalog is compiled into Broker from `crates/bloom-evm-clear-signing/catalogs`,
so it is trusted exactly as far as the Broker release is. There is no catalog
file, signature, publisher key or import step, and Broker never fetches
anything. Adding a contract inside this subset is catalog data. Changing what
Bloom promises about a call is code.

## Assurance levels

`structural_calldata` means Broker verified the canonical selector, length,
address padding and exact raw arguments from the signing preimage. The page
names the contract, recipient or spender and raw integer, and warns that token
behavior is unverified. Structural review never supplies a symbol, human units
or reusable authority.

`trusted_description` means the call was read with the catalog's description
of the listed deployment. It is **not** proof of execution, contract safety, or
the absence of an upgrade since the release. Broker reads no chain state and
resolves no proxy.

A review that read any address through an [instance entry](#instance-entries),
or an embedded ERC-20 call by its shape alone, has the class
`structural_description` instead: the description is used in the same way, but
nothing establishes which contract the address is.

## The admitted ERC-7730 subset

Taken from released v2, `ethereum/ERCs@2528d6a0cd463d7309464a33889774368ab52df3`
(`assets/erc-7730/erc7730-v2.schema.json`, SHA-256
`53c0fe0ed07c3e032fc3bfabb105585b6648b2adae4858fbf45b3a09dfe691f5`). This is a
published subset, not full ERC-7730 conformance.

**Accepted**

- `context.contract.deployments`: every `(chainId, address)` the descriptor
  describes. Each becomes a catalog entry.
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
  not shown, because the description fixes it: any other value makes the
  call unsupported. A `mustMatch` field carries only `path`, `label` and the rule.
- `intent` as a plain string. It is supplemental text beside the facts; Bloom
  writes the heading and the warnings.

**Refused, with the descriptor made unusable rather than partly rendered**

- Unresolved `includes`, inline `abi`, and `factory` bindings.
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
  second form the address that was actually decoded is looked up in the
  catalog, so a call naming a token the catalog does not describe is
  unsupported rather than shown with borrowed decimals, and that token's entry
  becomes part of the frozen evidence. A token path that names a non-address argument, or no argument
  at all, is refused at admission.
- `date` with `blockheight` encoding, which cannot be converted offline.
- `enum` references outside a local `$.metadata.enums` map, and any value the
  map does not label.
- `metadata.token`, `metadata.constants`, `metadata.maps`: units come from the
  catalog's token rows, not from the document.
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
  JSON ABI as a second input, or positional paths — and nothing here
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

An inner canonical `transfer` or `approve` to a contract the catalog does not
list is read by its shape, as at the top level: recipient or spender and raw
amount, the unverified-token warning, and the same unlimited-allowance policy.
The review is then `structural_description`.

The page shows one heading line, `<function> on <contract>`, then the inner
call's fields labelled under it (`Safe transaction · Amount`). The inner
call's warnings are prefixed the same way.

Empty inner calldata is a plain value transfer, shown as `Send <amount> to
<callee>`, or `No call` when the amount is zero. Calls nest at most two deep.

## Instance entries

Some contracts exist once per user: every Safe is its own proxy, so no catalog
can list them. ERC-7730 binds such a descriptor to the implementation and
expects the wallet to resolve the proxy. Broker reads no chain state, so it
cannot resolve one. A descriptor in `DESCRIPTORS` may instead name one of its
deployments as the instance address:

- An address with no entry of its own is read by that deployment's functions,
  matched by selector.
- An address that has an entry is only ever read by that entry, so a listed
  token is never read as a Safe.
- On one chain, two instance descriptions may not admit the same selector.
- An instance description admits no ERC-20 call and carries no token row, so
  it cannot lend a token's identity to unlisted addresses.

Such a call gets the structural assurance and a warning that Bloom has not
verified the address is that contract. Its evidence records the address it was
read for.

The address not being verified is bounded by an existing rule: an admitted
call carries no native value. A call to an address that is not what it claims
can spend only gas and whatever allowances this wallet already gave that
address.

## Safe

`catalogs/safe` holds Bloom's Safe descriptors, derived from `registry/safe` in
LedgerHQ/clear-signing-erc7730-registry. They cover the official Safe
singletons and proxy factories (1.3.0, 1.4.1, 1.5.0) on chains 1, 10, 100, 137,
8453 and 42161. Safe 1.4.1, the version the Safe Petal deploys, is the instance
address on each chain. Its `execTransaction` and owner-management functions are
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
| `transfer` | Must be canonical `transfer(address,uint256)`. Zero recipient refused; the token contract is not a valid recipient of its own transfer; listed decimals required; a zero amount is displayed honestly. |
| `allowance` | Must be canonical `approve(address,uint256)`. Zero spender refused; zero means clearing the allowance; a finite value sets a total, not an increment; exact U256 maximum is unlimited and is denied unless policy allows it. |
| `other` | Neutral heading, supplemental intent, every argument shown, no economic guarantee invented. |

The class is derived from the function signature, never declared: only the
canonical ERC-20 signatures get the `transfer` and `allowance` rules, so
`approve` relabelled "Login" still gets the allowance rules, and an unrelated
three-argument call never gets the transfer screen.

## Catalog

`catalog.rs` lists the compiled-in descriptor files in `DESCRIPTORS`, each with
its optional instance address. `catalogs/tokens.json` lists tokens:

```json
{"chain_id": 1, "address": "0x…", "symbol": "USDC", "name": "USD Coin",
 "decimals": 6, "upgradeable": true}
```

A token row is read by Bloom's built-in ERC-20 profile: `transfer` and
`approve`, with human units. A token row whose address is also a descriptor
deployment adds its units to that descriptor instead. Every function a
descriptor formats is admitted. Addresses are lowercase, and a deployment may
be listed once. `Catalog::built_in` admits all of it once, and a test proves it
admits.

Bounds: 64 KiB per descriptor, 16 functions per descriptor, 32 arguments per
function, 256 scalar values per label or intent, 64 labels per enum map, 64
values per `mustMatch`, 64 elements per array argument, two nested calls, 16
ASCII token symbol, 64 scalar values and 256 bytes of token name. `bytes`
longer than 128 bytes are shown by length and keccak-256.

`upgradeable` is shown on the page for the contracts a review used. Broker
cannot certify a proxy's current implementation; the page says its code may
have changed since this release described it.

## Wallet policy

An optional closed extension on the canonical wallet policy, changed through
the existing policy ceremony:

```text
opaque_exact_allowed (default false),
unlimited_allowance_allowed (default false)
```

Its presence turns clear signing on. Omitting it preserves the previous policy
serialization: the wallet still gets structural review for canonical transfers
and approvals, and cannot request a clear or opaque mode.

## Modes

One mode applies to a batch. In an enabled wallet, omission means `clear` for
contract calls; native sends and deployments keep their existing exact
envelope review. A canonical transfer or approval to an unlisted contract
falls back to structural review. A mixed batch labels the weaker members and
freezes catalog evidence only for the catalogued members. Any other unreadable
member still blocks the batch.

`opaque_exact` must be requested explicitly, needs `opaque_exact_allowed`, and
carries the inability-to-explain warning in the signed manifest. It covers
only calls Bloom cannot read: neither a catalogued nor a structurally decoded
call can be approved unread. A wallet without the extension refuses a
requested mode rather than ignoring it.

The frozen evidence records the verifier digest: SHA-256 over the verifier
sources and the compiled-in catalog. At activation and at each signing
authorization Broker compares it with its own, so a Broker upgrade between
review and signature invalidates the unsigned review rather than carrying it
forward. A signature already produced cannot be recalled.

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
`approve`, are not recognised as allowances: a descriptor that formats one
reads it as `other`, with no allowance warning and no unlimited gate.

Demonstrated so far: the default denial, against real services on a
disposable chain, with the message above. The enabling ceremony and the
reprepared allowance that follows it have been implemented but not yet
demonstrated with an owner approval.

## Adding to the catalog

- **A token:** add a row to `catalogs/tokens.json`. Check `decimals()`,
  `symbol()` and `name()` on chain, and mark a proxy `upgradeable`.
- **A contract:** add its ERC-7730 descriptor under `catalogs/` and a line to
  `DESCRIPTORS`. A descriptor outside the subset fails the built-in catalog
  test rather than reaching an owner.

Either change ships with the next Broker release.

## Durable-state compatibility

Storing a policy that carries the extension raises the store's minimum state
version to 2 in the same transaction. A build below that floor refuses to open
the store before it mutates anything.

A build predating the floor has no floor to read. It fails one step later
instead: its strict decoder rejects the unknown `clear_signing` field while
loading the policy. That is fail-closed rather than silent, but it is a
different message, and rollback is never made to work by dropping the field.
The same rule applies to backup and restore.

An unsafe or unreadable theme stops startup because it controls what the
owner sees. The theme file is opened without following symlinks, and
permissions are checked on the same file handle that is read.
