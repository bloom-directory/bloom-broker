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

## Token artwork

Approval pages use the same chain/address-bound token identities and amounts
for every Petal. Artwork is bundled into Broker; the browser never contacts an
image provider. The small static browser mapping retains issuer-reviewed
SVGs bound to exact chain/address identities. Reviewed neutral bindings
prevent pegged copies and pUSD from borrowing Circle's mark. CI checks this
mapping and browser identity boundaries offline. Long-tail artwork and its
acquisition pipeline remain preserved at Broker commit `2b7033a39163513a39b387a83abbaca80fcd0268`
for separate review. A logo is decorative and never establishes identity, token
behavior or decimals; a missing image uses the neutral icon.

## Released policy migration

Released catalog restrictions retain their exact canonical representation and
signature. Wallets carrying that extension or its required verifier cannot
prepare, activate or use signing authority until an owner approves a policy
replacement. Inspection and cancellation remain available. The policy ceremony
names removed trust keys, freshness and verifier restrictions and opaque or
unlimited-allowance refusals. Compiled descriptions do not enforce those rules.
Unrelated policy fields are retained unless explicitly changed. Policy-version
and digest binding keep old grants invalid after replacement. Broker stores
advance to version 3 before writing these manifests; released readers refuse
that version. Restore a pre-upgrade backup when returning to a released binary.

## Assurance levels

### Signed messages

An exact Petal approval can supply one `message_review_payloads` envelope:
`{"schema":"bloom.message.review.v1","kind":"eip712","typed_data":{...}}`
or `{"schema":"bloom.message.review.v1","kind":"personal","message":"..."}`.
Broker rebuilds the EIP-712 or EIP-191 preimage and checks both its SHA-256
payload commitment and Keccak signing hash against the exact selector. It
rejects mixed transaction/message reviews, batches, unused JSON members,
recursive types and oversized structures. Every typed leaf is displayed.
The reading and warnings are included in the signed review manifest.

Canonical ERC-3009 payment authorizations show the exact payer, recipient,
validity interval and amount. Units and artwork come only from the compiled
chain/address token catalog; unknown contracts retain raw units. The payer
must equal the approved signing account. A recognized login-message layout
shows its signed website, account, URI, nonce and session fields. Other
personal messages remain complete escaped text. This is not full ERC-4361
validation: Bloom does not authenticate the named website, validate session
permissions, or promise that a server accepts a timestamp or signature.

Gasless Relay and Venice's login/payment operation classes require this
envelope and refuse reusable or batch signing paths. For other Petals this
reader remains optional until their callers forward an envelope. A protocol's hash-of-action fields remain
hashes: decoding them does not establish the underlying order or action.

Hyperliquid owner operations also carry review envelopes. User-signed typed
messages are recognized only with the exact supported domain and canonical
type; agent authorization explicitly states that the venue receives trading
authority without the Petal's local spending/duration limits. Mainnet USDC
venue balances have a specific asset binding; test collateral stays neutral.
USD sends and withdrawals must declare the exact signed debit, recipient and
approval amount. The EIP-712 chain ID is a signing domain, not the venue or
withdrawal network.

`kind: "hyperliquid_l1"` supplies `network`, `action`, `nonce`, optional
`vault_address` and `expires_after`. Broker re-encodes supported orders,
cancellations, scheduled cancellations and leverage changes as ordered
MessagePack, rebuilds the action hash and EIP-712 Agent preimage, and checks
the exact selector. Unused JSON is refused. Every action leaf, including
builder fees, is displayed. An unknown market ID retains that exact ID and
an unverified-identity warning; no ticker or market artwork is guessed.
Existing delegated-agent grants remain a separate approval of future scope,
not a claim that each later session action received an owner review.

Every `hyperliquid.agent_action` signing use must carry the same complete L1
witness in `claim_assurance_evidence`. Broker independently reconstructs its
preimage before authority reservation or signing; a missing or mismatched
witness is refused, including for grants prepared before this upgrade. This
uses the existing evidence channel and does not add a ceremony per trade.
The claim remains `MachineAsserted`: market identities, venue effects and
Petal-local session limits are not independently established. Use-time
batches retain the input/node/array bounds and allow up to 4096 reading
fields; owner pages retain their 256-field display bound. Upgrade the
Hyperliquid package with Broker; older hash-only agent callers are refused.

These operation-class contracts require coordinated Petal publication and
Machine catalog repinning with the Broker release. Do not ship the reader's
mandatory classes while the default catalog still distributes older callers.

### Contract calls

Every reading is display: it is shown to the owner and signed with the review
manifest, and no authority is derived from it. A reading has one of two
assurance classes:

- `trusted_description`: every contract the call reaches is listed in the
  catalog. It is **not** proof of execution, contract safety, or the absence
  of an upgrade since the release. Broker reads no chain state and resolves no
  proxy.
- `structural_description`: some part of the reading names a contract the
  catalog does not identify. That is a call read by its ERC-20 shape alone
  (exact counterparty and raw amount, no token identity), an address read
  through an [instance or standard
  description](#instance-and-standard-descriptions), or an amount in an
  unlisted token.

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
  and `bytesN`; dynamic `bytes`; dynamic arrays of one static scalar
  (`address[]`, `uint256[]`, ...); and dynamic arrays of a tuple of those
  scalars or `bytes`, with named components (`(address to, bytes data)[] calls`).
- Named direct tuples and fixed arrays of admitted types, expanded to at most
  32 leaves. Fixed dimensions are 1–32, with at most eight tuple levels.
- Named field paths, optionally spelled `#.name`: `name`, `name.[]` for each
  element of a scalar array, and `name.[].component` for each element of a
  tuple array. An array is shown element by element, each field labelled with
  the element's position.
- Nested component paths such as `proof.pubSignals.[2]` and the transaction
  container path `@.value`. Native transaction value must use an always-visible
  `amount` field and an explicitly listed deployment; it cannot be hidden,
  shown as raw units, or admitted by instance/standard selector matching.
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
  `mustMatch`), and `mustMatch` on a whole array. `mustMatch` on
  `name.[].component` holds for every element.
- `tokenAmount` parameters other than `tokenPath` — in particular `threshold`
  and `message`, which is how the registry's ERC-20 template labels a large
  *finite* allowance "unlimited". An admitted derivative must drop them;
  Bloom's own maximum-U256 rule owns that warning.

  `tokenPath` itself takes either `"@.to"`, meaning the contract being called
  is the token, or the name of a top-level address argument of the same call.
  In the second form the address that was actually decoded is looked up in the
  catalog, and that token's entry is listed with the review. A token
  the catalog does not list is shown in raw units with its address, never with
  borrowed decimals, and the review is structural. A token path that names a non-address argument, or no argument
  at all, is refused at admission.
- `date` with `blockheight` encoding, which cannot be converted offline.
- `enum` references outside a local `$.metadata.enums` map, and any value the
  map does not label.
- `metadata.token`, `metadata.constants`, `metadata.maps`: units come from the
  catalog's token rows, not from the document.
- Any argument left off the screen. Every decoded leaf must be covered by a
  visible field naming its actual path.
- `string`, nested dynamic arrays, unnamed tuple components and signed integers.
- `calldata` parameters other than `calleePath` and `amountPath`. `selector`,
  `spender` and `chainId` would each change how the inner call is read.

`addressName` name sources are inert: no ENS request, no account-type
assertion, no sentinel substitution. The raw address is what is shown.

## Embedded calls

A `calldata` field reads a call carried inside this one. `calleePath` names the
contract it calls, as `"@.to"` or an address argument. The optional
`amountPath` names a uint argument holding the native value it sends. In a list
of calls (`bundle.[].data`), both come from the same element
(`bundle.[].to`, `bundle.[].value`), so each call is read with its own target.
The inner call is reviewed exactly as a top-level call:

- An inner call Bloom cannot read makes the whole call unsupported.
- Its warnings are retained, so an unlimited allowance inside a Safe receives
  the same strong warning as an allowance outside one. It is not denied just
  for being unlimited or unreadable.
- Its catalog entries are listed with the review.

An inner canonical `transfer` or `approve` to a contract the catalog does not
list is read by its shape, as at the top level: recipient or spender and raw
amount, the unverified-token warning, and the same unlimited-allowance warning.
The review is then `structural_description`.

The page shows one heading line, `<function> on <contract>`, then the inner
call's fields labelled under it (`Safe transaction · Amount`). The inner
call's warnings are prefixed the same way.

Empty inner calldata is a plain value transfer, shown as `Send <amount> to
<callee>`, or `No call` when the amount is zero. Calls nest at most two deep.

## Instance and standard descriptions

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

A **standard** description (`Binding::Standard`, such as
`catalogs/standards/erc4626.json`) has no deployments. It reads any address no
entry or instance description covers, on any chain, by selector: a vault's
`deposit`, `mint`, `withdraw` and `redeem`. Underlying amounts use an exact
compiled vault binding when available; unknown underlying assets and share
quantities remain raw. The same ERC-20 rule applies.

Such a call gets the structural assurance and a warning that Bloom has not
verified the address is that contract. The review records the address it was
read for.

The address not being verified is bounded by a rule: an instance or standard
reading carries no native value. A call to an address that is not what it claims
can spend only gas and whatever allowances this wallet already gave that
address.

## Safe

`catalogs/safe` holds Bloom's Safe descriptors, derived from `registry/safe` in
LedgerHQ/clear-signing-erc7730-registry. They cover the official Safe
singletons and proxy factories (1.3.0, 1.4.1, 1.5.0) on chains 1, 10, 100, 137,
8453 and 42161. Safe 1.4.1, the version the Safe Petal deploys, is the instance
address on each chain. Its `execTransaction` and owner-management functions are
identical in 1.3.0 and 1.5.0.

`mustMatch` and one rule in code hold the Safe safety rules:

- A delegatecall runs code as the Safe, so `execTransaction` may delegatecall
  only Safe's own libraries: CreateCall, described in `catalogs/safe`, and
  MultiSendCallOnly (1.3.0, 1.4.1, 1.5.0). That batch library's
  packed format is not ERC-7730, so Broker reads it in code: each call is
  shown as an embedded call, `Transaction 1`, `Transaction 2`, and reviewed as
  a top-level call would be. A call inside a batch must be a plain call to a
  nonzero address; an empty or truncated batch is refused.
- No gas refund: `gasPrice`, `gasToken` and `refundReceiver` must be zero.
- A new Safe uses an official singleton, has no setup call, no setup payment,
  and either an official fallback handler or none.

Owner signatures are shown raw and are not checked by Bloom.

## Morpho

`catalogs/morpho` describes Bundler3's `multicall` and GeneralAdapter1's
`erc20TransferFrom` and `erc4626Deposit` on chains 1, 10, 137, 8453 and 42161:
the protected deposit the Morpho Petal stages. Every call component is shown
or fixed: no callbacks and no skipped reverts. A withdrawal from the vault is
read by the ERC-4626 standard description.

## Safety rules over the generic result

These inspect the decoded values; they do not select a different decoder.

| Class | Rules |
| --- | --- |
| `transfer` | Must be canonical `transfer(address,uint256)`. Zero recipient refused; the token contract is not a valid recipient of its own transfer; listed decimals required; a zero amount is displayed honestly. |
| `allowance` | Must be canonical `approve(address,uint256)`. Zero spender refused; zero means clearing the allowance; a finite value sets a total, not an increment; exact U256 maximum receives a strong unlimited-allowance warning. |
| `other` | Neutral heading, supplemental intent, every argument shown, no economic guarantee invented. |

The class is derived from the function signature, never declared: only the
canonical ERC-20 signatures get the `transfer` and `allowance` rules, so
`approve` relabelled "Login" still gets the allowance rules, and an unrelated
three-argument call never gets the transfer screen.

## Catalog

`catalog.rs` lists the compiled-in descriptor files in `DESCRIPTORS`, each with
its optional instance address. Tokens are listed once, in
`bloom-broker-api/tokens/tokens.json`, which Machine compiles in too:

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

### Privacy Pools

The mainnet Entrypoint native deposit displays exact transaction value and note
precommitment. Its UUPS proxy binding is explicitly upgradeable. The ETH pool's
direct withdrawal displays the required caller/recipient, public-signal amount
in ETH and every proof field. Only empty withdrawal data is admitted: relayed
withdrawals have a different processor/recipient relationship and cannot borrow
this reading. Fees, credited deposit amount, proof validity and settlement are
not verified offline. Source revisions and deployments are recorded in the two
`catalogs/privacy-pools` descriptors. No private relay payload is added to
agent-visible records by this reader.

### Vault underlying assets

`vaultAssetAmount` is a Bloom extension whose `vaultPath` is `@.to` or a decoded
address argument. It resolves only the compiled chain/vault binding in
`catalogs/vault-assets.json`, then takes units and artwork identity from the
underlying token's existing catalog entry. Unknown vaults keep explicit raw
underlying units and no borrowed token identity. Share quantities remain shares;
they never use the underlying token's decimals or logo.

The initial Base binding covers vault
`0xc1256ae5ff1cf2719d4937adb3bbccab2e00a2ca` and underlying USDC. Both public
RPCs agreed at the recorded block, including its hash, asset and decimals.
The runtime bytecode matched Sourcify's exact verified MetaMorpho source,
whose inherited asset getter returns a private immutable asset. The file
retains the block/code/source digests and verification limits. Broker remains
offline: this is trusted release-time metadata, not a fresh code, price, balance
or settlement attestation.

### Enso Router V2 inputs and requested output checks

The catalog covers all twelve networks accepted by the Enso Petal: Ethereum,
Base, Polygon, BNB, Arbitrum, Optimism, Avalanche, Gnosis, HyperEVM, Linea,
Tempo and Robinhood. Addresses are network-specific; another deployment or
network does not inherit an Enso identity. The Petal prepares same-chain routes
with Router V2 output checks and preserves their actual floor across refresh.

The listed Router V2 deployments read `routeSingle` and `routeMulti` source
envelopes. Bloom's `ensoToken` format binds a bytes field to its sibling uint8
`typePath`: native inputs show the transaction's actual value; ERC-20 inputs
strictly decode `(address,uint256)` and use that exact chain/address's catalog
units. Unknown tokens keep raw units. Empty lists, duplicate native inputs,
dirty address padding, unsupported NFT inputs and ERC-20-only calls carrying
native value are refused by this reading.

`safeRouteSingle` and `safeRouteMulti` also read the receiver and output
balance-increase minimums. `ensoTokenOutput` uses the output's own canonical
bytes: native output minimums decode one uint256 instead of borrowing the
transaction value, while ERC-20 minimums bind their exact token address and
units. Outputs never count as source inputs or authorize native input value.
An empty output list explicitly warns that no minimum requires funds to
arrive. Unknown tokens stay raw and unsupported NFT layouts remain explicit.

The `ensoShortcut` format reads canonical `executeShortcut` programs against
Enso Weiroll revision `900250114203727ff236d3f6313673c17c2d90dd`. It reads
CALL, STATICCALL and value calls, raw calldata, extended indices, nested
arrays/tuples and whole-state arguments. Constant inputs reconstruct the exact
inner calldata and use the existing catalog reader. Return values remain
symbolic: reading an overwritten state slot never reuses its initial literal.
Unknown calls retain their target, arguments, bytes and inability-to-read reason.
The pinned VM does not support delegatecall; other program entry points and
malformed programs retain exact bytes and an explicit undecoded warning.

Programs are bounded to 64 KiB source and total reconstructed call bytes,
64 command words, 128 initial slots, eight dynamic nesting levels and the
VM's ten-entry dynamic table. Recursive call interpretation remains bounded.
Technical details retain the complete structured program and nested readings.

This is partial coverage: ordinary source envelopes do not establish outputs
or recipients. Runtime return values, code and effects are not verified. Safe-route
fields describe requested contract balance checks, not proof of received
funds, runtime code, intermediate effects, fees or settlement. The review
remains structural and displays that warning.
It does not rename a quoted route into a verified swap.

Decoded token-amount fields carry their exact catalog identity, chain and
formatted amount to the approval UI, including inside nested calls. This gives
source inputs their own asset cards without misidentifying the router as the
token. Unknown addresses have no asset identity or borrowed logo. Privacy proof
words and Enso's full shortcut program remain in the expandable technical review;
amounts and counterparties lead the decision.

## The owner decides

There is no setting. Every wallet gets every reading Broker can produce, and
nothing is refused for being unreadable. A call Bloom cannot read is shown as
exact bytes with the inability-to-explain warning and the reason: no
description of the contract, or bytes the description does not admit. The
owner approves or rejects it like any other.

A maximum-U256 `approve(address,uint256)` is shown with the strong unlimited
warning, never refused. The rule matches only that exact value: one less is
shown as a finite allowance with its exact amount. Other calls that grant
spending power, such as `increaseAllowance`, `setApprovalForAll` or Permit2's
`approve`, are not recognised as allowances: a descriptor that formats one
reads it as `other`, with no allowance warning.

## Safe owner signatures

When an owner signs a Safe transaction, its inner calls are read with the same
catalog as native calls, including the ERC-20 shape reading. A call it cannot
read is shown as exact bytes with the reason, as anywhere else.

## Adding to the catalog

- **Tokens:** before each release, run `python3 -I tokens/tokens.py >
  tokens/tokens.json` in `crates/bloom-broker-api`. It rebuilds the list from the Uniswap default list,
  CoinGecko's Gnosis list and Robinhood's Stock Token registry, keeps a token
  only if its address has code and its `decimals()` matches, and marks
  proxies `upgradeable`. A new family of tokens is a new source in
  `tokens.py`, not a hand-edited row.
- **A contract:** add its ERC-7730 descriptor under `catalogs/` and a line to
  `DESCRIPTORS`, binding it to its listed deployments, to per-user instances
  of one deployment, or as a standard. A descriptor outside the subset fails
  the built-in catalog test rather than reaching an owner.

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
