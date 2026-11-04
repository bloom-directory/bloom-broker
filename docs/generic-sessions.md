# Recurring declared-effects allowances

Broker trusts the pinned, installer-signed package's effects-v1 declaration.
Generic EIP-712 and EIP-191 review reconstruction binds the actual signing bytes,
without proving that a declared debit matches those bytes. Owner review uses
the installer-signed package display name and exact token identities from the
compiled token catalog. Symbols never select authority and no prices apply.

Bounded spending requires positive checked uint256 amounts, explicit payload
network and exact account bindings, no continuing permission effect, and active
owner-reviewed token limits. Different assets never net. Explicit zero spend
requires a certified class named in a Trader or Degen grant, no debit/fee, and
valid payload indexes and accounts. Zero-spend class consent covers any network;
it has no token spending limit and can risk venue balances or margin. Its one
rate cap is shared by all zero-spend classes in that grant. Institutional grants
have no automatic tier. Absence of effects is unspecified, never zero spend.

One automatic operation signs exactly one payload. All reservations, including
zero-use rate admissions, commit atomically into the existing authenticated
journal. Reserved, committed and ambiguous uses count. Definitive release frees
capacity. Retrying the same operation does not charge again; unlocking/rearm
retains budget identity and usage. New package/account grants need fresh owner
review and explicitly grant new independent capacity. Allowances add across
packages/accounts; routes within one allowance share token usage.

Limits govern signed volume per rolling window, not outstanding exposure.
Cancelling signed orders does not refund usage; open orders are not limited by
the window. Keep the journal and its authenticated accounting history intact.

Native wallet EVM/ERC20 and SOL transfers retain independent standard byte,
recipient and fee checks. The native selector is `native_session`. Degen's
any-recipient opt-in applies only to explicitly reviewed ERC20 transfers and
native gas caps. It does not enable approvals or arbitrary consumer calls.

Valid requests outside coverage need exact review after authenticated operation
status establishes that no retained reservation/result exists. Malformed input,
invalid provenance and mismatched review/signing bytes fail outright. There is
no protocol profile evaluator, chain-read trust scheme or wallet-wide ceiling.
