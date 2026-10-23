# Solana transaction readings

This is a network-free structural reader, separate from the policy-pinned
`bloom-solana-verify` native-transfer proof verifier. Display catalogs and v0
support must not change that verifier's source identity or accepted language.
The native verifier's covered sources are unchanged.

The reader handles bounded canonical legacy/v0 messages, static signer and
writable roles, lookup-table references, System transfers/account creation,
Compute Budget limits/prices, associated token creation, SPL Token/Token-2022
transfer/checked transfer/close/sync, and the selected Pump/PumpSwap trade and
launch instructions in the compiled catalog. Unknown programs/instructions,
malformed arguments or trailing bytes retain exact bytes and an explicit reason.
Token quantities remain raw; declared decimals are not promoted to verified
metadata. Program code, CPI effects, account state, cluster, fees, lookup
contents and settlement are not established by decoding a message.

`catalogs/pump.json` retains instruction discriminators, argument layouts and
ordered account names from the official Pump IDLs at immutable revision
`639b87fb45c3adeffa6f7c4a1bf0cb85e392bf22`:

- https://github.com/pump-fun/pump-public-docs/blob/639b87fb45c3adeffa6f7c4a1bf0cb85e392bf22/idl/pump.json
- https://github.com/pump-fun/pump-public-docs/blob/639b87fb45c3adeffa6f7c4a1bf0cb85e392bf22/idl/pump_amm.json

Only the selected trade/launch instruction family is compiled. Account names
are the IDL's positional labels, not proof of ownership or program behavior.
Missing trailing `OptionBool`/`OptionU64` wrapper bytes are shown as not encoded;
the program's default is not invented. Extra accounts remain visible.

The blockhash-independent digest has its own versioned domain. It binds the
canonical message version, all static keys/roles, lookup table keys/indices,
instruction order/accounts and every data byte; only the 32-byte recent
blockhash is replaced with zeroes. Referenced lookup contents remain unresolved.

Tests retain six captured builder messages with full source provenance, compare
v0 serialization with the pinned Anza reference and mutate every message byte
to check that only blockhash changes preserve the binding. Native transfer
golden/proof tests continue in their original crate.
