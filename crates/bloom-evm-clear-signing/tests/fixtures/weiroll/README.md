# Pinned Weiroll encoder boundary

`CommandBuilder.sol` is copied byte-for-byte from EnsoBuild/enso-weiroll
commit `900250114203727ff236d3f6313673c17c2d90dd`, contracts/CommandBuilder.sol,
with its GPL-3.0-only license retained.

`ShortcutDifferential.t.sol` preserves the six independently encoded constant,
dynamic, whole-state, array and tuple input vectors used to check the Rust
reader. Run `forge test --root crates/bloom-evm-clear-signing/tests/fixtures/weiroll`.
No /data checkout, network RPC, funded transaction or execution interpretation
is required. Rust state-overwrite, value-call, malformed-input and expansion
regressions remain in src/enso.rs. These fixtures prove encoding, not settlement.
