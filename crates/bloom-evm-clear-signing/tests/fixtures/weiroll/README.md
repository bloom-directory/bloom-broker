# Pinned Weiroll encoder boundary

`CommandBuilder.sol` is copied byte-for-byte from EnsoBuild/enso-weiroll
commit `900250114203727ff236d3f6313673c17c2d90dd`, contracts/CommandBuilder.sol,
with its GPL-3.0-only license retained.

`vectors.json` is consumed directly by the ordinary Rust reader test.
`scripts/weiroll_vectors.py` renders `ShortcutDifferential.t.sol` from those
same six constant/dynamic/whole-state/array/tuple cases and a raw value-call
case. CI checks generation and runs the pinned encoder. FLAG_DATA bypasses
CommandBuilder, so its Solidity case checks the VM's direct slot-copy rule;
it does not execute the VM. Symbolic runtime-selector cases stay in Rust.
Run `forge test --root crates/bloom-evm-clear-signing/tests/fixtures/weiroll`.
No /data checkout, network RPC, funded transaction or execution interpretation
is required. Rust state-overwrite, value-call, malformed-input and expansion
regressions remain in src/enso.rs. These fixtures prove encoding, not settlement.
