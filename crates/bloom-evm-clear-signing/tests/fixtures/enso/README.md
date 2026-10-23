# Protected swap preview input

`petal-protected-swap.json` is the exact output of Enso Petal
`protected_swap_ceremony_fixture` at commit
`84e9e7c` (PR 16). The test runs the normal create workflow with a deterministic
mocked quote of 3 USDC for 0.001 ETH on Base. The Petal applies its 50 bps
slippage floor, producing a signed-call minimum of 2.985 USDC at the account's
address. Broker independently decodes these bytes; its test compares the
result and source transaction with the production renderer's preview data.

The upstream shortcut is empty test data. This fixture establishes review
content and the Petal's output envelope, not venue executability, a live
quote, passkey acceptance or received funds.

Regenerate from the Enso checkout:

```sh
BLOOM_UI_FIXTURE_DIR=/path/to/evidence cargo test --locked \
  --manifest-path route/Cargo.toml protected_swap_ceremony_fixture
```

Compare that `enso-petal-swap.json` byte for byte with this fixture. Then run
Broker's `cargo test --locked -p bloom-evm-clear-signing --test enso`.
To export the independent reading for an intentional preview refresh, set
`BLOOM_UI_FIXTURE_DIR` on that command too.
