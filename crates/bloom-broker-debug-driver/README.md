# Bloom Broker debug driver

This test-only executable completes Broker ceremonies with a deterministic
software authenticator. Production Broker and Signer artifacts do not link it.
It produces real ES256 WebAuthn proofs and HPKE inputs against the same public
contracts used by a browser, but it is not a substitute for real-browser
acceptance evidence.

`complete` accepts either the canonical localhost ceremony URL or an assigned
hosted-relay launch URL:

```sh
bloom-broker-debug-driver complete \
  'https://5ixwab6amyu7e42fjobm3myxqe.relay.bloom.directory/#cap=CAPABILITY' \
  --authenticator-seed-file /protected/debug-authenticator-seed \
  --sign-count 1
```

The seed file must be a regular file inaccessible to group and other users.
For a remote launch, the driver requires HTTPS under the assigned
`relay.bloom.directory` namespace and normal platform certificate validation.
It exchanges the one-use fragment capability, verifies the exact scoped
`Secure`, `HttpOnly`, `SameSite=Strict` cookie, and uses the returned CSRF proof
for completion. WebAuthn client data and RP hashes bind the exact remote origin
and hostname. The driver does not print PRF material.

The command handles wallet registration and import, credential add and
replace, sealed approval, wallet deletion, key derivation, account allocation
and retirement, policy update, wallet export, and backend enrollment. Wallet
recovery, credential removal, and the paired cross-surface enrollment protocol
need their specialized multi-step clients and are rejected by this command.

The localhost form remains available for isolated Triad tests:

```sh
bloom-broker-debug-driver complete \
  'http://localhost:18734/ceremony/CAPABILITY' \
  --authenticator-seed-file /protected/debug-authenticator-seed \
  --sign-count 1
```
