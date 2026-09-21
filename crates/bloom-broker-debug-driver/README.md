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
  'https://5ixwab6amyu7e42fjobm3myxqe.relay.bloom.directory/ceremony/#cap=CAPABILITY' \
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

Registration and import accept an optional `--browser-result-file PATH`. When
provided, the driver binds its one-use HPKE output key to the ceremony, decrypts Signer's result, and
creates `PATH` as a private regular file (mode `0600`) without overwriting an
existing file. The file contains the recovery record as JSON:
`{"recovery_id":"…","recovery_secret":"…"}`. Store it outside Machine's
state and do not pass its contents on the command line.

Recovery requires `--browser-result-file` and uses the same authenticated
ceremony URL, a distinct new passkey seed, and the saved recovery record:

```sh
bloom-broker-debug-driver complete \
  'https://5ixwab6amyu7e42fjobm3myxqe.relay.bloom.directory/ceremony/#cap=CAPABILITY' \
  --new-authenticator-seed-file /protected/new-authenticator-seed \
  --recovery-record-file /protected/recovery-record.json \
  --browser-result-file /protected/rotated-recovery-record.json
```

Recovery verifies a new passkey and sends the recovery record only through the
Signer HPKE input. The rotated record is written before the driver acknowledges
delivery. The input and output paths must differ. Recovery requires no old
passkey seed.

The command handles wallet registration, import and recovery, credential add and
replace, sealed approval, wallet deletion, key derivation, account allocation
and retirement, policy update, wallet export, and backend enrollment. Credential
removal and the paired cross-surface enrollment protocol
need their specialized multi-step clients and are rejected by this command.

The localhost form remains available for isolated Triad tests:

```sh
bloom-broker-debug-driver complete \
  'http://localhost:18734/ceremony/#cap=CAPABILITY' \
  --authenticator-seed-file /protected/debug-authenticator-seed \
  --sign-count 1
```
