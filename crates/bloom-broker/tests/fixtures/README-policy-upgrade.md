# Released policy upgrade fixture

Run `bash scripts/test-released-policy-upgrade.sh` with
`BLOOM_RELEASED_BROKER_FIXTURE_ROOT` pointing at an owned checkout of
Broker `4885a77f7741f63aa04b131d091039716b14dffc`,
branch `released-policy-fixture`. Its only changes from released Broker
`9f394aebbc9c04a6031de31a12385e5485f8ca9b` are fixture hooks in
w5_ceremony.rs; the script verifies its production/API sources and dependency
inputs are unchanged. Both sides use released Signer
`bc88ad690757165ebf1978410ea5c7ec652215d3` and runtime
`ad0072512bb97fb4eb68d249ce785ea3ea4a49ab`.

The released test executable creates disposable stores and enrolls a
deterministic software owner, with and without the old policy extension.
Candidate services open the signed policy unchanged, block signing before
migration, cancel a real migration without altering policy, complete an
owner-approved replacement, recover its committed Signer outcome, reject old
policy bindings and sign a fixture payload under fresh authority. The original
reader then refuses the upgraded floor and accepts the original backup.

The SQLite files contain disposable encrypted test custody and are retained
only in the printed scratch directory. They are not production credentials or
release inputs. No real wallet is opened and no venue transaction is sent.
This is a software-owner service fixture, not installed-bundle or physical
passkey evidence. Existing authority and service tests cover stale baselines,
signature tampering, retained grants and restart/replay failures separately.
