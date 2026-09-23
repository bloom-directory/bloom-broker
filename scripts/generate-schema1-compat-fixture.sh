#!/bin/sh
set -eu

schema1_commit=dd2add2b9d41540521d08c77d19fb467a2d8029e
repo_root=$(git rev-parse --show-toplevel)
worktree=$(mktemp -d "${TMPDIR:-/tmp}/bloom-broker-schema1.XXXXXX")
target_dir=${BLOOM_SCHEMA1_TARGET_DIR:-"${TMPDIR:-/tmp}/bloom-broker-schema1-target"}
output="$repo_root/crates/bloom-broker/tests/fixtures/schema1/broker-journal.sqlite"
scratch_output="$output.tmp.$$"

cleanup() {
    rm -f "$scratch_output"
    git -C "$worktree" checkout -- crates/bloom-broker/tests/w5_ceremony.rs \
        >/dev/null 2>&1 || true
    git -C "$repo_root" worktree remove "$worktree" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

git -C "$repo_root" worktree add --detach "$worktree" "$schema1_commit"
python3 - "$worktree/crates/bloom-broker/tests/w5_ceremony.rs" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
anchor = '''        "a persisted custody status must expose the signed receipt digest after restart"
    );
'''
injection = anchor + '''    if let Some(output) = std::env::var_os("BLOOM_SCHEMA1_FIXTURE_OUT") {
        restarted_ceremony.prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("31"),
                wallet_id: Some(Token::new("schema1-pending-wallet").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("33"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_requests: Vec::new(),
            },
            now_ms + 2_000,
        ).unwrap();
        let output = output.to_string_lossy().replace('\\'', "''");
        rusqlite::Connection::open(&broker_journal_path).unwrap()
            .execute_batch(&format!("VACUUM INTO '{output}'")).unwrap();
    }
'''
if source.count(anchor) != 1:
    raise SystemExit("released fixture anchor changed")
path.write_text(source.replace(anchor, injection))
PY

rm -f "$scratch_output"
BLOOM_SCHEMA1_FIXTURE_OUT="$scratch_output" CARGO_TARGET_DIR="$target_dir" \
    cargo test --locked --manifest-path "$worktree/Cargo.toml" \
    -p bloom-broker --test w5_ceremony \
    policy_service_requires_completion_then_commits_and_replays_over_authenticated_rpc \
    -- --exact
mv "$scratch_output" "$output"
shasum -a 256 "$output"
