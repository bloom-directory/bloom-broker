#!/usr/bin/env bash
set -euo pipefail
# The released source has fixture-only test hooks on the published
# released-policy-fixture branch; its production source is unchanged from
# 9f394aebbc9c04a6031de31a12385e5485f8ca9b (Bloom v0.4.0 compatibility).
candidate_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
released_root="${BLOOM_RELEASED_BROKER_FIXTURE_ROOT:?set the owned released-policy-fixture checkout}"
git -C "$released_root" merge-base --is-ancestor 9f394aebbc9c04a6031de31a12385e5485f8ca9b HEAD
git -C "$released_root" diff --quiet 9f394aebbc9c04a6031de31a12385e5485f8ca9b HEAD -- \
  Cargo.toml Cargo.lock crates/bloom-broker/src crates/bloom-broker-api/src
evidence_root="${BLOOM_POLICY_UPGRADE_EVIDENCE_ROOT:-$(mktemp -d /tmp/bloom-policy-upgrade.XXXXXX)}"
mkdir -p "$evidence_root"
for kind in plain legacy; do
  legacy=()
  if [[ "$kind" == legacy ]]; then legacy=(BLOOM_PM80_LEGACY_POLICY=1); fi
  env -u BLOOM_PM80_LEGACY_POLICY "${legacy[@]}" BLOOM_PM80_RELEASED_STORE_OUT="$evidence_root/$kind" \
    cargo test --locked --manifest-path "$released_root/Cargo.toml" -p bloom-broker \
    --test w5_ceremony policy_service_requires_completion_then_commits_and_replays_over_authenticated_rpc -- --exact
  BLOOM_PM80_RELEASED_STORE="$evidence_root/$kind" \
  BLOOM_PM80_UPGRADED_STORE_OUT="$evidence_root/upgraded-$kind" \
    cargo test --locked --manifest-path "$candidate_root/Cargo.toml" -p bloom-broker \
    --test w5_ceremony released_legacy_policy_migrates_through_the_real_signer_boundary -- --ignored --exact
done
BLOOM_PM80_RELEASED_STORE="$evidence_root/legacy" \
BLOOM_PM80_UPGRADED_STORE="$evidence_root/upgraded-legacy" \
  cargo test --locked --manifest-path "$released_root/Cargo.toml" -p bloom-broker \
  --test w5_ceremony pm80_released_reader_refuses_the_upgraded_floor_and_accepts_the_backup -- --ignored --exact
printf 'Disposable software-owner evidence retained at %s\n' "$evidence_root"
