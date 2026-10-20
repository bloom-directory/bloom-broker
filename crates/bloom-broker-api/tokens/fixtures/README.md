# Offline catalog update evidence

The 2026-10-20 pUSD fixture captures public curated-source documents and their
SHA-256 digests, the exact selected identity, pinned block number/hash, raw
code, decimals/name/symbol results and both checked proxy slots. Capture
verifies the block hash again after reading. The gzip uses deterministic mtime 0.

Regenerate the row offline with the CI command in .github/workflows/ci.yml.
The capture command was:

```sh
python3 -B crates/bloom-broker-api/tokens/tokens.py --capture inputs.json --only 137:0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb
```

This is a new observation, not invented provenance for older catalog rows.
It supplements the existing pusd-observation.json and preserves its limitations.
Two proxy slots do not prove that another contract cannot upgrade.
