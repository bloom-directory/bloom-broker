# Token catalog evidence

`inputs-2026-10-22.json.gz` is a full capture of every candidate token:
the curated source documents with their SHA-256 digests, one pinned block
number and hash per chain, and each token's raw code, decimals/name/symbol
results and proxy slots at that block. Capture verifies each block hash again
after reading. The gzip uses mtime 0.

CI derives the catalog from this capture offline and requires it to equal
`tokens.json` row for row. When the catalog changes, recapture and replace
this file:

```sh
python3 -I -B crates/bloom-broker-api/tokens/tokens.py --capture inputs.json > crates/bloom-broker-api/tokens/tokens.json
```

then gzip `inputs.json` with mtime 0. Two proxy slots do not prove that a
contract cannot be upgraded another way.
