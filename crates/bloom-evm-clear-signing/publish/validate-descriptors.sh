#!/usr/bin/env bash
# Validate ERC-7730 descriptor sources against the pinned v2 schema and write
# the report `bloom-clear-signing-catalog build --schema-report` requires.
#
#   validate-descriptors.sh <schema.json> <descriptor.json>... > report.json
#
# The schema file must be assets/erc-7730/erc7730-v2.schema.json from
# ethereum/ERCs at the commit this build pins. Its digest is checked here, so
# validating against a different revision of the schema cannot produce a
# report `build` will accept. Fetch it once, out of band, and keep it:
#
#   curl -fsSLO https://raw.githubusercontent.com/ethereum/ERCs/<commit>/assets/erc-7730/erc7730-v2.schema.json
#
# Validation itself is upstream tooling, not ours. `check-jsonschema` (pipx
# install check-jsonschema) is used when present; any JSON Schema 2020-12
# validator can be substituted through VALIDATOR, as long as it exits
# non-zero on a document that does not conform.
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <schema.json> <descriptor.json>..." >&2
    exit 2
fi

schema=$1
shift

# The pins this repository was written against, printed by the tool itself so
# the two can never drift apart silently.
pins=$(cargo run --quiet -p bloom-evm-clear-signing --bin bloom-clear-signing-catalog -- schema-pin)
commit=$(printf '%s\n' "$pins" | sed -n 's/.*ethereum\/ERCs@\([0-9a-f]\{40\}\).*/\1/p')
expected=$(printf '%s\n' "$pins" | sed -n 's/.*sha256 \([0-9a-f]\{64\}\).*/\1/p')
actual=$(sha256sum "$schema" | cut -d' ' -f1)

if [ "$actual" != "$expected" ]; then
    echo "$schema is sha256 $actual, not the pinned $expected" >&2
    exit 1
fi

validator=${VALIDATOR:-check-jsonschema}
if ! command -v "$validator" >/dev/null 2>&1; then
    echo "$validator not found; install it (pipx install check-jsonschema) or set VALIDATOR" >&2
    exit 1
fi
version=$("$validator" --version 2>&1 | head -1)

"$validator" --schemafile "$schema" "$@" >&2

printf '{\n  "schema_commit": "%s",\n  "schema_sha256": "%s",\n  "validator": "%s",\n  "validated": {\n' \
    "$commit" "$expected" "$version"
separator=""
for descriptor in "$@"; do
    printf '%s    "%s": "%s"' "$separator" "$descriptor" "$(sha256sum "$descriptor" | cut -d' ' -f1)"
    separator=$',\n'
done
printf '\n  }\n}\n'
