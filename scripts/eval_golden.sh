#!/usr/bin/env bash
# Live eval: run the real model on every golden advisory and diff against the
# hand-checked golden record. Needs ANTHROPIC_API_KEY. Costs a few API calls.
set -uo pipefail
cd "$(dirname "$0")/.."
OUT="${OUT:-eval-out}"
mkdir -p "$OUT"
: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY first}"

status=0
for golden in tests/fixtures/expected/*.json; do
  cve="$(basename "$golden" .json)"
  echo "=== $cve"
  advisory-scope fetch --cve "$cve" --kev-catalog tests/fixtures/kev_subset.json \
    --advisory "tests/fixtures/advisories/$cve.txt" -o "$OUT/$cve.source.json" 2>/dev/null
  if advisory-scope extract --source "$OUT/$cve.source.json" -o "$OUT/$cve.result.json"; then
    advisory-scope diff "$OUT/$cve.result.json" "$golden" | tee "$OUT/$cve.diff.json"
  else
    echo "$cve: extraction did not pass validation (see $OUT/$cve.result.json)"
    status=1
  fi
done
exit $status
