#!/usr/bin/env bash
# Full pipeline with no network and no API key.
# The "model" is a scripted replay: response 1 contains deliberate mistakes,
# response 2 is the corrected record. It shows the repair loop, not model quality.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${OUT:-demo-out}"
mkdir -p "$OUT"

echo "== 1. fetch: KEV entry + advisory -> source bundle"
advisory-scope fetch --cve CVE-2024-3400 \
  --kev-catalog tests/fixtures/kev_subset.json \
  --advisory tests/fixtures/advisories/CVE-2024-3400.txt \
  -o "$OUT/source.json"

echo; echo "== 2. extract: scripted model, validator-driven repair loop"
advisory-scope extract --source "$OUT/source.json" \
  --replay tests/fixtures/replay/CVE-2024-3400.json -o "$OUT/result.json"

echo; echo "== 3. validate again, independently"
advisory-scope validate "$OUT/result.json" --source "$OUT/source.json"

echo; echo "== 4. match against the asset corpus"
advisory-scope match "$OUT/result.json" --assets examples/assets.csv --db "$OUT/scans.sqlite"

echo; echo "== 5. same corpus, coarse (but grounded) ranges -> watch the false positives"
advisory-scope match tests/fixtures/naive_CVE-2024-3400.json --assets examples/assets.csv
