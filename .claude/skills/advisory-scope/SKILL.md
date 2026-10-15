---
name: advisory-scope
description: Extract affected products and version ranges from a vendor security advisory or CISA KEV entry into the advisory-scope strict JSON schema, gate it with the deterministic validator, and optionally match it against an asset CSV. Use when asked to scope a CVE/advisory, build affected-version ranges, or check which assets an advisory hits.
---

# advisory-scope skill

In this mode **you** are the extractor and the `advisory-scope` CLI is the
gate. A record is not done until `advisory-scope validate` exits 0. Never
present an unvalidated record as a result.

## Steps

1. **Build the source text** (this exact text is what claims are checked against):
   - KEV + linked vendor advisory: `advisory-scope fetch --cve <CVE> --follow-notes -o work/source.json`
   - Advisory the user pasted or attached: save it verbatim to `work/advisory.txt`,
     then `advisory-scope fetch --advisory work/advisory.txt [--cve <CVE>] -o work/source.json`
   - If `fetch` prints a note that the page needs JavaScript, ask the user to paste the advisory text.

2. **Read the rules**: `advisory-scope schema` prints the contract. The modeling
   rules are in `src/advisory_scope/agent.py` (`SYSTEM_PROMPT`); follow them
   exactly. The essentials:
   - Use only the source text; no outside knowledge of the CVE.
   - Evidence = verbatim spans copied from the source (8+ chars).
   - Every version string must appear in the source (except `introduced: "0"`
     and an introduced/branch that is a prefix of the same range's upper bound).
   - One range per release line; per-maintenance-release hotfix lists become one
     range each (never one wide range).
   - Separate editions (FIPS, NDcPP) are separate products.
   - Configuration prerequisites go in `conditions`.

3. **Write the record** to `work/record.json`.

4. **Validate**: `advisory-scope validate work/record.json --source work/source.json`
   - Exit 2: fix exactly the reported errors and re-run. At most 3 rounds.
     Do not edit `source.json` to make a check pass, and do not invent text.
     If the source cannot support a value, remove it and say so in `extraction_notes`.
   - Warnings: fix if the source supports a fix; otherwise report them.
   - `info` / `uncovered_versions`: check each listed version for a missed release line.

5. **Optional - match assets**: `advisory-scope match work/record.json --assets <assets.csv>`

## Report back

- Validation status (PASS / FAIL, and whether human review is required)
- Affected products and ranges as a short table
- Conditions and not-affected products
- Anything in `extraction_notes` and any unresolved warnings
- Match summary and KPIs if step 5 ran

If validation still fails after 3 rounds, report the remaining errors as-is.
Do not claim success.
