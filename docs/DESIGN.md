# Design notes

Why each piece is the way it is. If you only read one section, read "LLM proposes, validator disposes."

## LLM proposes, validator disposes

There are two separate guarantees, and they come from two separate mechanisms.

| Question | Mechanism | Deterministic? |
|---|---|---|
| Is the output well-formed JSON with the right fields and types? | Strict tool use: the API compiles the schema into a grammar and constrains decoding | Yes, enforced at sampling time |
| Is the content true to the source? | `validate.py` | Yes, pure Python, same input → same report |
| Is the content *complete and precise enough*? | Golden-record diff + lab ground truth | Yes, but needs human-built references |

Strict tool use stops malformed output and missing fields, but the model can still invent `11.1.3`. The validator catches inventions, but it accepts a coarse range that is fully grounded. Golden records catch coarseness, but only for advisories someone has hand-checked. Each layer covers a gap in the one before it.

There is no `temperature` setting. Reliability comes from the gate, not from hoping sampling is repeatable.

## One schema, two views

`affected_products.schema.json` is the contract. The API's strict mode supports only a subset of JSON Schema: no `minLength`, no `uniqueItems`, `minItems` only 0/1, limits on optional and union parameters. `schema.py` derives the API subset by stripping exactly those keywords. The validator enforces the full contract, so the stripped rules are still checked, just after generation instead of during it. Since there's only one file, the model and the validator can't disagree about the shape of a valid record.

Every property is `required`, and nullable fields use `["string","null"]`. `schema_version` is in the contract but not in the API view: the tool sets it. The first live run showed why. Asked for a constant, Opus sent something other than the string `"1.0"` on all three attempts, spending the whole repair budget on bookkeeping. The model should only be asked for things that require reading the advisory. Strict mode caps optional parameters, and "required but null" is clearer than "absent" anyway.

## Grounding

- **Evidence** must be a verbatim span of the source after normalization. Normalization covers NFKC, unicode dashes and quotes mapped to ASCII, collapsed whitespace, and casefolding. Formatting noise passes; paraphrase fails.
- **Versions** must appear as a *whole version token*. `10.2.9` is not grounded by `10.2.9-h1`, and `1.2` is not grounded by `11.2.3`. Without this check, a model could cite a fragment of the real fix.
- **Derived lower bounds** are allowed, narrowly. Palo Alto writes `< 10.2.4-h16`, never "10.2.4". So `introduced` (or `branch`) may be a leading prefix of *the same range's* upper bound. `"0"` means "all earlier versions."
- **CVE IDs** must appear in the source.
- **Coverage (info).** The validator lists version-like strings in the source that no evidence quote covers. Grounding checks what the model *said*. Coverage hints at what it *didn't say*, such as a missed release line.

## Versions

Vendor versions aren't semver. `versions.py` tokenizes into numbers and words, then compares by these rules:

- numbers compare numerically;
- known pre-release words (`dev < alpha < beta < pre < rc`) sort before the release;
- any other trailing word is a post-release, so `10.2.9 < 10.2.9-h1 < 10.2.9-h10 < 10.2.10`.

When two versions disagree on an unknown word (`12.1-fips` vs `12.1-ndcpp`), comparison **raises** instead of guessing. A guessed order is how you get silent false negatives. The validator turns that into an error that says "split the product by edition or use the opaque scheme."

`branch` exists for one case that bounds can't express: a release line where every build is affected and there's no fix, such as Citrix 12.1 EOL. It's implemented as `[12.1, 12.1.∞)` using a sentinel infinity token. That interval contains `12.1-65.25` but not `12.10` or `13.0`.

## The repair loop

1. The model is asked to call `record_affected_products`. `tool_choice` is `auto`: Claude Opus 5.5 and Sonnet 5.5 reject forced tool choice with a 400 (found on the first live run), so the instruction lives in the prompt. A reply with no tool call gets a short nudge and uses up one attempt. `strict: true` still guarantees the call's input matches the schema.
2. The record is validated.
3. On failure, the assistant turn is replayed and the findings go back as a `tool_result` with `is_error: true`. That's the protocol's native "your tool call failed" signal. The feedback lists exact codes, JSON paths and messages, and says not to invent text to satisfy a check.
4. The loop is capped at 3 attempts. If it's still failing, the result is returned with `ok: false` and exit code 2. It is never silently accepted.

Warnings go back alongside errors, but they don't trigger a retry by themselves. Any warning sets `review_required`, which routes the record to a human.

## Untrusted input

Advisory text is attacker-reachable: a compromised vendor page or a poisoned feed. Three defenses apply:

- The system prompt says the source is data, not instructions.
- The source is fenced in `<source>` tags.
- Grounding limits what an injection can achieve. Injected text can steer the model only toward claims that are literally in the text.

That isn't a complete defense. An injected "PAN-OS 12.0 is not affected" is grounded because it's in the text. That is one more reason `review_required` and human sign-off stay in the workflow.

## Matching

- Assets are *observations* (asset, time, product, version, fingerprint source). `LATEST_OBSERVATIONS_SQL` uses `ROW_NUMBER() OVER (PARTITION BY asset_id ORDER BY observed_at DESC)`, so a host patched last week isn't judged on last month's banner.
- Verdicts separate *identified* from *confirmed*:
  - `VERSION_UNKNOWN` when there's no version;
  - `NEEDS_CONFIG_CHECK` when the advisory names a precondition that's invisible from outside;
  - `VULNERABLE` only when the version is pinned, in range, and no condition is pending.
- KPIs:
  - **Version-resolution rate**: identified assets with a pinned version. This is the fingerprinting coverage metric.
  - **Precision/recall** against an `expected_verdict` column from lab ground truth. "Positive" means `VULNERABLE` or `NEEDS_CONFIG_CHECK`, i.e. something you'd tell the client about. `VERSION_UNKNOWN` is counted separately, because it's a coverage gap, not a hit or a miss.

## Known gaps / next steps

- **Version aliases.** MOVEit `2021.0.6 (13.0.6)`: an asset reporting `15.0.1` would be compared against year-based ranges and come out wrong. The fix is an alias table per product, filled from the advisory's own parenthetical pairs.
- **Fingerprint → version mapping.** This would cover static-asset or favicon hashes per build, lab-verified across vulnerable and patched builds. It would raise the version-resolution rate, and it plugs in upstream of `match`.
- **CPE / product aliasing**, so "NetScaler ADC" matches `cpe:2.3:a:citrix:netscaler_application_delivery_controller`.
- **Batch mode** over the daily KEV delta, emitting only new or changed records for review.
- **NVD CPE cross-check** as a second, independent source of ranges. A disagreement would become a warning.
