"""Deterministic validation of an extracted record against its source text.

The LLM proposes; this module disposes. Nothing here calls a model, so the same
record and source always produce the same report.

Severity levels
  error    record is wrong or unsupported by the source -> rejected / retried
  warning  record is plausible but a human should look before it ships
  info     heuristics worth surfacing (e.g. version strings nobody quoted)

What it can catch: schema violations, hallucinated versions/quotes/CVE IDs,
impossible or overlapping ranges, duplicate products, contradictions, KEV
mismatch. What it cannot catch: a grounded but *too coarse* reading of the
advisory. That is what the golden-record diff and lab ground truth are for.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from jsonschema import Draft202012Validator

from .schema import load_schema
from .versions import (
    IncomparableVersions,
    VersionError,
    compare_tokens,
    is_prefix,
    overlaps,
    parse,
    range_interval,
)

ERROR, WARNING, INFO = "error", "warning", "info"

_DASHES = {ord(c): "-" for c in "‐‑‒–—―−"}
_QUOTES = {
    ord("‘"): "'",
    ord("’"): "'",
    ord("“"): '"',
    ord("”"): '"',
}
_WS = re.compile(r"\s+")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# Version-looking strings in prose: 10.2.9-h1, 13.1-49.15, 2021.0.6, 1.2.3-rc1
_VERSION_LIKE = re.compile(r"(?<![\w.])\d+(?:\.\d+)+(?:-[a-z]*\d+(?:\.\d+)*)?(?![\w])")


def normalize(text: str) -> str:
    """Canonical form for grounding checks: NFKC, ASCII dashes/quotes,
    collapsed whitespace, casefolded. Paraphrase still fails; formatting noise
    (smart quotes, en dashes, line wraps) does not."""
    text = unicodedata.normalize("NFKC", text).translate(_DASHES).translate(_QUOTES)
    return _WS.sub(" ", text).strip().casefold()


def name_key(name: str) -> str:
    """Identity key for vendor/product names: 'NetScaler ADC' == 'netscaler-adc'."""
    return re.sub(r"[^0-9a-z]+", "", normalize(name))


def version_in_text(version: str, norm_text: str) -> bool:
    """Is ``version`` present as a whole version token (not a fragment of a
    longer one)? '10.2.9' does not match inside '10.2.9-h1'; '1.2' does not
    match inside '11.2' or '1.2.3'."""
    v = re.escape(normalize(version))
    return re.search(rf"(?<![\w.]){v}(?![\w]|[.\-]\w)", norm_text) is not None


@dataclass
class Finding:
    severity: str
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.code} at {self.path}: {self.message}"

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass
class ValidationReport:
    findings: list[Finding] = field(default_factory=list)

    def add(self, severity: str, code: str, path: str, message: str) -> None:
        self.findings.append(Finding(severity, code, path, message))

    def _of(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def errors(self) -> list[Finding]:
        return self._of(ERROR)

    @property
    def warnings(self) -> list[Finding]:
        return self._of(WARNING)

    @property
    def infos(self) -> list[Finding]:
        return self._of(INFO)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def review_required(self) -> bool:
        return bool(self.errors or self.warnings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "review_required": self.review_required,
            "errors": [f.to_dict() for f in self.errors],
            "warnings": [f.to_dict() for f in self.warnings],
            "info": [f.to_dict() for f in self.infos],
        }

    def feedback(self) -> str:
        """Message returned to the model when validation fails."""
        lines = [
            (
                "Deterministic validation rejected the record. Fix exactly these "
                "errors and call the tool again with the complete corrected record. "
                "Do not invent text to satisfy a check; if the source does not "
                "support a value, remove it and explain in extraction_notes."
            ),
            "",
            "Errors:",
        ]
        lines += [f"- {f.code} at {f.path}: {f.message}" for f in self.errors]
        if self.warnings:
            lines += ["", "Warnings (fix if the source supports a fix):"]
            lines += [f"- {f.code} at {f.path}: {f.message}" for f in self.warnings]
        return "\n".join(lines)


def _json_path(parts) -> str:
    out = "$"
    for p in parts:
        out += f"[{p}]" if isinstance(p, int) else f".{p}"
    return out


def validate_record(
    record: Any,
    source_text: str,
    kev_entry: dict[str, Any] | None = None,
) -> ValidationReport:
    report = ValidationReport()

    # 1. Shape: the full contract schema (including rules the API grammar can't enforce)
    validator = Draft202012Validator(load_schema(), format_checker=Draft202012Validator.FORMAT_CHECKER)
    schema_errors = sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path))
    for err in schema_errors:
        got = repr(err.instance)
        got = got if len(got) <= 80 else got[:77] + "..."
        report.add(ERROR, "schema", _json_path(err.absolute_path),
                   f"{err.message} (got {got}, type {type(err.instance).__name__})")
    if schema_errors:
        return report  # semantic checks assume a well-formed record

    text = normalize(source_text)
    quoted: list[str] = []  # every normalized evidence string, for coverage

    # 2. CVE IDs must come from the source
    source_cves = {c.upper() for c in _CVE.findall(source_text)}
    for i, cve in enumerate(record["cve_ids"]):
        if cve.upper() not in source_cves:
            report.add(ERROR, "cve_not_in_source", f"$.cve_ids[{i}]",
                       f"{cve} does not appear in the source text")

    def check_evidence(items: list[str], base: str) -> None:
        for j, quote in enumerate(items):
            nq = normalize(quote)
            quoted.append(nq)
            if nq not in text:
                report.add(ERROR, "evidence_not_verbatim", f"{base}.evidence[{j}]",
                           f"quote not found verbatim in source: {quote[:120]!r}")

    def check_version(v: str, path: str, scheme: str, allow_prefix_of=()) -> Any:
        """Parse + ground one version string. Returns tokens or None."""
        tokens = None
        if scheme != "opaque":
            try:
                tokens = parse(v, scheme)
            except VersionError as exc:
                report.add(ERROR, "version_unparseable", path, str(exc))
                return None
        if version_in_text(v, text):
            return tokens
        if tokens is not None and any(
            other and (tokens == other or is_prefix(tokens, other)) for other in allow_prefix_of
        ):
            return tokens  # derived lower bound, e.g. introduced 10.2.0 for fixed 10.2.0-h3
        report.add(ERROR, "version_not_in_source", path,
                   f"version '{v}' does not appear in the source"
                   + (" and is not a prefix of this range's upper bound" if allow_prefix_of else ""))
        return tokens

    # 3. Affected products
    seen: dict[str, str] = {}
    for i, prod in enumerate(record["affected"]):
        base = f"$.affected[{i}]"
        key = f"{name_key(prod['vendor'])}/{name_key(prod['product'])}"
        if key in seen:
            report.add(ERROR, "duplicate_product", base,
                       f"{prod['vendor']} / {prod['product']} already listed at {seen[key]}; merge the ranges into one entry")
        else:
            seen[key] = base

        if normalize(prod["product"]) not in text:
            report.add(WARNING, "product_name_not_in_source", f"{base}.product",
                       f"product name '{prod['product']}' does not appear verbatim in the source")
        if normalize(prod["vendor"]) not in text and not (kev_entry and name_key(prod["vendor"]) == name_key(kev_entry.get("vendorProject", ""))):
            report.add(WARNING, "vendor_name_not_in_source", f"{base}.vendor",
                       f"vendor name '{prod['vendor']}' does not appear verbatim in the source")

        check_evidence(prod["evidence"], base)
        scheme = prod["version_scheme"]

        if not prod["ranges"] and not prod["versions"]:
            report.add(ERROR, "no_affected_versions", base,
                       "product has neither ranges nor versions; if every version is affected use "
                       "a range with introduced \"0\" and no upper bound")
        if scheme == "opaque" and prod["ranges"]:
            report.add(ERROR, "opaque_with_ranges", f"{base}.ranges",
                       "opaque versions have no ordering, so ranges are meaningless; list versions instead")

        intervals = []
        for r, rng in enumerate(prod["ranges"] if scheme != "opaque" else []):
            rpath = f"{base}.ranges[{r}]"
            if rng["fixed"] and rng["last_affected"]:
                report.add(ERROR, "fixed_and_last_affected", rpath,
                           "set either fixed (exclusive) or last_affected (inclusive), not both")
                continue
            upper_raw = rng["fixed"] or rng["last_affected"]
            upper = check_version(upper_raw, f"{rpath}.{'fixed' if rng['fixed'] else 'last_affected'}", scheme) if upper_raw else None
            branch = check_version(rng["branch"], f"{rpath}.branch", scheme, (upper,)) if rng["branch"] else None
            lower = None
            if rng["introduced"] != "0":
                lower = check_version(rng["introduced"], f"{rpath}.introduced", scheme, (upper, branch))
            if branch is not None and lower is not None and lower[: len(branch)] != branch:
                report.add(ERROR, "introduced_outside_branch", rpath,
                           f"introduced '{rng['introduced']}' is not on branch '{rng['branch']}'")
            if branch is not None and upper is not None and upper[: len(branch)] != branch:
                report.add(ERROR, "upper_outside_branch", rpath,
                           f"'{upper_raw}' is not on branch '{rng['branch']}'")
            if lower is not None and upper is not None:
                try:
                    c = compare_tokens(lower, upper)
                    if c > 0 or (c == 0 and rng["fixed"]):
                        report.add(ERROR, "empty_range", rpath,
                                   f"introduced '{rng['introduced']}' is not below '{upper_raw}'")
                        continue
                except IncomparableVersions as exc:
                    report.add(ERROR, "incomparable_bounds", rpath,
                               f"{exc}; split the product by edition or use the opaque scheme")
                    continue
            if upper_raw is None and rng["branch"] is None:
                report.add(WARNING, "unbounded_range", rpath,
                           "no fixed or last_affected version and no branch: every version from "
                           f"'{rng['introduced']}' upward is treated as affected. Confirm the source says no fix exists.")
            try:
                intervals.append((r, range_interval(rng, scheme)))
            except VersionError:
                pass  # already reported above

        for a in range(len(intervals)):
            for b in range(a + 1, len(intervals)):
                (ra, ia), (rb, ib) = intervals[a], intervals[b]
                try:
                    if overlaps(ia, ib):
                        report.add(ERROR, "overlapping_ranges", f"{base}.ranges[{rb}]",
                                   f"overlaps ranges[{ra}]; if these are different editions, make them separate products")
                except IncomparableVersions as exc:
                    report.add(ERROR, "incomparable_bounds", f"{base}.ranges[{rb}]", str(exc))

        for v_i, v in enumerate(prod["versions"]):
            tokens = check_version(v, f"{base}.versions[{v_i}]", scheme)
            if tokens is None:
                continue
            for r, interval in intervals:
                try:
                    if interval.contains(tokens):
                        report.add(WARNING, "version_redundant", f"{base}.versions[{v_i}]",
                                   f"'{v}' is already inside ranges[{r}]")
                except IncomparableVersions:
                    pass

    # 4. Not-affected products
    for i, prod in enumerate(record["not_affected"]):
        base = f"$.not_affected[{i}]"
        check_evidence(prod["evidence"], base)
        key = f"{name_key(prod['vendor'])}/{name_key(prod['product'])}"
        if key in seen:
            report.add(ERROR, "affected_and_not_affected", base,
                       f"{prod['vendor']} / {prod['product']} is also listed as affected at {seen[key]}; "
                       "express unaffected release lines through that product's ranges")

    # 5. KEV cross-check
    if kev_entry:
        kev_cve = kev_entry.get("cveID", "")
        if kev_cve and kev_cve.upper() not in {c.upper() for c in record["cve_ids"]}:
            report.add(ERROR, "kev_cve_missing", "$.cve_ids", f"KEV entry is {kev_cve} but the record does not include it")
        kev_vendor = name_key(kev_entry.get("vendorProject", ""))
        vendors = {name_key(p["vendor"]) for p in record["affected"]}
        if kev_vendor and not any(kev_vendor in v or v in kev_vendor for v in vendors):
            report.add(WARNING, "kev_vendor_mismatch", "$.affected",
                       f"KEV vendor '{kev_entry.get('vendorProject')}' matches none of the extracted vendors")

    # 6. Coverage heuristic: version strings in the source that no evidence quote covers
    evidence_blob = " | ".join(quoted)
    uncovered = sorted(
        {v for v in _VERSION_LIKE.findall(text) if not version_in_text(v, evidence_blob)}
    )
    if uncovered:
        shown = ", ".join(uncovered[:25]) + (" ..." if len(uncovered) > 25 else "")
        report.add(INFO, "uncovered_versions", "$",
                   f"version-like strings in the source not covered by any evidence quote "
                   f"(possible missed release line): {shown}")
    return report
