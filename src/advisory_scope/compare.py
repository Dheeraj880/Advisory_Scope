"""Diff an extracted record against a hand-checked golden record.

The validator proves a record is *grounded*; it cannot prove it is *complete
and precise*. This diff is how extraction quality is measured over a set of
golden advisories: range-level precision and recall, per product.
"""

from __future__ import annotations

from typing import Any

from .validate import name_key


def _ranges(record: dict[str, Any]) -> set[tuple]:
    out = set()
    for p in record["affected"]:
        prod = (name_key(p["vendor"]), name_key(p["product"]))
        for r in p["ranges"]:
            out.add((*prod, r["introduced"], r["fixed"], r["last_affected"], r["branch"]))
        for v in p["versions"]:
            out.add((*prod, "=", v, None, None))
    return out


def _products(record: dict[str, Any], key: str) -> set[tuple]:
    return {(name_key(p["vendor"]), name_key(p["product"])) for p in record[key]}


def _pr(actual: set, expected: set) -> dict[str, Any]:
    tp = len(actual & expected)
    return {
        "precision": round(tp / len(actual), 3) if actual else None,
        "recall": round(tp / len(expected), 3) if expected else None,
        "extra": sorted(map(str, actual - expected)),
        "missing": sorted(map(str, expected - actual)),
    }


def diff_records(actual: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_ids_match": sorted(actual["cve_ids"]) == sorted(expected["cve_ids"]),
        "affected_products": _pr(_products(actual, "affected"), _products(expected, "affected")),
        "not_affected_products": _pr(_products(actual, "not_affected"), _products(expected, "not_affected")),
        "ranges": _pr(_ranges(actual), _ranges(expected)),
    }
