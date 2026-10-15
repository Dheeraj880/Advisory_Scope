"""Match a validated record against an internet-asset corpus.

Assets are fingerprint observations (banner, HTML, favicon hash, ...) loaded
into SQLite. Each asset's *latest* observation gets one verdict:

  VULNERABLE          version is inside an affected range, no stated conditions
  NEEDS_CONFIG_CHECK  version is in range, but exposure depends on configuration
                      the advisory names (not observable from the internet)
  VERSION_UNKNOWN     product identified, version not resolved (or not comparable)
  NOT_AFFECTED        version outside every range, or product explicitly not affected

"Product identified" is not "vulnerability confirmed": only VULNERABLE asserts
the latter, and only when the version is pinned and no condition is pending.
"""

from __future__ import annotations

import csv
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .validate import name_key
from .versions import VersionError, parse, range_interval

VULNERABLE = "VULNERABLE"
NEEDS_CONFIG_CHECK = "NEEDS_CONFIG_CHECK"
VERSION_UNKNOWN = "VERSION_UNKNOWN"
NOT_AFFECTED = "NOT_AFFECTED"
FLAGGED = (VULNERABLE, NEEDS_CONFIG_CHECK)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS observations (
    obs_id            INTEGER PRIMARY KEY,
    asset_id          TEXT NOT NULL,
    ip                TEXT,
    port              INTEGER,
    hostname          TEXT,
    observed_at       TEXT NOT NULL,          -- ISO-8601, sorts lexically
    vendor            TEXT,
    product           TEXT,
    version           TEXT,                   -- NULL when the fingerprint has no version
    fingerprint_source TEXT,
    expected_verdict  TEXT                    -- optional lab ground truth
);
CREATE TABLE IF NOT EXISTS detections (
    asset_id    TEXT NOT NULL,
    cve_ids     TEXT NOT NULL,
    vendor      TEXT,
    product     TEXT,
    version     TEXT,
    verdict     TEXT NOT NULL,
    reason      TEXT NOT NULL,
    expected_verdict TEXT,
    PRIMARY KEY (asset_id, cve_ids)
);
"""

# Latest observation per asset: the window function picks one row per asset_id.
LATEST_OBSERVATIONS_SQL = """
WITH ranked AS (
    SELECT o.*,
           ROW_NUMBER() OVER (PARTITION BY asset_id
                              ORDER BY observed_at DESC, obs_id DESC) AS rn
    FROM observations AS o
)
SELECT asset_id, ip, port, hostname, observed_at, vendor, product,
       NULLIF(TRIM(version), '') AS version, fingerprint_source, expected_verdict
FROM ranked
WHERE rn = 1
ORDER BY asset_id
"""

SUMMARY_SQL = """
SELECT verdict, COUNT(*) AS assets
FROM detections
WHERE cve_ids = ?
GROUP BY verdict
ORDER BY CASE verdict WHEN 'VULNERABLE' THEN 1 WHEN 'NEEDS_CONFIG_CHECK' THEN 2
                      WHEN 'VERSION_UNKNOWN' THEN 3 ELSE 4 END
"""

# KPI: of the assets identified as the affected product, how many have a pinned version?
VERSION_RESOLUTION_SQL = """
SELECT COUNT(*)                                        AS identified,
       SUM(version IS NOT NULL)                        AS version_resolved,
       ROUND(100.0 * SUM(version IS NOT NULL) / COUNT(*), 1) AS resolution_pct
FROM detections
WHERE cve_ids = ? AND reason NOT LIKE 'explicitly not affected%'
"""

CSV_COLUMNS = ("asset_id", "ip", "port", "hostname", "observed_at", "vendor", "product",
               "version", "fingerprint_source", "expected_verdict")


@dataclass
class Detection:
    asset_id: str
    vendor: str
    product: str
    version: str | None
    verdict: str
    reason: str
    expected_verdict: str | None = None
    ip: str | None = None
    port: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def open_db(path: str | Path = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_SQL)
    return conn


def load_assets_csv(conn: sqlite3.Connection, path: str | Path) -> int:
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = {"asset_id", "observed_at", "vendor", "product", "version"} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path}: missing required columns {sorted(missing)}")
        rows = [tuple((row.get(c) or None) for c in CSV_COLUMNS) for row in reader]
    conn.executemany(
        f"INSERT INTO observations ({', '.join(CSV_COLUMNS)}) VALUES ({', '.join('?' * len(CSV_COLUMNS))})",
        rows,
    )
    conn.commit()
    return len(rows)


def _verdict_for(product: dict[str, Any], version: str | None) -> tuple[str, str]:
    scheme = product["version_scheme"]
    conditions = product["conditions"]
    if not version:
        return VERSION_UNKNOWN, "product identified but no version in the fingerprint"
    if scheme == "opaque":
        if version in product["versions"]:
            hit = f"{version} is a listed affected version"
            return (NEEDS_CONFIG_CHECK, f"{hit}; exposure requires: {'; '.join(conditions)}") if conditions else (VULNERABLE, hit)
        return NOT_AFFECTED, f"{version} is not a listed affected version"
    try:
        v = parse(version, scheme)
        hit = None
        for rng in product["ranges"]:
            if range_interval(rng, scheme).contains(v):
                if rng["fixed"]:
                    upper = f"fixed in {rng['fixed']}"
                elif rng["last_affected"]:
                    upper = f"last affected {rng['last_affected']}"
                else:
                    upper = f"no fix (branch {rng['branch']})" if rng["branch"] else "no fix"
                hit = f"{version} in range [introduced {rng['introduced']}, {upper}]"
                break
        if hit is None:
            for listed in product["versions"]:
                if parse(listed, scheme) == v:
                    hit = f"{version} is a listed affected version"
                    break
    except VersionError as exc:
        return VERSION_UNKNOWN, f"version '{version}' not comparable: {exc}"
    if hit is None:
        return NOT_AFFECTED, f"{version} is outside every affected range"
    if conditions:
        return NEEDS_CONFIG_CHECK, f"{hit}; exposure requires: {'; '.join(conditions)}"
    return VULNERABLE, hit


def match_record(conn: sqlite3.Connection, record: dict[str, Any]) -> list[Detection]:
    affected = {(name_key(p["vendor"]), name_key(p["product"])): p for p in record["affected"]}
    not_affected = {(name_key(p["vendor"]), name_key(p["product"])) for p in record["not_affected"]}
    cve_key = ",".join(sorted(record["cve_ids"]))

    detections: list[Detection] = []
    for row in conn.execute(LATEST_OBSERVATIONS_SQL):
        key = (name_key(row["vendor"] or ""), name_key(row["product"] or ""))
        if key in affected:
            verdict, reason = _verdict_for(affected[key], row["version"])
        elif key in not_affected:
            verdict, reason = NOT_AFFECTED, "explicitly not affected per advisory"
        else:
            continue  # not a product this advisory talks about
        detections.append(Detection(row["asset_id"], row["vendor"], row["product"], row["version"],
                                    verdict, reason, row["expected_verdict"], row["ip"], row["port"]))

    conn.execute("DELETE FROM detections WHERE cve_ids = ?", (cve_key,))
    conn.executemany(
        "INSERT INTO detections VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(d.asset_id, cve_key, d.vendor, d.product, d.version, d.verdict, d.reason, d.expected_verdict)
         for d in detections],
    )
    conn.commit()
    return detections


def summary(conn: sqlite3.Connection, record: dict[str, Any]) -> dict[str, Any]:
    cve_key = ",".join(sorted(record["cve_ids"]))
    counts = {r["verdict"]: r["assets"] for r in conn.execute(SUMMARY_SQL, (cve_key,))}
    res = conn.execute(VERSION_RESOLUTION_SQL, (cve_key,)).fetchone()
    return {
        "cve_ids": record["cve_ids"],
        "verdicts": counts,
        "identified_assets": res["identified"],
        "version_resolved": res["version_resolved"] or 0,
        "version_resolution_pct": res["resolution_pct"],
    }


def score(detections: Iterable[Detection]) -> dict[str, Any] | None:
    """Precision/recall of the flagged set against lab ground truth.

    Positive = VULNERABLE or NEEDS_CONFIG_CHECK (the asset should be raised to
    the client). VERSION_UNKNOWN rows are excluded from precision/recall and
    reported separately, because "unknown" is neither a hit nor a miss.
    """
    labeled = [d for d in detections if d.expected_verdict]
    if not labeled:
        return None
    tp = fp = fn = tn = 0
    exact = 0
    unknown = 0
    for d in labeled:
        exact += d.verdict == d.expected_verdict
        if d.verdict == VERSION_UNKNOWN:
            unknown += 1
            continue
        predicted, actual = d.verdict in FLAGGED, d.expected_verdict in FLAGGED
        tp += predicted and actual
        fp += predicted and not actual
        fn += actual and not predicted
        tn += not predicted and not actual
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {
        "labeled": len(labeled),
        "exact_verdict_match": exact,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "version_unknown": unknown,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "false_positives": [d.asset_id for d in labeled if d.verdict in FLAGGED and d.expected_verdict not in FLAGGED],
        "false_negatives": [d.asset_id for d in labeled
                            if d.verdict == NOT_AFFECTED and d.expected_verdict in FLAGGED],
    }
