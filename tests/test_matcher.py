import pytest
from conftest import FIXTURES, load_json

from advisory_scope.matcher import load_assets_csv, match_record, open_db, score, summary


@pytest.fixture
def db():
    conn = open_db()
    load_assets_csv(conn, FIXTURES / "assets.csv")
    return conn


def verdicts(detections):
    return {d.asset_id: d.verdict for d in detections}


def test_panos_hotfix_precision(db, golden):
    detections = match_record(db, golden("CVE-2024-3400"))
    v = verdicts(detections)
    assert v["fw-01"] == "NOT_AFFECTED"        # 10.2.8-h3 is a fixed hotfix
    assert v["fw-08"] == "NOT_AFFECTED"        # 10.2.4-h16 too
    assert v["fw-02"] == "NEEDS_CONFIG_CHECK"  # 10.2.9 < 10.2.9-h1, GlobalProtect config unknown
    assert v["fw-04"] == "NEEDS_CONFIG_CHECK"
    assert v["fw-05"] == "NOT_AFFECTED"        # 10.1 line unaffected
    assert v["fw-06"] == "VERSION_UNKNOWN"     # product identified, version hidden
    assert "ns-01" not in v                    # other products ignored
    sc = score(detections)
    assert (sc["precision"], sc["recall"], sc["fp"]) == (1.0, 1.0, 0)


def test_naive_ranges_create_false_positives(db):
    naive = load_json(FIXTURES / "naive_CVE-2024-3400.json")
    sc = score(match_record(db, naive))
    assert set(sc["false_positives"]) == {"fw-01", "fw-07", "fw-08"}
    assert sc["precision"] == 0.4


def test_latest_observation_wins(db, golden):
    """fw-07 was 11.1.1 in September and 11.1.1-h1 in October; only the latest counts."""
    d = {x.asset_id: x for x in match_record(db, golden("CVE-2024-3400"))}
    assert d["fw-07"].version == "11.1.1-h1"
    assert d["fw-07"].verdict == "NOT_AFFECTED"


def test_version_resolution_kpi(db, golden):
    rec = golden("CVE-2024-3400")
    match_record(db, rec)
    s = summary(db, rec)
    assert (s["identified_assets"], s["version_resolved"], s["version_resolution_pct"]) == (9, 8, 88.9)


def test_citrix_eol_branch_and_editions(db, golden):
    v = verdicts(match_record(db, golden("CVE-2023-4966")))
    assert v == {"ns-01": "NEEDS_CONFIG_CHECK", "ns-02": "NOT_AFFECTED",
                 "ns-03": "NEEDS_CONFIG_CHECK", "ns-04": "NOT_AFFECTED"}


def test_unconditional_vulnerability(db, golden):
    v = verdicts(match_record(db, golden("CVE-2023-34362")))
    assert v == {"mv-01": "VULNERABLE", "mv-02": "NOT_AFFECTED"}


def test_explicitly_not_affected_product():
    conn = open_db()
    conn.execute("INSERT INTO observations (asset_id, observed_at, vendor, product, version) "
                 "VALUES ('pa-01', '2026-10-01', 'Palo Alto Networks', 'Prisma Access', NULL)")
    rec = load_json(FIXTURES / "expected" / "CVE-2024-3400.json")
    (d,) = match_record(conn, rec)
    assert d.verdict == "NOT_AFFECTED" and "explicitly" in d.reason
