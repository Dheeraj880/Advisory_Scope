import copy
import json
from pathlib import Path

import pytest

from advisory_scope.sources import Source, find_kev, kev_to_text

FIXTURES = Path(__file__).parent / "fixtures"
CVES = ["CVE-2024-3400", "CVE-2023-4966", "CVE-2023-34362"]


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def kev_catalog():
    return load_json(FIXTURES / "kev_subset.json")


def make_source(cve: str, kev_catalog) -> Source:
    entry = find_kev(kev_catalog, cve)
    advisory = (FIXTURES / "advisories" / f"{cve}.txt").read_text(encoding="utf-8")
    text = f"=== CISA KEV ENTRY ===\n{kev_to_text(entry)}\n\n=== VENDOR ADVISORY ===\n{advisory}"
    return Source(text, "kev+advisory", f"test:{cve}", entry)


@pytest.fixture
def source_for(kev_catalog):
    return lambda cve: make_source(cve, kev_catalog)


@pytest.fixture
def golden():
    return lambda cve: copy.deepcopy(load_json(FIXTURES / "expected" / f"{cve}.json"))
