import pytest
from conftest import CVES

from advisory_scope.validate import normalize, validate_record, version_in_text


def codes(report, severity="error"):
    return {f.code for f in report.findings if f.severity == severity}


def R(introduced, fixed=None, last_affected=None, branch=None):
    return {"introduced": introduced, "fixed": fixed, "last_affected": last_affected, "branch": branch}


@pytest.mark.parametrize("cve", CVES)
def test_golden_records_pass(cve, golden, source_for):
    """Golden records are the regression baseline: they must always validate cleanly."""
    report = validate_record(golden(cve), source_for(cve).text, source_for(cve).kev_entry)
    assert report.ok, [str(f) for f in report.findings]
    assert not report.warnings


def test_schema_rejects_unknown_fields_and_bad_cve(golden, source_for):
    rec = golden("CVE-2024-3400")
    rec["severity"] = "critical"
    rec["cve_ids"] = ["CVE-24-3400"]
    report = validate_record(rec, source_for("CVE-2024-3400").text)
    assert codes(report) == {"schema"}
    assert len(report.errors) == 2


def test_schema_rules_the_api_cannot_enforce_are_still_checked(golden, source_for):
    rec = golden("CVE-2024-3400")
    rec["affected"][0]["evidence"] = ["short"]  # minLength 8
    report = validate_record(rec, source_for("CVE-2024-3400").text)
    assert "schema" in codes(report)


def test_paraphrased_evidence_is_rejected(golden, source_for):
    rec = golden("CVE-2024-3400")
    rec["affected"][0]["evidence"][0] = "PAN-OS 11.1 versions below 11.1.2-h3 are vulnerable"
    assert "evidence_not_verbatim" in codes(validate_record(rec, source_for("CVE-2024-3400").text))


def test_evidence_tolerates_formatting_noise(golden, source_for):
    rec = golden("CVE-2024-3400")
    rec["affected"][0]["evidence"][0] = "PAN-OS   11.1 |  < 11.1.0–h3, < 11.1.1-h1, < 11.1.2-h3"  # extra spaces, en dash
    assert validate_record(rec, source_for("CVE-2024-3400").text).ok


def test_hallucinated_version_is_rejected(golden, source_for):
    rec = golden("CVE-2024-3400")
    rec["affected"][0]["ranges"][2]["fixed"] = "11.1.3"
    report = validate_record(rec, source_for("CVE-2024-3400").text)
    assert "version_not_in_source" in codes(report)


def test_version_fragment_is_not_grounding():
    text = normalize("Fixed in PAN-OS 10.2.9-h1 and 11.2.3.")
    assert version_in_text("10.2.9-h1", text)
    assert not version_in_text("10.2.9", text)   # fragment of 10.2.9-h1
    assert not version_in_text("1.2", text)      # fragment of 11.2.3
    assert version_in_text("11.2.3", text)       # sentence-final period is fine


def test_derived_lower_bound_allowed_only_as_prefix(golden, source_for):
    rec = golden("CVE-2024-3400")
    assert rec["affected"][0]["ranges"][0]["introduced"] == "11.1.0"  # not in text, prefix of 11.1.0-h3
    assert validate_record(rec, source_for("CVE-2024-3400").text).ok
    rec["affected"][0]["ranges"][0]["introduced"] = "11.0.9"  # not in text, not a prefix
    assert "version_not_in_source" in codes(validate_record(rec, source_for("CVE-2024-3400").text))


def test_cve_must_be_in_source(golden, source_for):
    rec = golden("CVE-2024-3400")
    rec["cve_ids"].append("CVE-2024-3401")
    assert "cve_not_in_source" in codes(validate_record(rec, source_for("CVE-2024-3400").text))


def test_inverted_range(golden, source_for):
    rec = golden("CVE-2023-4966")
    rec["affected"][0]["ranges"][0] = R("14.1-8.50", "14.1")
    assert "empty_range" in codes(validate_record(rec, source_for("CVE-2023-4966").text))


def test_fixed_and_last_affected_together(golden, source_for):
    rec = golden("CVE-2023-4966")
    rec["affected"][0]["ranges"][0]["last_affected"] = "13.1-49.15"
    assert "fixed_and_last_affected" in codes(validate_record(rec, source_for("CVE-2023-4966").text))


def test_editions_collapsed_into_one_product_overlap(golden, source_for):
    """Putting the FIPS line under plain 'NetScaler ADC' creates overlapping 13.1 ranges."""
    rec = golden("CVE-2023-4966")
    rec["affected"][0]["ranges"].append(R("13.1", "13.1-37.164"))
    assert "overlapping_ranges" in codes(validate_record(rec, source_for("CVE-2023-4966").text))


def test_duplicate_product(golden, source_for):
    rec = golden("CVE-2023-4966")
    dup = dict(rec["affected"][0], product="netscaler-adc")
    rec["affected"].append(dup)
    assert "duplicate_product" in codes(validate_record(rec, source_for("CVE-2023-4966").text))


def test_affected_and_not_affected_conflict(golden, source_for):
    rec = golden("CVE-2024-3400")
    rec["not_affected"].append({"vendor": "Palo Alto Networks", "product": "PAN-OS",
                                "evidence": ["PAN-OS 10.1 | None | All"]})
    assert "affected_and_not_affected" in codes(validate_record(rec, source_for("CVE-2024-3400").text))


def test_opaque_scheme_cannot_have_ranges(golden, source_for):
    rec = golden("CVE-2023-34362")
    rec["affected"][0]["version_scheme"] = "opaque"
    assert "opaque_with_ranges" in codes(validate_record(rec, source_for("CVE-2023-34362").text))


def test_incomparable_bounds(golden, source_for):
    rec = golden("CVE-2023-4966")
    rec["affected"][2]["ranges"] = [R("13.1-FIPS", "13.1-37.164")]
    assert "incomparable_bounds" in codes(validate_record(rec, source_for("CVE-2023-4966").text))


def test_branch_must_contain_bounds(golden, source_for):
    rec = golden("CVE-2023-4966")
    rec["affected"][0]["ranges"][0]["branch"] = "13.0"  # 14.1 range declared on branch 13.0
    report = validate_record(rec, source_for("CVE-2023-4966").text)
    assert {"introduced_outside_branch", "upper_outside_branch"} <= codes(report)


def test_unbounded_range_needs_review(golden, source_for):
    rec = golden("CVE-2023-34362")
    rec["affected"][0]["ranges"].append(R("2023.0.1"))  # 'every version from 2023.0.1 up'
    report = validate_record(rec, source_for("CVE-2023-34362").text)
    assert "unbounded_range" in codes(report, "warning")
    assert report.review_required


def test_no_versions_at_all(golden, source_for):
    rec = golden("CVE-2023-34362")
    rec["affected"][0]["ranges"] = []
    assert "no_affected_versions" in codes(validate_record(rec, source_for("CVE-2023-34362").text))


def test_kev_cross_check(golden, source_for):
    src = source_for("CVE-2024-3400")
    rec = golden("CVE-2023-34362")  # a record for a different CVE
    report = validate_record(rec, src.text + "\nCVE-2023-34362 MOVEit Transfer before 2021.0.6 (13.0.6), "
                             "2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1)", src.kev_entry)
    assert "kev_cve_missing" in codes(report)
    assert "kev_vendor_mismatch" in codes(report, "warning")


def test_naive_record_is_grounded_and_passes(source_for):
    """Documented limit: a grounded-but-coarse record passes validation.
    The golden diff and lab ground truth (test_matcher) are what catch it."""
    from conftest import FIXTURES, load_json
    naive = load_json(FIXTURES / "naive_CVE-2024-3400.json")
    assert validate_record(naive, source_for("CVE-2024-3400").text).ok
