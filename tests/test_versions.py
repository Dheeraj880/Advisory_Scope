import pytest

from advisory_scope.versions import (
    IncomparableVersions,
    InvalidVersion,
    compare,
    overlaps,
    parse,
    range_interval,
    sort_key,
)


def R(introduced, fixed=None, last_affected=None, branch=None):
    return {"introduced": introduced, "fixed": fixed, "last_affected": last_affected, "branch": branch}


@pytest.mark.parametrize(
    "lower,higher",
    [
        ("10.2.9", "10.2.9-h1"),        # PAN-OS hotfix is a post-release
        ("10.2.9-h1", "10.2.9-h2"),
        ("10.2.9-h9", "10.2.9-h10"),    # numeric, not lexical
        ("10.2.9-h10", "10.2.10"),
        ("13.1", "13.1-49.15"),         # branch prefix sorts first
        ("13.1-37.164", "13.1-49.15"),  # Citrix build numbers
        ("13.1-49.9", "13.1-49.15"),
        ("2021.0.6", "2021.1.0"),
        ("1.0.0-rc1", "1.0.0"),         # pre-release sorts before release
        ("1.0.0-alpha", "1.0.0-beta"),
        ("1.9", "1.10"),
    ],
)
def test_ordering(lower, higher):
    assert compare(lower, higher) == -1
    assert compare(higher, lower) == 1


def test_equivalences():
    assert compare("v1.2.3", "1.2.3") == 0
    assert compare("1.2.3+build.7", "1.2.3") == 0
    assert compare("1.02", "1.2") == 0
    assert compare("1.0.0-a1", "1.0.0-alpha1") == 0


def test_sorting_mixed_hotfixes():
    versions = ["10.2.10", "10.2.9-h1", "10.2.9", "10.2.8-h3", "10.2.9-h10", "10.2.9-h2"]
    assert sorted(versions, key=sort_key()) == ["10.2.8-h3", "10.2.9", "10.2.9-h1", "10.2.9-h2", "10.2.9-h10", "10.2.10"]


def test_incomparable_editions_raise_instead_of_guessing():
    with pytest.raises(IncomparableVersions):
        compare("12.1-fips", "12.1-ndcpp")
    with pytest.raises(IncomparableVersions):
        compare("12.1-fips", "12.1-55")


@pytest.mark.parametrize("bad", ["", "abc", "1.2;rm -rf", "1.2 3", "≥1.2"])
def test_invalid_versions(bad):
    with pytest.raises(InvalidVersion):
        parse(bad)


def test_semver_strict():
    assert compare("1.2.3", "1.2.4", "semver") == -1
    with pytest.raises(InvalidVersion):
        parse("1.2", "semver")


def test_opaque_has_no_order():
    with pytest.raises(IncomparableVersions):
        parse("build-aurora", "opaque")


def test_half_open_range():
    iv = range_interval(R("10.2.0", "10.2.0-h3"), "dotted")
    assert iv.contains(parse("10.2.0"))
    assert iv.contains(parse("10.2.0-h2"))
    assert not iv.contains(parse("10.2.0-h3"))
    assert not iv.contains(parse("10.1.99"))


def test_last_affected_is_inclusive_and_zero_is_unbounded():
    iv = range_interval(R("0", last_affected="2.4.1"), "dotted")
    assert iv.contains(parse("0.1"))
    assert iv.contains(parse("2.4.1"))
    assert not iv.contains(parse("2.4.2"))


def test_branch_confines_unbounded_range():
    iv = range_interval(R("12.1", branch="12.1"), "dotted")
    assert iv.contains(parse("12.1"))
    assert iv.contains(parse("12.1-65.25"))
    assert not iv.contains(parse("12.10"))
    assert not iv.contains(parse("13.0-92.19"))


def test_overlap():
    a = range_interval(R("13.1", "13.1-49.15"), "dotted")
    b = range_interval(R("13.1", "13.1-37.164"), "dotted")  # FIPS line under the same product name
    c = range_interval(R("13.0", "13.0-92.19"), "dotted")
    d = range_interval(R("12.1", branch="12.1"), "dotted")
    assert overlaps(a, b)
    assert not overlaps(a, c)
    assert not overlaps(c, d)
    # adjacent half-open ranges touch but do not overlap
    assert not overlaps(range_interval(R("1.0", "2.0"), "dotted"), range_interval(R("2.0", "3.0"), "dotted"))
