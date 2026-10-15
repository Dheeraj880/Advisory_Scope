"""Deterministic version parsing, comparison and range membership.

No LLM is involved here. Vendor versions are messy, so the rules are explicit:

* A version is split into numeric and alphabetic tokens:
  ``10.2.9-h1`` -> (10, 2, 9, "h", 1); ``13.1-49.15`` -> (13, 1, 49, 15).
  Separators (``.``, ``-``, ``_``) only split tokens; build metadata after ``+``
  is ignored; a leading ``v`` is dropped.
* Numbers compare numerically (``1.10`` > ``1.9``).
* Pre-release markers (dev < alpha/a < beta/b < pre/preview < rc) sort *before*
  the release they precede: ``1.0.0-rc1`` < ``1.0.0``.
* Any other trailing text is a post-release suffix (e.g. PAN-OS hotfix ``h``):
  ``10.2.9`` < ``10.2.9-h1`` < ``10.2.9-h2`` < ``10.2.10``.
* When two versions disagree on a non-numeric, non-pre-release token
  (``12.1-fips`` vs ``12.1-ndcpp``), they are *incomparable* and an error is
  raised. Guessing an order there is how silent false negatives happen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cmp_to_key

SCHEMES = ("dotted", "semver", "opaque")
PRERELEASE_RANK = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "pre": 3,
    "preview": 3,
    "rc": 4,
}

_ALLOWED = re.compile(r"^[0-9A-Za-z.\-_+]+$")
_TOKEN = re.compile(r"\d+|[a-z]+")
_SEMVER = re.compile(
    r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$"
)


class VersionError(ValueError):
    """Base class for version problems."""


class InvalidVersion(VersionError):
    """The string cannot be parsed under the declared scheme."""


class IncomparableVersions(VersionError):
    """The two versions have no defined order."""


class _Infinity:
    """Token that sorts after every other token (used for branch upper bounds)."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "INF"


INF = _Infinity()
Token = int | str | _Infinity
Tokens = tuple  # tuple[Token, ...]


def parse(version: str, scheme: str = "dotted") -> Tokens:
    """Parse ``version`` into comparable tokens, or raise VersionError."""
    if scheme == "opaque":
        raise IncomparableVersions(f"'{version}' uses the opaque scheme, which has no ordering")
    if scheme not in SCHEMES:
        raise InvalidVersion(f"unknown version scheme '{scheme}'")
    text = version.strip()
    if not text or not _ALLOWED.match(text):
        raise InvalidVersion(
            f"'{version}' contains characters outside [0-9A-Za-z.-_+]"
        )
    if scheme == "semver" and not _SEMVER.match(text):
        raise InvalidVersion(
            f"'{version}' is not valid semver (MAJOR.MINOR.PATCH[-pre][+build])"
        )
    text = text.split("+", 1)[0].lower()
    if len(text) > 1 and text[0] == "v" and text[1].isdigit():
        text = text[1:]
    tokens = tuple(int(t) if t.isdigit() else t for t in _TOKEN.findall(text))
    if not tokens or not isinstance(tokens[0], int):
        raise InvalidVersion(f"'{version}' must start with a number")
    return tokens


def compare_tokens(a: Tokens, b: Tokens) -> int:
    """Return -1, 0 or 1. Raises IncomparableVersions when no order exists."""
    for x, y in zip(a, b):
        if x == y:
            continue
        if x is INF or y is INF:
            return 1 if x is INF else -1
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            if x in PRERELEASE_RANK and y in PRERELEASE_RANK:
                rx, ry = PRERELEASE_RANK[x], PRERELEASE_RANK[y]
                if rx == ry:
                    continue  # "a" and "alpha" are the same marker
                return -1 if rx < ry else 1
            raise IncomparableVersions(f"cannot order '{x}' against '{y}'")
        # one int, one str
        word = x if isinstance(x, str) else y
        if word in PRERELEASE_RANK:
            return -1 if isinstance(x, str) else 1
        raise IncomparableVersions(f"cannot order '{x}' against '{y}'")

    if len(a) == len(b):
        return 0
    longer, sign = (a, 1) if len(a) > len(b) else (b, -1)
    nxt = longer[min(len(a), len(b))]
    if isinstance(nxt, str) and nxt in PRERELEASE_RANK:
        return -sign  # 1.0.0-rc1 < 1.0.0
    return sign  # 1.0 < 1.0.1, 10.2.9 < 10.2.9-h1, 12.1 < (12.1, INF)


def compare(a: str, b: str, scheme: str = "dotted") -> int:
    return compare_tokens(parse(a, scheme), parse(b, scheme))


def sort_key(scheme: str = "dotted"):
    return cmp_to_key(lambda a, b: compare(a, b, scheme))


def is_prefix(short: Tokens, long: Tokens) -> bool:
    """True when ``short`` is a strict leading prefix of ``long``."""
    return len(short) < len(long) and long[: len(short)] == short


@dataclass(frozen=True)
class Interval:
    """A version interval. ``None`` bounds mean unbounded on that side."""

    lower: Tokens | None  # inclusive
    upper: Tokens | None
    upper_inclusive: bool

    def contains(self, v: Tokens) -> bool:
        if self.lower is not None and compare_tokens(v, self.lower) < 0:
            return False
        if self.upper is None:
            return True
        c = compare_tokens(v, self.upper)
        return c <= 0 if self.upper_inclusive else c < 0

    def is_empty(self) -> bool:
        if self.lower is None or self.upper is None:
            return False
        c = compare_tokens(self.lower, self.upper)
        return c > 0 if self.upper_inclusive else c >= 0


def range_interval(rng: dict, scheme: str) -> Interval:
    """Turn one schema ``version_range`` object into an Interval.

    ``branch`` confines the range to one release line: branch "12.1" means
    [12.1, 12.1.<infinity>), which contains 12.1-65.25 but not 12.10 or 13.0.
    """
    introduced = rng["introduced"]
    lower = None if introduced == "0" else parse(introduced, scheme)
    upper: Tokens | None = None
    inclusive = False
    if rng.get("fixed"):
        upper = parse(rng["fixed"], scheme)
    elif rng.get("last_affected"):
        upper, inclusive = parse(rng["last_affected"], scheme), True

    if rng.get("branch"):
        branch = parse(rng["branch"], scheme)
        branch_end = branch + (INF,)
        if lower is None or compare_tokens(branch, lower) > 0:
            lower = branch
        if upper is None or compare_tokens(branch_end, upper) < 0:
            upper, inclusive = branch_end, False
    return Interval(lower, upper, inclusive)


def _before(a: Tokens | None, b: Tokens | None, b_inclusive: bool) -> bool:
    """Is lower bound ``a`` inside the region below upper bound ``b``?"""
    if a is None or b is None:
        return True
    c = compare_tokens(a, b)
    return c <= 0 if b_inclusive else c < 0


def overlaps(x: Interval, y: Interval) -> bool:
    return _before(x.lower, y.upper, y.upper_inclusive) and _before(
        y.lower, x.upper, x.upper_inclusive
    )
