"""Source ingestion: CISA KEV entries and vendor advisories -> plain text.

The text produced here is the *ground truth* the validator checks every claim
against, so it is built deterministically and hashed into the output.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, ClassVar

# CISA publishes KEV on cisa.gov and mirrors it to GitHub. Try the mirror first:
# it is the same data and is reachable from more networks.
KEV_URLS = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
MAX_ADVISORY_CHARS = 60_000
USER_AGENT = "advisory-scope/0.1 (+https://github.com/)"
_URL = re.compile(r"https?://[^\s;,<>\"')\]]+")


@dataclass
class Source:
    text: str
    kind: str  # "kev", "advisory", or "kev+advisory"
    origin: str
    kev_entry: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    def provenance(self) -> dict[str, Any]:
        return {"kind": self.kind, "origin": self.origin, "sha256": self.sha256, "notes": self.notes}


# --- HTML -> text -----------------------------------------------------------

class _TextExtractor(HTMLParser):
    _SKIP: ClassVar[set[str]] = {"script", "style", "noscript", "svg", "head", "nav", "footer"}
    _BLOCK: ClassVar[set[str]] = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
                                   "section", "article", "table", "ul", "ol", "pre", "blockquote"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag in ("td", "th"):
            self.parts.append(" | ")
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip_depth:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    raw = "".join(parser.parts)
    lines = [re.sub(r"[ \t ]+", " ", line).strip() for line in raw.splitlines()]
    out: list[str] = []
    for line in lines:
        if line or (out and out[-1]):
            out.append(line)
    return "\n".join(out).strip()


# --- fetching ----------------------------------------------------------------

def _http_get(url: str, timeout: float = 30.0) -> tuple[str, str]:
    import httpx  # imported lazily so offline commands never need it

    resp = httpx.get(url, timeout=timeout, follow_redirects=True, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    return resp.text, resp.headers.get("content-type", "")


def load_document(location: str) -> tuple[str, list[str]]:
    """Read a local file or URL and return (plain text, notes)."""
    notes: list[str] = []
    if re.match(r"^https?://", location):
        body, ctype = _http_get(location)
        is_html = "html" in ctype.lower()
    else:
        path = Path(location)
        body = path.read_text(encoding="utf-8", errors="replace")
        is_html = path.suffix.lower() in (".html", ".htm")
    text = html_to_text(body) if is_html else body.strip()
    if len(text) > MAX_ADVISORY_CHARS:
        notes.append(f"advisory text truncated from {len(text)} to {MAX_ADVISORY_CHARS} characters")
        text = text[:MAX_ADVISORY_CHARS]
    if is_html and len(text) < 400:
        notes.append("very little text extracted from HTML; the page may need JavaScript. "
                     "Save the advisory as text and pass the file instead.")
    return text, notes


def load_kev_catalog(location: str | None = None) -> dict[str, Any]:
    """Load the KEV catalog from a path or URL; default tries the official feeds."""
    if location and not re.match(r"^https?://", location):
        return json.loads(Path(location).read_text(encoding="utf-8"))
    errors = []
    for url in ([location] if location else KEV_URLS):
        try:
            body, _ = _http_get(url, timeout=60.0)
            return json.loads(body)
        except Exception as exc:  # noqa: BLE001 - report every failed mirror
            errors.append(f"{url}: {exc}")
    raise RuntimeError("could not download the KEV catalog:\n  " + "\n  ".join(errors))


def find_kev(catalog: dict[str, Any], cve_id: str) -> dict[str, Any]:
    cve_id = cve_id.strip().upper()
    for entry in catalog.get("vulnerabilities", []):
        if entry.get("cveID", "").upper() == cve_id:
            return entry
    raise KeyError(f"{cve_id} is not in the KEV catalog (version {catalog.get('catalogVersion', '?')})")


def kev_to_text(entry: dict[str, Any]) -> str:
    fields = [
        ("CVE ID", "cveID"),
        ("Vendor/Project", "vendorProject"),
        ("Product", "product"),
        ("Vulnerability Name", "vulnerabilityName"),
        ("Date Added", "dateAdded"),
        ("Short Description", "shortDescription"),
        ("Required Action", "requiredAction"),
        ("Due Date", "dueDate"),
        ("Known Ransomware Campaign Use", "knownRansomwareCampaignUse"),
        ("Notes", "notes"),
    ]
    lines = [f"{label}: {entry[key]}" for label, key in fields if entry.get(key)]
    if entry.get("cwes"):
        lines.append("CWEs: " + ", ".join(entry["cwes"]))
    return "\n".join(lines)


def advisory_urls(entry: dict[str, Any]) -> list[str]:
    """Vendor URLs from a KEV entry's notes, vendor links before NVD/CISA."""
    urls = []
    for url in _URL.findall(entry.get("notes", "") + " " + entry.get("requiredAction", "")):
        url = url.rstrip(".")
        if url not in urls:
            urls.append(url)
    secondary = ("nvd.nist.gov", "cisa.gov")
    return [u for u in urls if not any(s in u for s in secondary)] + [
        u for u in urls if any(s in u for s in secondary)
    ]


def build_source(
    cve: str | None = None,
    advisory: str | None = None,
    kev_catalog: dict[str, Any] | None = None,
    follow_notes: bool = False,
) -> Source:
    """Assemble the text the model reads and the validator checks against."""
    if not cve and not advisory:
        raise ValueError("give a CVE ID (KEV lookup), an advisory file/URL, or both")
    sections: list[str] = []
    notes: list[str] = []
    kev_entry = None
    origins: list[str] = []

    if cve:
        catalog = kev_catalog if kev_catalog is not None else load_kev_catalog()
        kev_entry = find_kev(catalog, cve)
        sections.append(f"=== CISA KEV ENTRY ===\n{kev_to_text(kev_entry)}")
        notes.append(f"KEV catalog version {catalog.get('catalogVersion', '?')}")
        origins.append(f"kev:{kev_entry['cveID']}")
        if follow_notes and not advisory:
            for url in advisory_urls(kev_entry):
                try:
                    text, doc_notes = load_document(url)
                except Exception as exc:  # noqa: BLE001
                    notes.append(f"could not fetch {url}: {exc}")
                    continue
                notes += doc_notes
                sections.append(f"=== VENDOR ADVISORY ({url}) ===\n{text}")
                origins.append(url)
                break
            else:
                notes.append("no linked advisory could be fetched; extracting from the KEV entry alone")

    if advisory:
        text, doc_notes = load_document(advisory)
        notes += doc_notes
        sections.append(f"=== VENDOR ADVISORY ({advisory}) ===\n{text}")
        origins.append(advisory)

    kind = "kev+advisory" if kev_entry and len(sections) > 1 else ("kev" if kev_entry else "advisory")
    return Source("\n\n".join(sections), kind, " + ".join(origins), kev_entry, notes)
