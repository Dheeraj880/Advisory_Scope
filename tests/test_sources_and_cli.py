import json

from conftest import FIXTURES, load_json

from advisory_scope import cli
from advisory_scope.compare import diff_records
from advisory_scope.sources import advisory_urls, find_kev, html_to_text, kev_to_text


def test_kev_lookup_and_text(kev_catalog):
    entry = find_kev(kev_catalog, "cve-2024-3400")
    text = kev_to_text(entry)
    assert "Vendor/Project: Palo Alto Networks" in text
    assert "Known Ransomware Campaign Use: Known" in text


def test_advisory_urls_prefer_vendor(kev_catalog):
    urls = advisory_urls(find_kev(kev_catalog, "CVE-2023-4966"))
    assert urls[0].startswith("https://www.netscaler.com/")
    assert urls[-1].startswith("https://nvd.nist.gov/")


def test_html_to_text_keeps_tables_drops_scripts():
    html = """<html><head><title>x</title><script>var a=1</script></head><body>
      <h1>CVE-2024-3400</h1><table><tr><th>Versions</th><th>Affected</th></tr>
      <tr><td>PAN-OS 11.1</td><td>&lt; 11.1.2-h3</td></tr></table></body></html>"""
    text = html_to_text(html)
    assert "var a" not in text
    assert "PAN-OS 11.1 | < 11.1.2-h3" in text


def test_diff_measures_coarse_extraction():
    gold = load_json(FIXTURES / "expected" / "CVE-2024-3400.json")
    naive = load_json(FIXTURES / "naive_CVE-2024-3400.json")
    d = diff_records(naive, gold)
    assert d["affected_products"]["recall"] == 1.0
    assert d["ranges"]["recall"] == 0.0  # none of the 18 per-hotfix ranges recovered
    assert diff_records(gold, gold)["ranges"] == {"precision": 1.0, "recall": 1.0, "extra": [], "missing": []}


def test_cli_end_to_end_offline(tmp_path, capsys):
    src, out = tmp_path / "source.json", tmp_path / "result.json"
    assert cli.main(["fetch", "--cve", "CVE-2024-3400", "--kev-catalog", str(FIXTURES / "kev_subset.json"),
                     "--advisory", str(FIXTURES / "advisories" / "CVE-2024-3400.txt"), "-o", str(src)]) == 0
    assert cli.main(["extract", "--source", str(src), "--replay",
                     str(FIXTURES / "replay" / "CVE-2024-3400.json"), "-o", str(out)]) == 0
    result = json.loads(out.read_text())
    assert result["validation"]["ok"] and len(result["attempts"]) == 2
    assert result["provenance"]["source"]["sha256"] == json.loads(src.read_text())["sha256"]

    assert cli.main(["validate", str(out), "--source", str(src)]) == 0
    assert cli.main(["match", str(out), "--assets", str(FIXTURES / "assets.csv")]) == 0
    printed = capsys.readouterr().out
    assert "precision=1.0 recall=1.0" in printed


def test_cli_validate_fails_bad_record(tmp_path):
    bad = load_json(FIXTURES / "replay" / "CVE-2024-3400.json")["responses"][0]
    rec = tmp_path / "bad.json"
    rec.write_text(json.dumps(bad))
    assert cli.main(["validate", str(rec), "--source", str(FIXTURES / "advisories" / "CVE-2024-3400.txt")]) == 2


def test_cli_extract_without_key_is_a_clear_error(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rc = cli.main(["extract", "--source", str(FIXTURES / "advisories" / "CVE-2024-3400.txt")])
    assert rc == 1
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err
