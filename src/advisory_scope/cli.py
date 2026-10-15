"""Command-line interface.

  advisory-scope fetch    --cve CVE-2024-3400 [--advisory FILE|URL] [--follow-notes] -o source.json
  advisory-scope extract  --source source.json -o result.json          (needs ANTHROPIC_API_KEY)
  advisory-scope validate result.json --source source.json             (deterministic, no LLM)
  advisory-scope match    result.json --assets assets.csv [--db scans.sqlite]
  advisory-scope diff     result.json expected.json
  advisory-scope schema   [--api]

Exit codes: 0 success, 1 usage/runtime error, 2 record failed validation.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .agent import DEFAULT_MODEL, ExtractionError, ReplayClient, extract
from .compare import diff_records
from .matcher import load_assets_csv, match_record, open_db, score, summary
from .schema import api_tool_schema, load_schema
from .sources import Source, build_source, load_kev_catalog
from .validate import validate_record

EXIT_OK, EXIT_ERROR, EXIT_INVALID = 0, 1, 2


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _write_json(data: Any, out: str | None) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if out:
        Path(out).write_text(text, encoding="utf-8")
        _err(f"wrote {out}")
    else:
        sys.stdout.write(text)


def _load_record(path: str) -> dict[str, Any]:
    """Accept a bare record or an `extract` envelope ({"record": ...})."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data["record"] if isinstance(data, dict) and "record" in data and "affected" not in data else data


def _load_source_file(path: str) -> Source:
    """A source bundle from `fetch` (.json) or plain advisory text (anything else)."""
    p = Path(path)
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        return Source(data["text"], data["kind"], data["origin"], data.get("kev_entry"), data.get("notes", []))
    return Source(p.read_text(encoding="utf-8"), "advisory", str(p))


def _source_from_args(args) -> Source:
    if getattr(args, "source", None):
        return _load_source_file(args.source)
    catalog = load_kev_catalog(args.kev_catalog) if args.cve else None
    return build_source(cve=args.cve, advisory=args.advisory, kev_catalog=catalog,
                        follow_notes=args.follow_notes)


def _print_report(report, stream=sys.stderr) -> None:
    status = "PASS" if report.ok else "FAIL"
    review = " (human review required)" if report.ok and report.review_required else ""
    print(f"validation: {status}{review} - {len(report.errors)} error(s), "
          f"{len(report.warnings)} warning(s), {len(report.infos)} info", file=stream)
    for f in report.findings:
        print(f"  {f}", file=stream)


# --- commands -----------------------------------------------------------------

def cmd_fetch(args) -> int:
    source = _source_from_args(args)
    for note in source.notes:
        _err(f"note: {note}")
    _write_json({"text": source.text, "kind": source.kind, "origin": source.origin,
                 "kev_entry": source.kev_entry, "notes": source.notes, "sha256": source.sha256}, args.out)
    return EXIT_OK


def cmd_extract(args) -> int:
    source = _source_from_args(args)
    if args.replay:
        client, model = ReplayClient.from_file(args.replay), f"replay:{Path(args.replay).name}"
    else:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            _err("ANTHROPIC_API_KEY is not set. Export it, or use --replay FILE for an offline run.")
            return EXIT_ERROR
        import anthropic

        client, model = anthropic.Anthropic(), args.model
    try:
        result = extract(source, client, model=model, max_attempts=args.max_attempts,
                         max_tokens=args.max_tokens)
    except ExtractionError as exc:
        _err(f"extraction failed: {exc}")
        return EXIT_ERROR
    for a in result.attempts:
        _err(f"attempt {a.number}: {'PASS' if a.report.ok else 'FAIL'} "
             f"({len(a.report.errors)} error(s), {len(a.report.warnings)} warning(s))")
    _print_report(result.report)
    _write_json(result.to_dict(), args.out)
    return EXIT_OK if result.ok else EXIT_INVALID


def cmd_validate(args) -> int:
    record = _load_record(args.record)
    source = _load_source_file(args.source)
    report = validate_record(record, source.text, source.kev_entry)
    if args.json:
        _write_json(report.to_dict(), None)
    else:
        _print_report(report, sys.stdout)
    return EXIT_OK if report.ok else EXIT_INVALID


def cmd_match(args) -> int:
    record = _load_record(args.record)
    conn = open_db(args.db or ":memory:")
    if args.assets:
        n = load_assets_csv(conn, args.assets)
        _err(f"loaded {n} observation(s) from {args.assets}")
    detections = match_record(conn, record)
    result = {"summary": summary(conn, record), "score": score(detections),
              "detections": [d.to_dict() for d in detections]}
    if args.json:
        _write_json(result, args.out)
        return EXIT_OK

    print(f"{'ASSET':<10} {'PRODUCT':<22} {'VERSION':<14} {'VERDICT':<19} REASON")
    for d in detections:
        if not d.expected_verdict or d.expected_verdict == d.verdict:
            flag = ""
        elif d.verdict == "VERSION_UNKNOWN":
            flag = f"  << lab truth {d.expected_verdict} (coverage gap: version not resolved)"
        else:
            flag = f"  << WRONG, lab truth {d.expected_verdict}"
        print(f"{d.asset_id:<10} {d.product[:22]:<22} {(d.version or '-'):<14} {d.verdict:<19} {d.reason}{flag}")
    s = result["summary"]
    print(f"\nverdicts: {s['verdicts']}")
    print(f"version resolution: {s['version_resolved']}/{s['identified_assets']} "
          f"identified assets ({s['version_resolution_pct']}%)")
    if result["score"]:
        sc = result["score"]
        print(f"vs ground truth: precision={sc['precision']} recall={sc['recall']} "
              f"(tp={sc['tp']} fp={sc['fp']} fn={sc['fn']} tn={sc['tn']}, unknown={sc['version_unknown']})")
        if sc["false_positives"]:
            print(f"false positives: {', '.join(sc['false_positives'])}")
        if sc["false_negatives"]:
            print(f"false negatives: {', '.join(sc['false_negatives'])}")
    if args.out:
        _write_json(result, args.out)
    return EXIT_OK


def cmd_diff(args) -> int:
    _write_json(diff_records(_load_record(args.actual), _load_record(args.expected)), None)
    return EXIT_OK


def cmd_schema(args) -> int:
    _write_json(api_tool_schema() if args.api else load_schema(), None)
    return EXIT_OK


# --- parser -------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="advisory-scope", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def source_args(sp, allow_bundle: bool):
        sp.add_argument("--cve", help="look up this CVE in the CISA KEV catalog")
        sp.add_argument("--advisory", help="vendor advisory: local .txt/.md/.html file or URL")
        sp.add_argument("--kev-catalog", help="KEV catalog JSON path or URL (default: official feed)")
        sp.add_argument("--follow-notes", action="store_true",
                        help="fetch the first vendor advisory URL listed in the KEV entry")
        if allow_bundle:
            sp.add_argument("--source", help="source bundle from `fetch` (.json) or advisory text file")

    sp = sub.add_parser("fetch", help="build the source text (KEV entry and/or advisory)")
    source_args(sp, allow_bundle=False)
    sp.add_argument("-o", "--out")
    sp.set_defaults(func=cmd_fetch)

    sp = sub.add_parser("extract", help="LLM extraction with validator-driven repair loop")
    source_args(sp, allow_bundle=True)
    sp.add_argument("--model", default=os.environ.get("ADVISORY_SCOPE_MODEL", DEFAULT_MODEL))
    sp.add_argument("--max-attempts", type=int, default=3)
    sp.add_argument("--max-tokens", type=int, default=16000)
    sp.add_argument("--replay", help="offline: JSON file of scripted tool inputs instead of the API")
    sp.add_argument("-o", "--out")
    sp.set_defaults(func=cmd_extract)

    sp = sub.add_parser("validate", help="deterministically validate a record against its source")
    sp.add_argument("record", help="record JSON or `extract` output")
    sp.add_argument("--source", required=True, help="source bundle (.json) or advisory text file")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("match", help="apply a record to an asset corpus")
    sp.add_argument("record")
    sp.add_argument("--assets", help="observations CSV to load")
    sp.add_argument("--db", help="SQLite file to use/keep (default: in-memory)")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("-o", "--out")
    sp.set_defaults(func=cmd_match)

    sp = sub.add_parser("diff", help="compare a record to a golden record")
    sp.add_argument("actual")
    sp.add_argument("expected")
    sp.set_defaults(func=cmd_diff)

    sp = sub.add_parser("schema", help="print the record schema")
    sp.add_argument("--api", action="store_true", help="the subset sent to the API as the strict tool schema")
    sp.set_defaults(func=cmd_schema)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in ("fetch", "extract") and not (args.cve or args.advisory or getattr(args, "source", None)):
        _err("give --cve, --advisory, or --source")
        return EXIT_ERROR
    try:
        return args.func(args)
    except (KeyError, ValueError, FileNotFoundError, RuntimeError) as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
