# Test cases for advisory-scope.yml. Not imported anywhere; excluded from ruff and CodeQL.
import json
import subprocess
from pathlib import Path

import httpx


def returns_raw_model_output(call):
    # ruleid: advscope-model-record-not-validated
    record = call.input
    return record


def validates_model_output(call, source):
    # ok: advscope-model-record-not-validated
    record = call.input if isinstance(call.input, dict) else json.loads(call.input)
    report = validate_record(record, source.text, source.kev_entry)
    return record if report.ok else None


def retry_loop(calls, source):
    for call in calls:
        # ok: advscope-model-record-not-validated
        record = call.input if isinstance(call.input, dict) else json.loads(call.input)
        record = {"schema_version": 1, **record}
        report = validate_record(record, source.text, source.kev_entry)
        if report.ok:
            return record
    return None


def advisory_text_executed(url):
    body, _ = _http_get(url)
    # ruleid: advscope-untrusted-text-to-dangerous-sink
    subprocess.run(body, shell=True)


def model_picks_output_path(call):
    # ruleid: advscope-model-record-not-validated
    out = call.input
    # ruleid: advscope-untrusted-text-to-dangerous-sink
    Path(out["path"]).write_text("x")


def advisory_document_deserialized(location):
    text, _ = load_document(location)
    # ruleid: advscope-untrusted-text-to-dangerous-sink
    eval(text)


def parsed_as_json_is_fine(url):
    body, _ = _http_get(url)
    # ok: advscope-untrusted-text-to-dangerous-sink
    return json.loads(body)


def insecure_fetch(url):
    # ruleid: advscope-tls-verification-disabled
    return httpx.get(url, verify=False)


def secure_fetch(url):
    # ok: advscope-tls-verification-disabled
    return httpx.get(url, timeout=30.0, follow_redirects=True)
