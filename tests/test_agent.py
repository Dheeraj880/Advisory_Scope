import json

import pytest
from conftest import FIXTURES, load_json

from advisory_scope.agent import TOOL_NAME, ExtractionError, ReplayClient, extract, tool_definition
from advisory_scope.schema import api_tool_schema


def test_repair_loop_feeds_errors_back_and_converges(source_for):
    client = ReplayClient.from_file(FIXTURES / "replay" / "CVE-2024-3400.json")
    result = extract(source_for("CVE-2024-3400"), client, model="test", max_attempts=3)

    assert result.ok
    assert [a.report.ok for a in result.attempts] == [False, True]
    first_errors = {f.code for f in result.attempts[0].report.errors}
    assert first_errors == {"evidence_not_verbatim", "version_not_in_source", "affected_and_not_affected"}

    # Second request must replay the model's tool call and return the errors as an is_error tool_result
    second = client.requests[1]
    # Opus 5.5 / Sonnet 5.5 reject forced tool_choice; the tool call is requested in the prompt instead
    assert second["tool_choice"] == {"type": "auto"}
    assert TOOL_NAME in second["messages"][0]["content"]
    assistant, user = second["messages"][1], second["messages"][2]
    assert assistant["role"] == "assistant" and assistant["content"][0]["type"] == "tool_use"
    tool_result = user["content"][0]
    assert tool_result["type"] == "tool_result"
    assert tool_result["is_error"] is True
    assert tool_result["tool_use_id"] == assistant["content"][0]["id"]
    assert "11.1.3" in tool_result["content"]


def test_gives_up_after_max_attempts_and_reports_failure(source_for):
    bad = load_json(FIXTURES / "replay" / "CVE-2024-3400.json")["responses"][0]
    client = ReplayClient([bad, bad])
    result = extract(source_for("CVE-2024-3400"), client, model="test", max_attempts=2)
    assert not result.ok
    assert len(result.attempts) == 2
    out = result.to_dict()
    assert out["validation"]["ok"] is False and out["review_required"] is True


def test_source_is_untrusted_and_wrapped(source_for):
    client = ReplayClient([load_json(FIXTURES / "expected" / "CVE-2024-3400.json")])
    extract(source_for("CVE-2024-3400"), client, model="test")
    req = client.requests[0]
    assert "untrusted" in req["system"]
    assert req["messages"][0]["content"].count("<source") == 1


class ScriptedClient:
    """Returns a text-only reply first, then tool calls with the given records."""

    def __init__(self, text_replies, records):
        self.text_replies, self.records, self.requests = text_replies, list(records), []
        self.messages = self

    def create(self, **kwargs):
        from types import SimpleNamespace
        self.requests.append(json.loads(json.dumps(kwargs)))
        if self.text_replies:
            self.text_replies -= 1
            return SimpleNamespace(content=[SimpleNamespace(type="text", text="I think it is 10.2")],
                                   stop_reason="end_turn")
        block = SimpleNamespace(type="tool_use", id=f"toolu_{len(self.requests)}", name=TOOL_NAME,
                                input=self.records.pop(0))
        return SimpleNamespace(content=[block], stop_reason="tool_use")


def test_missing_tool_call_is_nudged_then_succeeds(source_for):
    gold = load_json(FIXTURES / "expected" / "CVE-2024-3400.json")
    client = ScriptedClient(1, [gold])
    result = extract(source_for("CVE-2024-3400"), client, model="test")
    assert result.ok
    nudge = client.requests[1]["messages"][-1]
    assert nudge["role"] == "user" and "did not call" in nudge["content"]


def test_never_calling_the_tool_raises(source_for):
    with pytest.raises(ExtractionError):
        extract(source_for("CVE-2024-3400"), ScriptedClient(3, []), model="test", max_attempts=3)


def _walk(node, path="$"):
    if isinstance(node, dict):
        yield path, node
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


def test_schema_version_is_set_by_the_tool_not_the_model(source_for):
    """The model is never asked for constants; whatever it sends, the tool sets it."""
    assert "schema_version" not in api_tool_schema()["properties"]
    assert "schema_version" not in api_tool_schema()["required"]
    gold = load_json(FIXTURES / "expected" / "CVE-2024-3400.json")
    for sent in ({k: v for k, v in gold.items() if k != "schema_version"}, {**gold, "schema_version": 1.0}):
        result = extract(source_for("CVE-2024-3400"), ReplayClient([sent]), model="test")
        assert result.ok and result.record["schema_version"] == "1.0"


def test_api_schema_fits_strict_tool_limits():
    """Strict tool use: objects need additionalProperties false, no unsupported keywords,
    minItems only 0/1, <=24 optional params, <=16 union-typed params."""
    schema = api_tool_schema()
    banned = {"minLength", "maxLength", "uniqueItems", "maxItems", "minimum", "maximum", "$schema", "$id"}
    unions = optional = 0
    for path, node in _walk(schema):
        assert not banned & set(node), path
        if node.get("minItems") is not None:
            assert node["minItems"] in (0, 1), path
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False, path
            optional += len(set(node.get("properties", {})) - set(node.get("required", [])))
        if isinstance(node.get("type"), list) or "anyOf" in node:
            unions += 1
    assert optional <= 24 and unions <= 16
    assert tool_definition()["strict"] is True
    json.dumps(tool_definition())  # serializable
