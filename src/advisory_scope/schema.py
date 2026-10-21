"""The record schema: one contract file, two views of it.

* ``load_schema()`` is the full contract. The deterministic validator enforces
  all of it (uniqueItems, minLength, ...).
* ``api_tool_schema()`` is the same schema with the keywords the Claude API's
  strict tool mode cannot compile into its grammar removed. Constrained decoding
  then guarantees the *shape*; the validator still enforces the stripped rules.

Keeping a single source of truth means the model and the validator can never
drift apart on what a valid record looks like.
"""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from importlib import resources  # nosemgrep: python37-compatibility-importlib2 -- requires-python >= 3.10
from typing import Any

SCHEMA_RESOURCE = ("advisory_scope", "schema/affected_products.schema.json")
SCHEMA_VERSION = "1.0"

# Fields the tool fills in itself. The model is never asked for constants: on the
# first live run Opus filled schema_version with something other than the string
# "1.0" three times in a row, burning every repair attempt on bookkeeping.
_TOOL_OWNED_FIELDS = ("schema_version",)

# Keywords strict tool use does not support (see "JSON Schema limitations" in the
# Anthropic structured-outputs docs). They stay in the contract and are enforced
# by validate.py instead.
_UNSUPPORTED_KEYWORDS = {
    "$schema",
    "$id",
    "minLength",
    "maxLength",
    "uniqueItems",
    "maxItems",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
}


@lru_cache(maxsize=1)
def _schema_text() -> str:
    package, name = SCHEMA_RESOURCE
    return resources.files(package).joinpath(name).read_text(encoding="utf-8")


def load_schema() -> dict[str, Any]:
    """Full contract schema (JSON Schema 2020-12)."""
    return json.loads(_schema_text())


def _strip(node: Any) -> Any:
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key in _UNSUPPORTED_KEYWORDS:
                continue
            if key == "minItems" and isinstance(value, int) and value > 1:
                continue  # only 0 and 1 are supported
            out[key] = _strip(value)
        return out
    if isinstance(node, list):
        return [_strip(item) for item in node]
    return node


def api_tool_schema() -> dict[str, Any]:
    """Contract schema reduced to the subset strict tool use accepts, minus tool-owned fields."""
    schema = _strip(copy.deepcopy(load_schema()))
    for name in _TOOL_OWNED_FIELDS:
        schema["properties"].pop(name, None)
        schema["required"] = [r for r in schema["required"] if r != name]
    return schema
