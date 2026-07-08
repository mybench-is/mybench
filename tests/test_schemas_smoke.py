"""Smoke test: the shipped JSON Schema stubs are valid Draft 2020-12 schemas.

Uses a synthetic in-memory instance only (privacy invariant #3) — no real ledger
or transcript data is read.
"""

import json
from pathlib import Path

import jsonschema
from jsonschema.validators import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"


def _load(name):
    return json.loads((SCHEMA_DIR / name).read_text())


def test_ledger_entry_schema_is_valid():
    Draft202012Validator.check_schema(_load("ledger_entry.schema.json"))


def test_report_schema_is_valid():
    Draft202012Validator.check_schema(_load("report.schema.json"))


def test_synthetic_report_validates():
    schema = _load("report.schema.json")
    instance = {
        "schema_version": "0",
        "report_version": "v0",
        "generated_at": "2020-01-01T00:00:00Z",
        "metrics": [
            {"name": "history_length_days", "value": 0, "trust_tier": "ANCHORED"},
            {"name": "commit_session_binding_coverage", "value": 0.0, "trust_tier": "PROVEN"},
        ],
    }
    jsonschema.validate(instance, schema)


def test_synthetic_ledger_entry_validates():
    schema = _load("ledger_entry.schema.json")
    instance = {
        "schema_version": "0",
        "entry_id": "synthetic-0001",
        "kind": "session",
        "commitment": "deadbeef",
        "timestamp": "2020-01-01T00:00:00Z",
    }
    jsonschema.validate(instance, schema)
