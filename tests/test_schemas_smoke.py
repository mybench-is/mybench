"""Smoke test: the shipped JSON Schema stubs are valid Draft 2020-12 schemas.

Uses synthetic in-memory instances only (privacy invariant #3) — no real ledger
or transcript data is read.
"""

import json
from importlib import resources
from pathlib import Path

import jsonschema
from jsonschema.validators import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"


def _ledger_schema():
    # Lives inside the package (mybench/schemas/) so installed code can
    # validate rows; report.schema.json stays a top-level stub until MYB-4.1.
    return json.loads(
        resources.files("mybench.schemas").joinpath("ledger_entry.schema.json").read_text()
    )


def test_ledger_entry_schema_is_valid():
    Draft202012Validator.check_schema(_ledger_schema())


def test_report_schema_is_valid():
    Draft202012Validator.check_schema(json.loads((SCHEMA_DIR / "report.schema.json").read_text()))


def test_synthetic_report_validates():
    schema = json.loads((SCHEMA_DIR / "report.schema.json").read_text())
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


def test_synthetic_ledger_rows_validate():
    schema = _ledger_schema()
    genesis = {
        "schema_version": "1",
        "i": 0,
        "type": "genesis",
        "ts": "2020-01-01T00:00:00Z",
        "prev": "0" * 64,
        "h": "a" * 64,
    }
    session = {
        "schema_version": "1",
        "i": 1,
        "type": "session",
        "ts": "2020-01-01T00:00:00Z",
        "prev": "a" * 64,
        "h": "b" * 64,
        "session_id": "synthetic-0001",
        "session_root": "c" * 64,
        "item_count": 3,
        "source": "synthetic",
    }
    jsonschema.validate(genesis, schema)
    jsonschema.validate(session, schema)


def test_ledger_schema_rejects_content_shaped_fields():
    schema = _ledger_schema()
    bad = {
        "schema_version": "1",
        "i": 0,
        "type": "genesis",
        "ts": "2020-01-01T00:00:00Z",
        "prev": "0" * 64,
        "h": "a" * 64,
        "filename": "leak.py",
    }
    try:
        jsonschema.validate(bad, schema)
    except jsonschema.ValidationError:
        return
    raise AssertionError("schema accepted an extra 'filename' field")
