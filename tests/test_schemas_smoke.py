"""Smoke tests: packaged JSON Schemas are valid and enforce their whitelists.

Uses synthetic in-memory instances only (privacy invariant #3).
"""

import jsonschema
import pytest
from jsonschema.validators import Draft202012Validator

from mybench.schemas import load_validator


def _schema(name):
    return load_validator(name).schema


def _all_packaged_schemas():
    # Glob, not an enumeration: a schema added without metaschema coverage
    # would silently widen its whitelist at validation time (MYB-10.1 review).
    from importlib import resources

    names = sorted(
        r.name
        for r in resources.files("mybench.schemas").iterdir()
        if r.name.endswith(".schema.json")
    )
    assert names, "no packaged schemas found"
    return names


@pytest.mark.parametrize("name", _all_packaged_schemas())
def test_packaged_schemas_are_valid(name):
    Draft202012Validator.check_schema(_schema(name))


REPORT = {
    "schema_version": "1",
    "report_version": "v0",
    "generated_at": "2026-01-01T00:00:00Z",
    "scorer_version": "0.1.0",
    "backfill_note": "history captured by backfill is anchored as of anchor time",
    "binding_tips": {"synthetic/repo": "a" * 40},
    "metrics": [
        {"name": "anchored_span_days", "value": 0, "trust_tier": "PROVEN"},
        {
            "name": "session_size_distribution",
            "value": {"1-10": 2, "11-100": 1, "101-1000": 0, "1000+": 0},
            "trust_tier": "ANCHORED",
        },
        {
            "name": "items_total",
            "value": 42,
            "trust_tier": "ANCHORED",
            "caveat": "synthetic caveat text",
        },
    ],
}


def test_synthetic_report_validates():
    jsonschema.validate(REPORT, _schema("report.schema.json"))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(session_list=["x"]),  # extra top-level field
        lambda r: r["metrics"][0].update(samples=[1, 2, 3]),  # extra metric field
        lambda r: r["metrics"][0].update(trust_tier="TEE-VERIFIED"),  # future tier: bump first
        lambda r: r["metrics"][0].update(name="Hour_Of_Day"),  # name pattern
        lambda r: r["metrics"][1].update(value=[1, 2, 3]),  # ordered sequence as value
        lambda r: r.pop("scorer_version"),
        lambda r: r.pop("metrics"),
    ],
    ids=["extra-top", "extra-metric-field", "unknown-tier", "bad-name", "sequence-value",
         "no-scorer-version", "no-metrics"],
)
def test_report_whitelist_rejects(mutate):
    import copy

    bad = copy.deepcopy(REPORT)
    mutate(bad)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, _schema("report.schema.json"))


def test_synthetic_ledger_rows_validate():
    schema = _schema("ledger_entry.schema.json")
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


def test_schema_v2_lifecycle_row_is_closed_and_v1_stays_frozen():
    schema = _schema("ledger_entry.schema.json")
    event = {
        "schema_version": "2",
        "i": 1,
        "type": "event",
        "ts": "2026-07-15T20:00:00Z",
        "prev": "a" * 64,
        "h": "b" * 64,
        "event_kind": "compact_pre",
        "trigger": "manual",
        "session_id": "synthetic-session-a1",
        "context_gen": 1,
        "harness": "claude-code",
    }
    jsonschema.validate(event, schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**event, "custom_instructions": "must never fit"}, schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**event, "schema_version": "1"}, schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**event, "trigger": "startup"}, schema)


def test_ledger_schema_rejects_content_shaped_fields():
    schema = _schema("ledger_entry.schema.json")
    bad = {
        "schema_version": "1",
        "i": 0,
        "type": "genesis",
        "ts": "2020-01-01T00:00:00Z",
        "prev": "0" * 64,
        "h": "a" * 64,
        "filename": "leak.py",
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)
