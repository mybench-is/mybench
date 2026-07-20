"""Machine-check the accepted MYB-13.1 report-v2 assembly whitelist.

Synthetic in-memory values only (privacy invariant #3). This does not activate
schema v2 in the report runner; it proves the accepted schema artifact is
closed before implementation activation.
"""

from __future__ import annotations

import copy

import jsonschema
import pytest

from mybench.schemas import load_validator


FIELD = {
    "registry_id": "fingerprint.summary.task_episode_total",
    "registry_version": "0.1.0",
    "claim_digest": "a" * 64,
    "derivation_class": "measured",
    "execution_env": "local-unattested",
    "trust_tier": "ANCHORED",
    "anchor_state": "covered",
    "disclosure": "PUBLISHABLE",
    "inference_risk": "R0",
    "coverage_basis_points": 10000,
    "confidence": "HIGH",
    "value": 12,
}

REPORT = {
    "schema_version": "2",
    "report_version": "v0.2.0",
    "generated_at": "2026-01-01T00:00:00Z",
    "scorer_version": "0.2.0",
    "input_schema_versions": {
        "ledger": ["2"],
        "anchor": ["2"],
        "normalized_events": ["1"],
        "phase_classifier": ["1.0.0"],
    },
    "registry": {"version": "0.2.0", "digest": "b" * 64},
    "evidence_period": {"start": "2025-10-01", "end": "2025-12-31"},
    "anchored_through": "2026-01-01",
    "metrics": [{"name": "anchored_span_days", "value": 90, "trust_tier": "PROVEN"}],
    "catalog_metrics": [],
    "fingerprint": {
        "workflow_summary": {"status": "available", "fields": [FIELD]},
        "workflow_map": {"status": "not-supported", "fields": []},
        "model_role_profile": {"status": "not-supported", "fields": []},
        "context_management_profile": {"status": "not-supported", "fields": []},
        "orchestration_topology": {"status": "not-supported", "fields": []},
        "token_cost_profile": {"status": "not-supported", "fields": []},
        "evidence_coverage": {"status": "not-supported", "fields": []},
    },
}


def _validate(report: dict) -> None:
    load_validator("report-v2.schema.json").validate(report)


def test_report_v2_validates() -> None:
    _validate(REPORT)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(session_ids=["synthetic-session"]),
        lambda r: r["fingerprint"].update(extra_section={"status": "not-supported", "fields": []}),
        lambda r: r["fingerprint"]["workflow_summary"]["fields"][0].update(path="private"),
        lambda r: r["fingerprint"]["workflow_summary"]["fields"][0].update(value=1.5),
        lambda r: r["fingerprint"]["workflow_summary"]["fields"][0].update(
            disclosure="PUBLIC_BY_DEFAULT"
        ),
        lambda r: r["fingerprint"]["workflow_summary"].update(fields=[]),
        lambda r: r["fingerprint"]["workflow_map"].update(fields=[copy.deepcopy(FIELD)]),
        lambda r: r.pop("catalog_metrics"),
        lambda r: r.update(schema_version="1"),
    ],
    ids=[
        "extra-top-level",
        "extra-section",
        "extra-field-metadata",
        "float-value",
        "unknown-disclosure",
        "available-without-fields",
        "unsupported-with-field",
        "missing-catalog-lane",
        "wrong-version",
    ],
)
def test_report_v2_rejects_widening(mutate) -> None:
    bad = copy.deepcopy(REPORT)
    mutate(bad)
    with pytest.raises(jsonschema.ValidationError):
        _validate(bad)


def test_report_v2_rejects_extra_cell_properties() -> None:
    bad = copy.deepcopy(REPORT)
    bad["fingerprint"]["workflow_summary"]["fields"][0]["value"] = [
        {"dimensions": ["PLAN", "BUILD"], "value": "25-49%", "session": "forbidden"}
    ]
    with pytest.raises(jsonschema.ValidationError):
        _validate(bad)


def test_catalog_metrics_reserves_closed_registry_governed_lane() -> None:
    report = copy.deepcopy(REPORT)
    report["catalog_metrics"] = [
        {
            **copy.deepcopy(FIELD),
            "registry_id": "repo.blame_survival.band",
            "trust_tier": "PROVEN",
            "caveats": ["persistence-not-quality"],
        }
    ]
    _validate(report)

    report["catalog_metrics"][0]["display_copy"] = "forbidden"
    with pytest.raises(jsonschema.ValidationError):
        _validate(report)


def test_reserved_reference_and_conditioning_shapes_are_closed() -> None:
    report = copy.deepcopy(REPORT)
    field = report["fingerprint"]["workflow_summary"]["fields"][0]
    field["reference_frame"] = {
        "reference_corpus_id": "cohort.founder-v1",
        "reference_version": "0.1.0",
        "as_of_date": "2026-01-01",
        "percentile_band": "p50-p74",
    }
    field["conditioning"] = {
        "axis": "arrival-pattern",
        "cell": "prepared-spec",
        "min_support_met": True,
    }
    _validate(report)

    field["conditioning"]["denominator"] = 10
    with pytest.raises(jsonschema.ValidationError):
        _validate(report)


def test_publishable_conditioning_cannot_report_failed_support() -> None:
    report = copy.deepcopy(REPORT)
    field = report["fingerprint"]["workflow_summary"]["fields"][0]
    field["conditioning"] = {
        "axis": "arrival-pattern",
        "cell": "prepared-spec",
        "min_support_met": False,
    }
    with pytest.raises(jsonschema.ValidationError):
        _validate(report)

    field["disclosure"] = "LOCAL_ONLY"
    _validate(report)


def test_caveats_are_controlled_codes() -> None:
    report = copy.deepcopy(REPORT)
    field = report["fingerprint"]["workflow_summary"]["fields"][0]
    field["caveats"] = ["provider-reported-inflatable"]
    _validate(report)

    field["caveats"] = ["Provider reported and potentially inflatable."]
    with pytest.raises(jsonschema.ValidationError):
        _validate(report)


def test_tier_qualifier_matches_judged_execution_environment() -> None:
    report = copy.deepcopy(REPORT)
    field = report["fingerprint"]["workflow_summary"]["fields"][0]
    field.update(trust_tier="JUDGED", tier_qualifier="unattested")
    _validate(report)

    field["tier_qualifier"] = "attested"
    with pytest.raises(jsonschema.ValidationError):
        _validate(report)

    field.update(execution_env="tee-attested", tier_qualifier="attested")
    _validate(report)


def test_tee_verified_requires_measured_attested_execution() -> None:
    report = copy.deepcopy(REPORT)
    field = report["fingerprint"]["workflow_summary"]["fields"][0]
    field.update(trust_tier="TEE-VERIFIED", execution_env="tee-attested")
    _validate(report)

    field["derivation_class"] = "characterization"
    with pytest.raises(jsonschema.ValidationError):
        _validate(report)
