"""MYB-13.8 shared coverage contract and evidence-coverage aggregate."""

from __future__ import annotations

import copy
import json

import jsonschema
import pytest

from mybench.claims.canonical import canonical_bytes
from mybench.schemas import load_validator
from mybench.scorer import (
    AMBIGUITY_CATEGORIES,
    EvidenceCoverageError,
    basis_points,
    build_coverage_contribution,
    confidence,
    score_evidence_coverage,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures
from tests.test_report_v2_schema_spec import REPORT as REPORT_V2


LEGACY_METRICS = [
    {
        "name": "binding_coverage",
        "value": {"synthetic-public-repo": 0.5},
        "trust_tier": "PROVEN",
    },
    {
        "name": "evidence_provenance_split",
        "value": {"IMPORTED": 0.4286, "LIVE": 0.5714},
        "trust_tier": "PROVEN",
    },
]


def _contributions() -> list[dict]:
    return [
        build_coverage_contribution(
            "workflow-map",
            {},
            missing_ambiguous={"unknown-phase": 2},
        ),
        build_coverage_contribution(
            "model-role-profile",
            {"model": (4, 5), "effort": (2, 5)},
            missing_ambiguous={"missing-model": 1, "missing-effort": 3},
        ),
        build_coverage_contribution(
            "context-management-profile",
            {"context-lifecycle": (0, 5)},
            missing_ambiguous={"missing-marker": 5},
        ),
        build_coverage_contribution(
            "token-cost-profile",
            {"token-data": None},
            missing_ambiguous={"missing-token-data": 5},
        ),
    ]


def test_pinned_rate_rounding_confidence_and_invalid_counts() -> None:
    assert basis_points(1, 6) == 1667
    assert basis_points(0, 5) == 0
    assert basis_points(0, 0) == "UNKNOWN"
    assert confidence(0) == "LOW"
    assert confidence(5000) == "MEDIUM"
    assert confidence(7500) == "HIGH"
    assert confidence("UNKNOWN") == "UNKNOWN"
    for covered, eligible in ((-1, 5), (6, 5)):
        with pytest.raises(EvidenceCoverageError, match="inconsistent"):
            basis_points(covered, eligible)
    with pytest.raises(EvidenceCoverageError, match="integers"):
        basis_points(True, 5)


def test_every_section_contract_is_closed_sorted_and_deterministic() -> None:
    first = _contributions()
    second = _contributions()
    assert canonical_bytes(first) == canonical_bytes(second)
    validator = load_validator("fingerprint_coverage_input.schema.json")
    for contribution in first:
        validator.validate(contribution)

    context = next(item for item in first if item["producer"] == "context-management-profile")
    assert context["observations"] == [
        {
            "input_class": "context-lifecycle",
            "basis": "reliable-lifecycle-marker-per-eligible-session",
            "coverage_basis_points": 0,
            "confidence": "LOW",
            "evidence_state": "partial",
        }
    ]
    token = next(item for item in first if item["producer"] == "token-cost-profile")
    assert token["observations"][0]["coverage_basis_points"] == "UNKNOWN"
    assert token["observations"][0]["evidence_state"] == "unknown"


def test_marker_free_is_zero_coverage_not_zero_activity() -> None:
    contribution = build_coverage_contribution(
        "context-management-profile",
        {"context-lifecycle": (0, 12)},
        missing_ambiguous={"missing-marker": 12},
    )
    observation = contribution["observations"][0]
    assert observation["coverage_basis_points"] == 0
    assert observation["evidence_state"] == "partial"
    assert "value" not in observation
    assert "activity" not in observation


def test_aggregate_is_deterministic_and_contains_only_fixed_classes() -> None:
    contributions = _contributions()
    first = score_evidence_coverage(contributions, legacy_metrics=LEGACY_METRICS)
    second = score_evidence_coverage(
        list(reversed(contributions)), legacy_metrics=list(reversed(LEGACY_METRICS))
    )
    assert canonical_bytes(first) == canonical_bytes(second)
    load_validator("evidence_coverage_section.schema.json").validate(first)

    coverage = {item["input_class"]: item for item in first["coverage"]}
    assert coverage["git-session-linkage"] == {
        "input_class": "git-session-linkage",
        "basis": "binding-coverage-based-stand-in",
        "coverage_basis_points": 5000,
        "confidence": "MEDIUM",
        "evidence_state": "partial",
        "trust_tier": "PROVEN",
    }
    assert coverage["model"]["coverage_basis_points"] == 8000
    assert coverage["effort"]["coverage_basis_points"] == 4000
    assert coverage["context-lifecycle"]["coverage_basis_points"] == 0
    assert coverage["token-data"]["coverage_basis_points"] == "UNKNOWN"
    assert first["provenance_split"] == [
        {
            "provenance": "IMPORTED",
            "share_basis_points": 4286,
            "trust_tier": "PROVEN",
            "basis": "anchor-coverage-derived-provenance-split",
        },
        {
            "provenance": "LIVE",
            "share_basis_points": 5714,
            "trust_tier": "PROVEN",
            "basis": "anchor-coverage-derived-provenance-split",
        },
    ]
    assert first["missing_ambiguous"] == [
        {"category": "missing-effort", "count": 3},
        {"category": "missing-marker", "count": 5},
        {"category": "missing-model", "count": 1},
        {"category": "missing-token-data", "count": 5},
        {"category": "unknown-phase", "count": 2},
    ]


def test_provenance_and_binding_reuse_shipped_proven_values() -> None:
    from tests.scorer.test_score import fixed_report_bytes

    report = json.loads(fixed_report_bytes())
    metrics = {item["name"]: item for item in report["metrics"]}
    aggregate = score_evidence_coverage(_contributions(), legacy_metrics=report["metrics"])
    linkage = next(
        item for item in aggregate["coverage"] if item["input_class"] == "git-session-linkage"
    )
    assert linkage["coverage_basis_points"] == round(
        next(iter(metrics["binding_coverage"]["value"].values())) * 10000
    )
    split = {
        item["provenance"]: item["share_basis_points"] for item in aggregate["provenance_split"]
    }
    assert split == {
        name: round(value * 10000)
        for name, value in metrics["evidence_provenance_split"]["value"].items()
    }


def test_legacy_unknowns_never_become_zero_activity_or_invented_weighting() -> None:
    metrics = [
        {
            "name": "binding_coverage",
            "value": {"synthetic-a": 0.25, "synthetic-b": 0.75},
            "trust_tier": "PROVEN",
        },
        {
            "name": "evidence_provenance_split",
            "value": {"IMPORTED": 0.0, "LIVE": 0.0},
            "trust_tier": "PROVEN",
        },
    ]
    aggregate = score_evidence_coverage(_contributions(), legacy_metrics=metrics)
    linkage = aggregate["coverage"][0]
    assert linkage["coverage_basis_points"] == "UNKNOWN"
    assert linkage["evidence_state"] == "unknown"
    assert {item["share_basis_points"] for item in aggregate["provenance_split"]} == {"UNKNOWN"}


def test_closed_whitelists_reject_names_paths_ids_and_unknown_taxonomy() -> None:
    validator = load_validator("fingerprint_coverage_input.schema.json")
    contribution = _contributions()[1]
    for forbidden in (
        {"filename": "synthetic-private.py"},
        {"path": "/synthetic/private"},
        {"session_id": "synthetic-session-canary"},
    ):
        bad = copy.deepcopy(contribution)
        bad["missing_ambiguous"][0].update(forbidden)
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(bad)

    with pytest.raises(EvidenceCoverageError, match="pinned taxonomy"):
        build_coverage_contribution(
            "workflow-map",
            {},
            missing_ambiguous={"/synthetic/private/file.py": 1},
        )

    aggregate_validator = load_validator("evidence_coverage_section.schema.json")
    aggregate = score_evidence_coverage(_contributions(), legacy_metrics=LEGACY_METRICS)
    bad_aggregate = copy.deepcopy(aggregate)
    bad_aggregate["missing_ambiguous"][0]["session_id"] = "synthetic-session-canary"
    with pytest.raises(jsonschema.ValidationError):
        aggregate_validator.validate(bad_aggregate)
    encoded = canonical_bytes(aggregate)
    for forbidden_key in (b'"filename"', b'"path"', b'"session_id"', b'"timestamp"'):
        assert forbidden_key not in encoded

    assert set(AMBIGUITY_CATEGORIES) == {
        "missing-marker",
        "missing-pointer-target",
        "conflicting-evidence",
        "unsupported-harness-version",
        "unlinked-session",
        "unknown-phase",
        "missing-model",
        "missing-effort",
        "missing-token-data",
    }


def test_all_producers_and_honesty_labels_are_enforced() -> None:
    with pytest.raises(EvidenceCoverageError, match="every fingerprint"):
        score_evidence_coverage(_contributions()[:-1], legacy_metrics=LEGACY_METRICS)

    bad = copy.deepcopy(_contributions())
    bad[1]["observations"][0]["confidence"] = "LOW"
    with pytest.raises(EvidenceCoverageError, match="honesty labels"):
        score_evidence_coverage(bad, legacy_metrics=LEGACY_METRICS)


def test_raw_aggregate_cannot_masquerade_as_an_assembled_report_section() -> None:
    aggregate = score_evidence_coverage(_contributions(), legacy_metrics=LEGACY_METRICS)
    report = copy.deepcopy(REPORT_V2)
    assert report["fingerprint"]["evidence_coverage"] == {
        "status": "not-supported",
        "fields": [],
    }
    load_validator("report-v2.schema.json").validate(report)

    report["fingerprint"]["evidence_coverage"] = aggregate
    with pytest.raises(jsonschema.ValidationError):
        load_validator("report-v2.schema.json").validate(report)


def test_aggregate_leak_scan_is_clean_and_companion_canary_fires(tmp_path) -> None:
    fixtures = generate_fixtures(tmp_path / "fixtures")
    session_id_canary = b"MYBENCH-CANARY-session-id-13-8"
    canaries = [*fixtures.all_canaries(), session_id_canary]
    aggregate = score_evidence_coverage(_contributions(), legacy_metrics=LEGACY_METRICS)
    safe = tmp_path / "coverage.json"
    safe.write_bytes(canonical_bytes(aggregate) + b"\n")
    assert assert_no_canaries([safe], canaries) == 1

    planted = tmp_path / "planted.json"
    planted.write_bytes(canonical_bytes(aggregate) + session_id_canary)
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], canaries)
