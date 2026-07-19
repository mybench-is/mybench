"""MYB-6.8 private orchestration distributions; synthetic evidence only."""

from __future__ import annotations

import base64
import json
from copy import deepcopy

import pytest
from jsonschema import ValidationError

from mybench.claims import canonical_bytes
from mybench.registry import Registry, _packaged_registry_bytes
from mybench.schemas import load_validator
from mybench.scorer import (
    DELEGATION_DEPTH_DISTRIBUTION_ID,
    DELEGATION_REGISTRY_IDS,
    FAN_OUT_DISTRIBUTION_ID,
    PEAK_PARALLEL_LANES_DISTRIBUTION_ID,
    SPAWNING_SESSION_RATE_ID,
    DelegationScoringError,
    score_orchestration_delegation,
)
from tests.fixtures import (
    CanaryLeakError,
    assert_no_canaries,
    generate_fixtures,
    synthetic_delegation_input,
)


def _score(**fixture_options: bool) -> tuple[dict, object]:
    fixture = synthetic_delegation_input(**fixture_options)
    result = score_orchestration_delegation(fixture.corpus)
    assert result is not None
    return result, fixture


def test_four_private_distributions_are_exact_schema_registry_and_deterministic():
    fixture = synthetic_delegation_input()
    before = deepcopy(fixture.corpus)
    first = score_orchestration_delegation(fixture.corpus)
    second = score_orchestration_delegation(fixture.corpus)
    assert first is not None and second is not None
    assert fixture.corpus == before
    assert canonical_bytes(first) == canonical_bytes(second)
    load_validator("orchestration_delegation.schema.json").validate(first)
    assert tuple(first["fields"]) == DELEGATION_REGISTRY_IDS

    fields = first["fields"]
    assert fields[SPAWNING_SESSION_RATE_ID] == {
        "lineage_coverage_basis_points": 10000,
        "eligible_sessions": 7,
        "unknown_sessions": 0,
        "spawning_sessions": 3,
        "rate_basis_points": 4286,
        "trust_tier": "ANCHORED",
        "caveats": ["lineage-marker-coverage-dependent"],
    }
    assert fields[DELEGATION_DEPTH_DISTRIBUTION_ID] == {
        "lineage_coverage_basis_points": 10000,
        "eligible_sessions": 7,
        "unknown_sessions": 0,
        "depth_0_sessions": 3,
        "depth_1_sessions": 3,
        "depth_2_sessions": 1,
        "trust_tier": "ANCHORED",
        "caveats": ["lineage-marker-coverage-dependent"],
    }
    assert fields[FAN_OUT_DISTRIBUTION_ID] == {
        "lineage_coverage_basis_points": 10000,
        "eligible_sessions": 7,
        "unknown_sessions": 0,
        "fan_out_0_sessions": 4,
        "fan_out_1_sessions": 2,
        "fan_out_2_sessions": 1,
        "trust_tier": "ANCHORED",
        "caveats": ["lineage-marker-coverage-dependent"],
    }
    assert fields[PEAK_PARALLEL_LANES_DISTRIBUTION_ID] == {
        "lineage_coverage_basis_points": 10000,
        "interval_coverage_basis_points": 10000,
        "eligible_graphs": 3,
        "unknown_graphs": 0,
        "peak_1_graphs": 1,
        "peak_2_graphs": 1,
        "peak_4_graphs": 1,
        "trust_tier": "ANCHORED",
        "caveats": [
            "lineage-marker-coverage-dependent",
            "observed-activity-envelope-not-execution",
        ],
    }

    registry = Registry.load()
    for registry_id, output in fields.items():
        entry = registry.entry(registry_id)
        registry.check_claim(
            {
                "registry_id": registry_id,
                "registry_version": entry["version"],
                "derivation_class": entry["class"],
                "output": output,
            }
        )
        report_value = [
            {"dimensions": [name], "value": value}
            for name, value in sorted(output.items())
            if name not in {"trust_tier", "caveats"}
        ]
        assert (
            registry.check_report_field(
                {
                    "registry_id": registry_id,
                    "registry_version": entry["version"],
                    "claim_digest": "a" * 64,
                    "derivation_class": entry["class"],
                    "execution_env": "local-unattested",
                    "trust_tier": "ANCHORED",
                    "anchor_state": "covered",
                    "disclosure": "LOCAL_ONLY",
                    "inference_risk": "R1",
                    "coverage_basis_points": output.get(
                        "interval_coverage_basis_points",
                        output["lineage_coverage_basis_points"],
                    ),
                    "confidence": "HIGH",
                    "value": report_value,
                    "caveats": output["caveats"],
                },
                "fingerprint.orchestration_topology",
            )["id"]
            == registry_id
        )


def test_unknown_lineage_and_interval_evidence_reduce_coverage_without_guessing():
    result, _fixture = _score(include_unknown_lane=True, include_untimed_root=True)
    fields = result["fields"]
    spawn = fields[SPAWNING_SESSION_RATE_ID]
    assert spawn["eligible_sessions"] == 8
    assert spawn["unknown_sessions"] == 1
    assert spawn["lineage_coverage_basis_points"] == 8889
    assert spawn["spawning_sessions"] == 3
    assert spawn["rate_basis_points"] == 3750

    peak = fields[PEAK_PARALLEL_LANES_DISTRIBUTION_ID]
    assert peak["eligible_graphs"] == 3
    assert peak["unknown_graphs"] == 1
    assert peak["interval_coverage_basis_points"] == 7500
    assert peak["peak_1_graphs"] == 1


def test_peak_distribution_is_absent_below_its_five_session_support_floor():
    result, _fixture = _score(below_peak_support=True)
    assert set(result["fields"]) == {
        DELEGATION_DEPTH_DISTRIBUTION_ID,
        FAN_OUT_DISTRIBUTION_ID,
        SPAWNING_SESSION_RATE_ID,
    }
    load_validator("orchestration_delegation.schema.json").validate(result)


def test_schema_excludes_ids_paths_names_timestamps_shapes_and_ordered_sequences():
    result, fixture = _score()
    encoded = canonical_bytes(result)
    for canary in fixture.canaries:
        assert canary not in encoded
        assert canary.hex().encode() not in encoded
        assert base64.b64encode(canary) not in encoded
    for forbidden in (
        b"session_id",
        b"parent_session_id",
        b"task_episode_id",
        b"path",
        b"filename",
        b"observed_at",
        b"timestamp",
        b"graph_shape",
        b"sequence",
        b"topology_gallery",
    ):
        assert forbidden not in encoded

    planted = deepcopy(result)
    planted["fields"][SPAWNING_SESSION_RATE_ID]["session_ids"] = ["synthetic-private-id"]
    with pytest.raises(ValidationError):
        load_validator("orchestration_delegation.schema.json").validate(planted)


def test_whole_artifact_leak_scan_and_planted_firing(tmp_path, caplog):
    generated = generate_fixtures(tmp_path / "fixtures")
    result, fixture = _score()
    artifact = tmp_path / "delegation.json"
    artifact.write_bytes(canonical_bytes(result) + b"\n")
    log = tmp_path / "delegation.log"
    log.write_text(caplog.text)
    canaries = [*generated.all_canaries(), *fixture.canaries]
    assert assert_no_canaries([artifact, log], canaries) == 2

    planted = tmp_path / "planted.json"
    planted.write_bytes(canonical_bytes(result) + generated.canary("plan_content"))
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], canaries)


def test_registry_contract_refuses_public_activation_or_weakened_support():
    document = json.loads(_packaged_registry_bytes())
    entry = next(item for item in document["entries"] if item["id"] == SPAWNING_SESSION_RATE_ID)
    entry["disclosure"] = "public"
    entry["presets"] = ["full"]
    fixture = synthetic_delegation_input()
    with pytest.raises(DelegationScoringError, match="registry contract"):
        score_orchestration_delegation(fixture.corpus, registry=Registry(document))

    document = json.loads(_packaged_registry_bytes())
    entry = next(item for item in document["entries"] if item["id"] == SPAWNING_SESSION_RATE_ID)
    entry["min_support"] = {"sessions": 5}
    with pytest.raises(DelegationScoringError, match="registry contract"):
        score_orchestration_delegation(fixture.corpus, registry=Registry(document))


def test_invalid_corpus_fails_with_content_free_diagnostic():
    fixture = synthetic_delegation_input()
    broken = deepcopy(fixture.corpus)
    broken["manifest"]["sessions"][0]["private_path"] = "/synthetic/private/do-not-echo-this-path"
    with pytest.raises(DelegationScoringError, match="normalized corpus validation failed") as exc:
        score_orchestration_delegation(broken)
    assert "do-not-echo" not in str(exc.value)
