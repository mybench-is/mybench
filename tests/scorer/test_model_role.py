"""MYB-13.5 model-role scorer privacy, coverage, and determinism tests."""

from __future__ import annotations

import base64
from copy import deepcopy

import pytest

from mybench.claims.canonical import canonical_bytes
from mybench.registry import Registry
from mybench.schemas import load_validator
from mybench.scorer import (
    EFFORT_SHARES_BAND_ID,
    EFFORT_SHARES_EXACT_ID,
    EVIDENCE_QUALITY_ID,
    MODEL_SHARES_BAND_ID,
    MODEL_SHARES_EXACT_ID,
    PROVIDER_SHARES_BAND_ID,
    PROVIDER_SHARES_EXACT_ID,
    ModelRoleScoringError,
    score_model_role_profile,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

CONTENT_CANARY = "MYBENCH-MODEL-ROLE-CONTENT-CANARY-76e1"
FILENAME_CANARY = "synthetic-private-model-role-file-a733.py"
SESSION_CANARY = "synthetic-private-model-role-session-b84d"


def _event(session: str, event_kind: str, **fields: object) -> dict[str, object]:
    return {
        "session_id": session,
        "event_kind": event_kind,
        "content": CONTENT_CANARY,
        "filename": FILENAME_CANARY,
        **fields,
    }


def _rich_fixture(count: int = 5) -> list[dict]:
    events = []
    for index in range(count):
        session = f"{SESSION_CANARY}-{index}"
        events.extend(
            [
                _event(
                    session,
                    "model",
                    authorship="agent-turn",
                    model="gpt-5-codex-private-suffix",
                    provider="openai",
                    reasoning_effort="high",
                ),
                _event(
                    session,
                    "reference",
                    authorship="agent-turn",
                    reference_kind="plan",
                ),
                _event(
                    session,
                    "tool-call",
                    authorship="agent-turn",
                    tool_family="edit",
                ),
                _event(session, "test", authorship="agent-turn"),
                _event(
                    session,
                    "tool-result",
                    authorship="pasted-content-span",
                    result_status="error",
                ),
                _event(
                    session,
                    "forge-action",
                    authorship="agent-turn",
                    forge_action_kind="pr-comment",
                ),
                _event(session, "future-structural-event", authorship="agent-turn"),
            ]
        )
    return events


def _cell_map(result: dict) -> dict[tuple[str, str, str], dict]:
    return {
        (cell["phase"], cell["input_class"], cell["value"]): cell
        for cell in result["local"]["distribution_cells"]
    }


def test_profile_is_schema_registry_valid_and_byte_deterministic() -> None:
    events = _rich_fixture()
    before = deepcopy(events)
    first = score_model_role_profile(events)
    second = score_model_role_profile(events)

    load_validator("model_role_profile.schema.json").validate(first)
    assert canonical_bytes(first) == canonical_bytes(second)
    assert events == before
    assert first["local"]["eligible_event_count"] == 30
    assert first["local"]["phase_counts"] == [
        {"phase": "debugging", "eligible_events": 5},
        {"phase": "implementation", "eligible_events": 10},
        {"phase": "planning", "eligible_events": 5},
        {"phase": "review", "eligible_events": 5},
        {"phase": "unknown", "eligible_events": 5},
    ]

    cells = _cell_map(first)
    assert cells[("planning", "model", "gpt-5-codex")]["share_basis_points"] == 10000
    assert cells[("implementation", "provider", "openai")]["evidence_quality"] == {
        "coverage_basis_points": 10000,
        "confidence": "HIGH",
        "evidence_state": "available",
    }
    assert cells[("implementation", "effort", "high")]["share_basis_points"] == 10000

    registry = Registry.load()
    all_outputs = {
        **first["local"]["registry_outputs"],
        **first["publishable"],
    }
    assert set(all_outputs) == {
        MODEL_SHARES_EXACT_ID,
        MODEL_SHARES_BAND_ID,
        PROVIDER_SHARES_EXACT_ID,
        PROVIDER_SHARES_BAND_ID,
        EFFORT_SHARES_EXACT_ID,
        EFFORT_SHARES_BAND_ID,
        EVIDENCE_QUALITY_ID,
    }
    for registry_id, output in all_outputs.items():
        entry = registry.entry(registry_id)
        registry.check_claim(
            {
                "registry_id": registry_id,
                "registry_version": entry["version"],
                "derivation_class": entry["class"],
                "output": output,
            }
        )


def test_missing_metadata_and_unknown_phase_are_explicit_never_imputed() -> None:
    events = [
        _event(
            f"{SESSION_CANARY}-unknown-{index}", "future-structural-event", authorship="agent-turn"
        )
        for index in range(5)
    ]
    result = score_model_role_profile(events)
    cells = _cell_map(result)
    for input_class in ("model", "provider", "effort"):
        cell = cells[("unknown", input_class, "UNKNOWN")]
        assert cell["share_basis_points"] == 10000
        assert cell["evidence_quality"] == {
            "coverage_basis_points": 0,
            "confidence": "LOW",
            "evidence_state": "partial",
        }

    assert result["publishable"][MODEL_SHARES_BAND_ID]["cells"] == [
        {"phase": "unknown", "model": "UNKNOWN", "share_band": "75-100%"}
    ]
    assert result["publishable"][PROVIDER_SHARES_BAND_ID]["cells"] == [
        {"phase": "unknown", "provider": "UNKNOWN", "share_band": "75-100%"}
    ]
    assert result["publishable"][EFFORT_SHARES_BAND_ID]["cells"] == [
        {"phase": "unknown", "effort": "UNKNOWN", "share_band": "75-100%"}
    ]
    quality = result["publishable"][EVIDENCE_QUALITY_ID]["cells"]
    assert all(cell["coverage_band"] == "0-9%" for cell in quality)
    assert all(cell["confidence"] == "LOW" for cell in quality)
    assert all(cell["evidence_state"] == "partial" for cell in quality)

    contribution = result["coverage_contribution"]
    assert [item["coverage_basis_points"] for item in contribution["observations"]] == [0, 0]
    assert contribution["missing_ambiguous"] == [
        {"category": "missing-effort", "count": 5},
        {"category": "missing-model", "count": 5},
    ]


def test_partial_carriers_preserve_only_observed_fields_and_vocabularies() -> None:
    events = []
    for index in range(5):
        session = f"{SESSION_CANARY}-partial-{index}"
        events.extend(
            [
                _event(
                    session,
                    "model",
                    authorship="agent-turn",
                    provider="openai",
                ),
                _event(
                    session,
                    "model",
                    authorship="agent-turn",
                    model="unrecognized-synthetic-model-family",
                    reasoning_effort="xhigh",
                ),
                _event(
                    session,
                    "reference",
                    authorship="agent-turn",
                    reference_kind="plan",
                ),
            ]
        )
    cells = _cell_map(score_model_role_profile(events))
    assert ("planning", "model", "other") in cells
    assert ("planning", "provider", "openai") in cells
    assert ("planning", "effort", "max") in cells
    assert all(
        cell["evidence_quality"]["coverage_basis_points"] == 10000 for cell in cells.values()
    )


def test_support_floor_suppresses_registry_atoms_but_not_local_unknowns() -> None:
    events = [
        _event(f"{SESSION_CANARY}-thin-{index}", "future-structural-event", authorship="agent-turn")
        for index in range(4)
    ]
    result = score_model_role_profile(events)
    assert len(result["local"]["distribution_cells"]) == 3
    assert result["local"]["registry_outputs"] == {}
    assert result["publishable"] == {}

    fired = score_model_role_profile(
        [
            *events,
            _event(f"{SESSION_CANARY}-thin-4", "future-structural-event", authorship="agent-turn"),
        ]
    )
    assert set(fired["publishable"]) == {
        MODEL_SHARES_BAND_ID,
        PROVIDER_SHARES_BAND_ID,
        EFFORT_SHARES_BAND_ID,
        EVIDENCE_QUALITY_ID,
    }


def test_provider_and_substrate_names_are_data_never_trust_copy() -> None:
    result = score_model_role_profile(_rich_fixture())
    trust_copy = result["trust_basis"].casefold()
    assert trust_copy == "signatures-commitments-and-timestamps-only"
    for operational_name in (
        "anthropic",
        "aws",
        "bedrock",
        "google",
        "vertex",
        "openai",
        "azure",
        "gpu",
        "cuda",
        "nitro",
        "sev",
    ):
        assert operational_name not in trust_copy
    assert result["provider_semantics"] == "operational-metadata-only"

    forbidden_phrases = (
        b"trusted by openai",
        b"openai-verified",
        b"openai trust anchor",
        b"aws trust anchor",
        b"gpu-backed trust",
    )
    encoded = canonical_bytes(result).lower()
    assert not any(phrase in encoded for phrase in forbidden_phrases)


def test_section_and_logs_are_canary_clean_and_scanner_fires(tmp_path, caplog) -> None:
    generated = generate_fixtures(tmp_path / "fixtures")
    events = _rich_fixture()
    for index, event in enumerate(events):
        event["private_content"] = generated.content_canaries[
            index % len(generated.content_canaries)
        ]
        event["private_filename"] = generated.filename_canaries[
            index % len(generated.filename_canaries)
        ]
        event["private_session_marker"] = generated.canary("worktree_name").decode()
    result = score_model_role_profile(events)
    section = tmp_path / "model-role.json"
    section.write_bytes(canonical_bytes(result) + b"\n")
    log = tmp_path / "model-role.log"
    log.write_text(caplog.text)
    assert assert_no_canaries([section, log], generated.all_canaries()) == 2

    raw = generated.canary("plan_content")
    encoded_variants = (raw, raw.hex().encode(), base64.b64encode(raw))
    for index, planted_value in enumerate(encoded_variants):
        planted = tmp_path / f"planted-{index}.json"
        planted.write_bytes(canonical_bytes(result) + planted_value)
        with pytest.raises(CanaryLeakError):
            assert_no_canaries([planted], generated.all_canaries())


def test_invalid_input_fails_with_content_safe_errors() -> None:
    with pytest.raises(ModelRoleScoringError, match="explicit sequence"):
        score_model_role_profile("private input")
    with pytest.raises(ModelRoleScoringError, match="wrong type"):
        score_model_role_profile(["private event"])
    with pytest.raises(ModelRoleScoringError, match="normalized session identity") as caught:
        score_model_role_profile([{"event_kind": "test", "content": CONTENT_CANARY}])
    assert CONTENT_CANARY not in str(caught.value)
    assert FILENAME_CANARY not in str(caught.value)
