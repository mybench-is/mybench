"""MYB-13.3 workflow-map scorer privacy, support, and determinism tests."""

from __future__ import annotations

import base64
import json
from copy import deepcopy

import pytest
from jsonschema import ValidationError

from mybench.claims.canonical import canonical_bytes
from mybench.registry import Registry, _packaged_registry_bytes
from mybench.schemas import load_validator
from mybench.scorer import (
    AUTHORSHIP_SHARES_ID,
    CONTEXT_BOUNDARY_RATE_ID,
    MODEL_ROUTING_ID,
    RECURRING_SEQUENCES_ID,
    REWORK_LOOP_RATE_ID,
    TASK_EPISODE_TOTAL_ID,
    TRANSITION_SHARES_ID,
    UNKNOWN_PHASE_SHARE_ID,
    WorkflowMapScoringError,
    score_workflow_map,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

CONTENT_CANARY = "MYBENCH-WORKFLOW-CONTENT-CANARY-74de"
FILENAME_CANARY = "synthetic-private-workflow-file-1d0a.py"
SESSION_CANARY = "synthetic-private-workflow-session-882c"


def _episode(index: int) -> dict[str, str]:
    return {"task_episode_id": f"ep-{index:032x}"}


def _event(episode: dict[str, str], event_kind: str, **fields: object) -> dict[str, object]:
    return {
        "task_episode_id": episode["task_episode_id"],
        "session_id": fields.pop("session_id", SESSION_CANARY),
        "event_kind": event_kind,
        "content": CONTENT_CANARY,
        "filename": FILENAME_CANARY,
        **fields,
    }


def _rich_fixture(count: int = 5) -> tuple[list[dict], list[dict]]:
    episodes = [_episode(index) for index in range(count)]
    events: list[dict] = []
    for index, episode in enumerate(episodes):
        session = f"{SESSION_CANARY}-{index}"
        events.extend(
            [
                _event(
                    episode,
                    "model",
                    session_id=session,
                    authorship="agent-turn",
                    model="gpt-5-codex-private-suffix",
                ),
                _event(
                    episode,
                    "turn",
                    session_id=session,
                    authorship="human-turn",
                ),
                _event(
                    episode,
                    "reference",
                    session_id=session,
                    authorship="agent-turn",
                    reference_kind="plan",
                ),
                _event(
                    episode,
                    "tool-call",
                    session_id=session,
                    authorship="agent-turn",
                    tool_family="edit",
                ),
                _event(
                    episode,
                    "lifecycle",
                    session_id=session,
                    authorship="agent-turn",
                    lifecycle_marker="context-boundary",
                    context_generation_id=1,
                ),
                _event(
                    episode,
                    "test",
                    session_id=session,
                    authorship="agent-turn",
                ),
            ]
        )
    return events, episodes


def _score(events: list[dict], episodes: list[dict]) -> dict:
    result = score_workflow_map(
        events,
        episodes=episodes,
        episode_stitcher_version="2.0.0",
    )
    assert result is not None
    return result


def test_section_is_schema_and_registry_valid_and_byte_deterministic():
    events, episodes = _rich_fixture()
    before = deepcopy((events, episodes))
    first = _score(events, episodes)
    second = _score(events, episodes)

    load_validator("workflow_map.schema.json").validate(first)
    assert canonical_bytes(first) == canonical_bytes(second)
    assert (events, episodes) == before

    local = first["local"]
    assert local["task_episode_total"] == 5
    assert local["transition_counts"] == [
        {"from_phase": "PLAN", "to_phase": "BUILD", "count": 5},
        {"from_phase": "TASK", "to_phase": "PLAN", "count": 5},
    ]
    assert local["context_boundary_rate_basis_points"] == 3333
    assert local["unknown_phase_share_basis_points"] == 3333
    assert local["graph_coverage_basis_points"] == 6667

    public = first["publishable"]
    assert public[TASK_EPISODE_TOTAL_ID]["task_episode_total"] == 5
    assert public[CONTEXT_BOUNDARY_RATE_ID]["rate_band"] == "25-49%"
    assert public[UNKNOWN_PHASE_SHARE_ID] == {
        "unknown_phase_share": "25-49%",
        "graph_confidence": "MEDIUM",
        "classifier_version": "1.0.0",
        "trust_tier": "ANCHORED",
    }
    assert public[REWORK_LOOP_RATE_ID]["rate_band"] == "0-9%"
    assert all(cell["share_band"] == "75-100%" for cell in public[TRANSITION_SHARES_ID]["cells"])
    assert all(cell["share_band"] == "75-100%" for cell in public[AUTHORSHIP_SHARES_ID]["cells"])
    assert {cell["model"] for cell in public[MODEL_ROUTING_ID]["cells"]} == {"gpt-5-codex"}

    registry = Registry.load()
    for registry_id, output in public.items():
        entry = registry.entry(registry_id)
        registry.check_claim(
            {
                "registry_id": registry_id,
                "registry_version": entry["version"],
                "derivation_class": entry["class"],
                "output": output,
            }
        )


def test_publishable_schema_rejects_ordered_per_episode_or_identifier_fields():
    events, episodes = _rich_fixture()
    result = _score(events, episodes)
    encoded = canonical_bytes(result)
    for canary in (CONTENT_CANARY, FILENAME_CANARY, SESSION_CANARY):
        value = canary.encode()
        assert value not in encoded
        assert value.hex().encode() not in encoded
        assert base64.b64encode(value) not in encoded
    assert b"session_id" not in encoded
    assert b"task_episode_id" not in encoded
    assert b"event_sequence" not in encoded
    assert b"episode_sequence" not in encoded

    planted = deepcopy(result)
    planted["publishable"][TASK_EPISODE_TOTAL_ID]["session_sequences"] = [["TASK", "PLAN"]]
    with pytest.raises(ValidationError):
        load_validator("workflow_map.schema.json").validate(planted)


def test_recurring_sequence_requires_five_distinct_episodes_and_fires_at_five():
    episodes = [_episode(index) for index in range(9)]
    events: list[dict] = []
    for index, episode in enumerate(episodes):
        sequence = (
            [
                ("reference", {"authorship": "agent-turn", "reference_kind": "plan"}),
                ("tool-call", {"authorship": "agent-turn", "tool_family": "edit"}),
            ]
            if index < 5
            else [
                ("test", {"authorship": "agent-turn"}),
                (
                    "forge-action",
                    {"authorship": "agent-turn", "forge_action_kind": "pr-comment"},
                ),
            ]
        )
        events.extend(_event(episode, kind, **fields) for kind, fields in sequence)

    result = _score(events, episodes)
    recurring = result["publishable"][RECURRING_SEQUENCES_ID]["sequences"]
    assert recurring == [{"sequence": ["PLAN", "BUILD"], "share_band": "50-74%"}]
    assert result["local"]["recurring_sequences"] == [
        {
            "sequence": ["PLAN", "BUILD"],
            "supporting_episodes": 5,
            "eligible_episodes": 9,
        }
    ]
    assert ["TEST", "REVIEW"] not in [item["sequence"] for item in recurring]
    transition_cells = result["publishable"][TRANSITION_SHARES_ID]["cells"]
    assert not any(
        cell["from_phase"] == "TEST" and cell["to_phase"] == "REVIEW" for cell in transition_cells
    )


def test_structural_rework_loop_is_neutral_aggregate_not_an_ordered_stream():
    episodes = [_episode(index) for index in range(5)]
    events: list[dict] = []
    for episode in episodes:
        events.extend(
            [
                _event(episode, "reference", authorship="agent-turn", reference_kind="plan"),
                _event(episode, "tool-call", authorship="agent-turn", tool_family="edit"),
                _event(episode, "test", authorship="agent-turn"),
                _event(episode, "tool-call", authorship="agent-turn", tool_family="write"),
            ]
        )
    result = _score(events, episodes)
    assert result["local"]["rework_loop_rate_basis_points"] == 10000
    assert result["publishable"][REWORK_LOOP_RATE_ID]["rate_band"] == "75-100%"


def test_episode_total_uses_explicit_normalized_identity_and_unknown_dilutes_confidence():
    events, episodes = _rich_fixture()
    assert _score(events, episodes)["local"]["task_episode_total"] == 5
    assert (
        score_workflow_map(
            events[:24],
            episodes=episodes[:4],
            episode_stitcher_version="2.0.0",
        )
        is None
    )

    duplicate = [*episodes, episodes[0]]
    with pytest.raises(WorkflowMapScoringError, match="must be unique"):
        _score(events, duplicate)
    invalid = deepcopy(episodes)
    invalid[0]["task_episode_id"] = "private-episode-name"
    with pytest.raises(WorkflowMapScoringError, match="normalized schema"):
        _score(events, invalid)
    with pytest.raises(WorkflowMapScoringError, match="lacks a declared episode identity"):
        _score([{**events[0], "task_episode_id": "ep-" + "f" * 32}], episodes)
    with pytest.raises(WorkflowMapScoringError, match="stitcher version"):
        score_workflow_map(events, episodes=episodes, episode_stitcher_version="1.0.0")

    all_unknown = [
        _event(episode, "future-structural-event", authorship="agent-turn") for episode in episodes
    ]
    unknown_result = _score(all_unknown, episodes)
    assert unknown_result["publishable"][UNKNOWN_PHASE_SHARE_ID] == {
        "unknown_phase_share": "75-100%",
        "graph_confidence": "LOW",
        "classifier_version": "1.0.0",
        "trust_tier": "ANCHORED",
    }
    assert TRANSITION_SHARES_ID not in unknown_result["publishable"]
    assert RECURRING_SEQUENCES_ID not in unknown_result["publishable"]


def test_section_and_log_lines_are_canary_clean_and_scanner_fires(tmp_path, caplog):
    generated = generate_fixtures(tmp_path / "fixtures")
    events, episodes = _rich_fixture()
    for index, event in enumerate(events):
        event["private_content"] = generated.content_canaries[
            index % len(generated.content_canaries)
        ]
        event["private_filename"] = generated.filename_canaries[
            index % len(generated.filename_canaries)
        ]
    result = _score(events, episodes)
    section = tmp_path / "workflow-map.json"
    section.write_bytes(canonical_bytes(result) + b"\n")
    log = tmp_path / "workflow-map.log"
    log.write_text(caplog.text)
    assert assert_no_canaries([section, log], generated.all_canaries()) == 2

    planted = tmp_path / "planted.json"
    planted.write_bytes(canonical_bytes(result) + generated.canary("plan_content"))
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], generated.all_canaries())


def test_registry_contract_refuses_lowered_k_floor():
    document = json.loads(_packaged_registry_bytes())
    entry = next(item for item in document["entries"] if item["id"] == RECURRING_SEQUENCES_ID)
    entry["output_schema"]["properties"]["k_suppression_floor"]["const"] = 4
    events, episodes = _rich_fixture()
    with pytest.raises(WorkflowMapScoringError, match="k-suppression"):
        score_workflow_map(
            events,
            episodes=episodes,
            episode_stitcher_version="2.0.0",
            registry=Registry(document),
        )
