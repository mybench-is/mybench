"""MYB-13.4 context-management scorer privacy, coverage, and determinism tests."""

from __future__ import annotations

import base64
from copy import deepcopy

import pytest
from jsonschema import ValidationError

from mybench.claims.canonical import canonical_bytes
from mybench.registry import Registry
from mybench.schemas import load_validator
from mybench.scorer import (
    AUTOMATIC_COMPACTIONS_ID,
    CLEAR_RATE_ID,
    FRESH_PHASE_SPLIT_ID,
    FRESH_SESSION_RATE_ID,
    GENERATIONS_PER_EPISODE_ID,
    MANUAL_COMPACTIONS_ID,
    MODEL_CHANGE_BOUNDARY_RATE_ID,
    ONE_CONTEXT_EPISODE_RATE_ID,
    RESUME_RATE_ID,
    ContextManagementScoringError,
    score_context_management,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

CONTENT_CANARY = "MYBENCH-CONTEXT-CONTENT-CANARY-6c21"
FILENAME_CANARY = "synthetic-private-context-file-138d.py"
SESSION_CANARY = "synthetic-private-context-session-774a"


def _episode(index: int) -> dict[str, str]:
    return {"task_episode_id": f"ep-{index:032x}"}


def _session(index: int, episode: dict[str, str]) -> dict[str, str]:
    return {
        "source": "claude-code",
        "session_id": f"{SESSION_CANARY}-{index}",
        "task_episode_id": episode["task_episode_id"],
    }


def _normalized(
    session: dict[str, str], record_index: int, event_kind: str, **fields: object
) -> dict[str, object]:
    return {
        "source": session["source"],
        "session_id": session["session_id"],
        "task_episode_id": session["task_episode_id"],
        "record_index": record_index,
        "subevent_index": 0,
        "event_kind": event_kind,
        "authorship": fields.pop("authorship", "agent-turn"),
        "private_content": CONTENT_CANARY,
        "private_filename": FILENAME_CANARY,
        **fields,
    }


def _lifecycle(
    index: int,
    session: dict[str, str],
    event_kind: str,
    trigger: str,
    generation: int,
) -> dict[str, object]:
    return {
        "schema_version": "2",
        "type": "event",
        "i": index,
        "harness": session["source"],
        "session_id": session["session_id"],
        "event_kind": event_kind,
        "trigger": trigger,
        "context_gen": generation,
        "private_content": CONTENT_CANARY,
        "private_filename": FILENAME_CANARY,
    }


def rich_fixture(count: int = 5) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    episodes = [_episode(index) for index in range(count)]
    sessions = [_session(index, episode) for index, episode in enumerate(episodes)]
    events: list[dict] = []
    lifecycle: list[dict] = []
    row_index = 0
    for index, session in enumerate(sessions):
        before = "synthetic-model-a"
        after = "synthetic-model-b" if index < 3 else before
        events.extend(
            [
                _normalized(session, 0, "model", model=before),
                _normalized(
                    session,
                    1,
                    "lifecycle",
                    lifecycle_marker="context-boundary",
                    context_generation_id=1,
                ),
                _normalized(session, 2, "model", model=after),
                (
                    _normalized(session, 3, "reference", reference_kind="plan")
                    if index < 3
                    else _normalized(session, 3, "tool-call", tool_family="edit")
                ),
            ]
        )
        lifecycle.extend(
            [
                _lifecycle(row_index, session, "session_start", "startup", 0),
                _lifecycle(
                    row_index + 1,
                    session,
                    "compact_pre",
                    "manual" if index < 3 else "auto",
                    1,
                ),
            ]
        )
        row_index += 2
        if index < 3:
            lifecycle.append(_lifecycle(row_index, session, "model_change", "unknown", 1))
            row_index += 1
    return events, sessions, episodes, lifecycle


def mixed_marker_fixture() -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    events, sessions, episodes, lifecycle = rich_fixture()
    marker_free_episodes = [_episode(index) for index in range(5, 10)]
    marker_free_sessions = [
        _session(index, episode)
        for index, episode in enumerate(marker_free_episodes, start=5)
    ]
    events.extend(
        _normalized(session, 0, "turn", authorship="human-turn")
        for session in marker_free_sessions
    )
    return (
        events,
        [*sessions, *marker_free_sessions],
        [*episodes, *marker_free_episodes],
        lifecycle,
    )


def score_fixture(
    events: list[dict], sessions: list[dict], episodes: list[dict], lifecycle: list[dict]
) -> dict:
    return score_context_management(
        events,
        sessions=sessions,
        episodes=episodes,
        lifecycle_events=lifecycle,
        episode_stitcher_version="2.0.0",
    )


def test_all_roadmap_fields_are_schema_registry_valid_and_deterministic():
    events, sessions, episodes, lifecycle = rich_fixture()
    before = deepcopy((events, sessions, episodes, lifecycle))
    first = score_fixture(events, sessions, episodes, lifecycle)
    second = score_fixture(events, sessions, episodes, lifecycle)

    load_validator("context_management_profile.schema.json").validate(first)
    assert canonical_bytes(first) == canonical_bytes(second)
    assert (events, sessions, episodes, lifecycle) == before

    local = first["local"]
    assert local["fresh_session_rate"] == {
        "value": 10000,
        "coverage_basis_points": 10000,
        "confidence": "HIGH",
    }
    assert local["resume_rate"]["value"] == 0
    assert local["clear_rate"]["value"] == 0
    assert local["manual_compactions"]["value"] == 3
    assert local["automatic_compactions"]["value"] == 2
    assert local["generations_per_episode"]["value"] == [
        {"generation_count_band": "1-4", "episode_count": 5}
    ]
    assert local["one_context_episode_rate"]["value"] == 0
    assert local["fresh_phase_split"]["value"] == [
        {"phase_group": "IMPLEMENTATION", "basis_points": 4000},
        {"phase_group": "PLAN", "basis_points": 6000},
        {"phase_group": "UNKNOWN", "basis_points": 0},
    ]
    assert local["model_change_boundary_rate"]["value"] == 6000

    public = first["publishable"]
    assert set(public) == {
        AUTOMATIC_COMPACTIONS_ID,
        CLEAR_RATE_ID,
        FRESH_PHASE_SPLIT_ID,
        FRESH_SESSION_RATE_ID,
        GENERATIONS_PER_EPISODE_ID,
        MANUAL_COMPACTIONS_ID,
        MODEL_CHANGE_BOUNDARY_RATE_ID,
        ONE_CONTEXT_EPISODE_RATE_ID,
        RESUME_RATE_ID,
    }
    assert public[FRESH_SESSION_RATE_ID]["rate_band"] == "75-100%"
    assert public[RESUME_RATE_ID]["rate_band"] == "0-9%"
    assert public[MANUAL_COMPACTIONS_ID]["count_band"] == "1-4"
    assert public[AUTOMATIC_COMPACTIONS_ID]["count_band"] == "1-4"
    assert public[MODEL_CHANGE_BOUNDARY_RATE_ID]["rate_band"] == "50-74%"

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


def test_marker_free_corpus_is_unknown_with_zero_coverage_never_zero_activity():
    episodes = [_episode(index) for index in range(5)]
    sessions = [_session(index, episode) for index, episode in enumerate(episodes)]
    events = [_normalized(session, 0, "turn", authorship="human-turn") for session in sessions]
    result = score_fixture(events, sessions, episodes, [])

    assert result["publishable"] == {}
    for field in result["local"].values():
        assert field["value"] == "UNKNOWN"
        assert field["coverage_basis_points"] in {0, "UNKNOWN"}
        assert field["confidence"] in {"LOW", "UNKNOWN"}
    assert result["coverage_contribution"] == {
        "schema_version": "1",
        "producer": "context-management-profile",
        "observations": [
            {
                "input_class": "context-lifecycle",
                "basis": "reliable-lifecycle-marker-per-eligible-session",
                "coverage_basis_points": 0,
                "confidence": "LOW",
                "evidence_state": "partial",
            }
        ],
        "missing_ambiguous": [{"category": "missing-marker", "count": 5}],
    }


def test_mixed_marker_corpus_is_byte_deterministic_and_excludes_missing_observations():
    events, sessions, episodes, lifecycle = mixed_marker_fixture()
    first = score_fixture(events, sessions, episodes, lifecycle)
    second = score_fixture(events, sessions, episodes, lifecycle)

    assert canonical_bytes(first) == canonical_bytes(second)
    result = first

    assert result["local"]["fresh_session_rate"] == {
        "value": 10000,
        "coverage_basis_points": 5000,
        "confidence": "MEDIUM",
    }
    assert result["local"]["one_context_episode_rate"] == {
        "value": 0,
        "coverage_basis_points": 5000,
        "confidence": "MEDIUM",
    }
    observation = result["coverage_contribution"]["observations"][0]
    assert observation["coverage_basis_points"] == 5000
    assert result["coverage_contribution"]["missing_ambiguous"] == [
        {"category": "missing-marker", "count": 5}
    ]


def test_historical_boundaries_raise_only_the_fields_they_support():
    events, sessions, episodes, _lifecycle = rich_fixture()
    historical = score_fixture(events, sessions, episodes, [])

    assert historical["coverage_contribution"]["observations"][0]["coverage_basis_points"] == 10000
    assert historical["local"]["fresh_session_rate"] == {
        "value": "UNKNOWN",
        "coverage_basis_points": 0,
        "confidence": "LOW",
    }
    assert historical["local"]["manual_compactions"] == {
        "value": "UNKNOWN",
        "coverage_basis_points": 0,
        "confidence": "LOW",
    }
    assert historical["local"]["generations_per_episode"] == {
        "value": [{"generation_count_band": "1-4", "episode_count": 5}],
        "coverage_basis_points": 10000,
        "confidence": "HIGH",
    }
    assert set(historical["publishable"]) == {
        GENERATIONS_PER_EPISODE_ID,
        MODEL_CHANGE_BOUNDARY_RATE_ID,
        ONE_CONTEXT_EPISODE_RATE_ID,
    }


def test_partial_compaction_classification_is_unknown_not_a_lower_bound():
    events, sessions, episodes, lifecycle = rich_fixture()
    target = next(row for row in lifecycle if row["event_kind"] == "compact_pre")
    target["trigger"] = "unknown"
    result = score_fixture(events, sessions, episodes, lifecycle)

    assert result["local"]["manual_compactions"] == {
        "value": "UNKNOWN",
        "coverage_basis_points": 8000,
        "confidence": "HIGH",
    }
    assert result["local"]["automatic_compactions"]["value"] == "UNKNOWN"
    assert MANUAL_COMPACTIONS_ID not in result["publishable"]
    assert AUTOMATIC_COMPACTIONS_ID not in result["publishable"]


def test_compaction_without_normalized_boundary_join_is_unknown_and_unpublished():
    events, sessions, episodes, lifecycle = rich_fixture()
    removed_session = sessions[0]
    events = [
        event
        for event in events
        if not (
            event["source"] == removed_session["source"]
            and event["session_id"] == removed_session["session_id"]
            and event.get("lifecycle_marker") == "context-boundary"
            and event.get("context_generation_id") == 1
        )
    ]

    result = score_fixture(events, sessions, episodes, lifecycle)

    for field in ("manual_compactions", "automatic_compactions"):
        assert result["local"][field] == {
            "value": "UNKNOWN",
            "coverage_basis_points": "UNKNOWN",
            "confidence": "UNKNOWN",
        }
    assert MANUAL_COMPACTIONS_ID not in result["publishable"]
    assert AUTOMATIC_COMPACTIONS_ID not in result["publishable"]


def test_output_schema_excludes_identifiers_ordered_sequences_and_private_strings():
    events, sessions, episodes, lifecycle = rich_fixture()
    result = score_fixture(events, sessions, episodes, lifecycle)
    encoded = canonical_bytes(result)
    for canary in (CONTENT_CANARY, FILENAME_CANARY, SESSION_CANARY, "synthetic-model-a"):
        value = canary.encode()
        assert value not in encoded
        assert value.hex().encode() not in encoded
        assert base64.b64encode(value) not in encoded
    for forbidden in (b"session_id", b"task_episode_id", b"boundary_position", b"event_sequence"):
        assert forbidden not in encoded

    planted = deepcopy(result)
    planted["publishable"][FRESH_SESSION_RATE_ID]["session_sequence"] = ["fresh"]
    with pytest.raises(ValidationError):
        load_validator("context_management_profile.schema.json").validate(planted)


def test_section_and_logs_are_canary_clean_and_scanner_fires(tmp_path, caplog):
    generated = generate_fixtures(tmp_path / "fixtures")
    events, sessions, episodes, lifecycle = rich_fixture()
    for index, event in enumerate(events):
        event["private_content"] = generated.content_canaries[
            index % len(generated.content_canaries)
        ]
        event["private_filename"] = generated.filename_canaries[
            index % len(generated.filename_canaries)
        ]
    result = score_fixture(events, sessions, episodes, lifecycle)
    section = tmp_path / "context-profile.json"
    section.write_bytes(canonical_bytes(result) + b"\n")
    log = tmp_path / "context-profile.log"
    log.write_text(caplog.text)
    assert assert_no_canaries([section, log], generated.all_canaries()) == 2

    planted = tmp_path / "planted.json"
    planted.write_bytes(canonical_bytes(result) + generated.canary("plan_content"))
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], generated.all_canaries())


def test_closed_inputs_refuse_undeclared_identities_and_conflicting_ordinals():
    events, sessions, episodes, lifecycle = rich_fixture()
    with pytest.raises(ContextManagementScoringError, match="undeclared episode"):
        bad_sessions = deepcopy(sessions)
        bad_sessions[0]["task_episode_id"] = "ep-" + "f" * 32
        score_fixture(events, bad_sessions, episodes, lifecycle)
    with pytest.raises(ContextManagementScoringError, match="ordinals must be unique"):
        score_fixture([events[0], deepcopy(events[0])], sessions, episodes, lifecycle)
    with pytest.raises(ContextManagementScoringError, match="closed projection"):
        bad_lifecycle = deepcopy(lifecycle)
        bad_lifecycle[0]["trigger"] = "guessed"
        score_fixture(events, sessions, episodes, bad_lifecycle)
    with pytest.raises(ContextManagementScoringError, match="stitcher version"):
        score_context_management(
            events,
            sessions=sessions,
            episodes=episodes,
            lifecycle_events=lifecycle,
            episode_stitcher_version="1.0.0",
        )
