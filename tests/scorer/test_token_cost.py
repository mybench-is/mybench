"""MYB-13.6 deterministic token/cost profile; synthetic evidence only."""

from __future__ import annotations

import base64
import json
import os
import socket
import time
from copy import deepcopy

import pytest
from jsonschema import ValidationError

from mybench.claims.canonical import canonical_bytes
from mybench.registry import Registry
from mybench.schemas import load_validator
from mybench.scorer import (
    ABANDONED_TOKEN_SHARE_ID,
    COST_BY_MODEL_ID,
    COST_PER_EPISODE_ID,
    PLANNING_RATIO_ID,
    REWORK_TOKEN_SHARE_ID,
    TOKENS_BY_MODEL_ID,
    TOKENS_BY_PHASE_ID,
    PricingSnapshotError,
    load_pricing_snapshot,
    score_token_cost_profile,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

SESSION_CANARY = "synthetic-private-token-session-canary-13-6"
CONTENT_CANARY = "MYBENCH-TOKEN-CONTENT-CANARY-13-6"
FILENAME_CANARY = "synthetic-private-token-file-13-6.py"


def _corpus(count: int = 5) -> tuple[list[dict], list[dict], list[dict]]:
    events: list[dict] = []
    episodes: list[dict] = []
    sessions: list[dict] = []
    for index in range(count):
        episode_id = f"ep-{index:032x}"
        session_id = f"{SESSION_CANARY}-{index}"
        episodes.append(
            {
                "task_episode_id": episode_id,
                "episode_outcome": (
                    "abandoned" if index == 0 else "closed-with-bound-commit"
                ),
                "outcome_classifier_version": "1.0.0",
            }
        )
        sessions.append({"session_id": session_id, "task_episode_id": episode_id})
        base = {
            "session_id": session_id,
            "task_episode_id": episode_id,
            "authorship": "agent-turn",
            "content": CONTENT_CANARY,
            "filename": FILENAME_CANARY,
        }

        def usage(minute: int) -> dict:
            return {
                **base,
                "event_kind": "token-usage",
                "observed_at": f"2026-07-19T00:{minute:02d}:00.000000Z",
                "token_usage": {
                    "input_tokens": 100_000,
                    "output_tokens": 10_000,
                    "cache_read_input_tokens": 10_000,
                },
            }

        events.extend(
            [
                {**base, "event_kind": "reference", "reference_kind": "plan"},
                {
                    **base,
                    "event_kind": "model",
                    "provider": "openai",
                    "model": "gpt-5",
                    "reasoning_effort": "high",
                },
                usage(0),
                {**base, "event_kind": "tool-call", "tool_family": "edit"},
                {**base, "event_kind": "model", "provider": "openai", "model": "gpt-5"},
                usage(1),
                {**base, "event_kind": "test"},
                {**base, "event_kind": "tool-call", "tool_family": "write"},
                {**base, "event_kind": "model", "provider": "openai", "model": "gpt-5"},
                usage(2),
            ]
        )
    return events, episodes, sessions


def _score(count: int = 5) -> dict:
    events, episodes, sessions = _corpus(count)
    return score_token_cost_profile(
        events,
        episodes=episodes,
        sessions=sessions,
        pricing_snapshot=load_pricing_snapshot("1.0.0"),
    )


def test_snapshot_is_closed_content_addressed_and_defensively_owned():
    first = load_pricing_snapshot("1.0.0")
    second = load_pricing_snapshot("1.0.0")
    assert first.reference() == second.reference()
    assert first.digest == "7a54a695e2f0ca6a0c959dfa7c5a51f9c0546c4422c785233269a4eb52939f50"
    document = first.document()
    load_validator("pricing_snapshot.schema.json").validate(document)
    assert {source["provider"] for source in document["sources"]} == {"anthropic", "openai"}
    document["rates"][0]["input"] = 0
    assert first.document()["rates"][0]["input"] == 1_000_000
    with pytest.raises(PricingSnapshotError):
        load_pricing_snapshot("latest")


def test_profile_is_deterministic_registry_conforming_and_support_qualified():
    first = _score()
    second = _score()
    assert canonical_bytes(first) == canonical_bytes(second)
    load_validator("token_cost_profile.schema.json").validate(first)

    assert first["pricing_snapshot"] == {
        "version": "1.0.0",
        "digest": "7a54a695e2f0ca6a0c959dfa7c5a51f9c0546c4422c785233269a4eb52939f50",
        "currency": "USD",
    }
    assert first["local"]["tokens_by_model"] == [{"model": "gpt-5", "tokens": 1_800_000}]
    assert first["local"]["tokens_by_phase"] == [
        {"phase": "BUILD", "tokens": 1_200_000},
        {"phase": "PLAN", "tokens": 600_000},
    ]
    assert first["local"]["rework_token_share_basis_points"] == 3333
    assert first["local"]["abandoned_session_token_share_basis_points"] == 2000

    public = first["publishable"]
    assert public[TOKENS_BY_MODEL_ID]["cells"] == [
        {"model": "gpt-5", "token_band": "1m-9.9m"}
    ]
    assert public[TOKENS_BY_PHASE_ID]["cells"] == [
        {"phase": "BUILD", "token_band": "1m-9.9m"},
        {"phase": "PLAN", "token_band": "100-999k"},
    ]
    assert public[PLANNING_RATIO_ID]["ratio_band"] == "0.5-0.99"
    assert public[REWORK_TOKEN_SHARE_ID]["share_band"] == "25-49%"
    assert public[ABANDONED_TOKEN_SHARE_ID]["share_band"] == "10-24%"
    assert all(output["caveats"] == ["provider-reported-inflatable"] for output in public.values())

    local_costs = first["local"]["cost_claims"]
    assert local_costs[COST_BY_MODEL_ID]["cells"] == [
        {"model": "gpt-5", "cost_micro_usd": 3_206_250}
    ]
    assert local_costs[COST_PER_EPISODE_ID]["cells"] == [
        {"cost_band": "<$1", "episode_count": 5}
    ]
    assert local_costs[COST_PER_EPISODE_ID]["unknown_episode_count"] == 0
    assert local_costs[COST_BY_MODEL_ID]["estimate_label"].endswith("not-invoice")

    registry = Registry.load()
    for registry_id, output in {**public, **local_costs}.items():
        entry = registry.entry(registry_id)
        registry.check_claim(
            {
                "registry_id": registry_id,
                "registry_version": entry["version"],
                "derivation_class": entry["class"],
                "output": output,
            }
        )


def test_support_floor_suppresses_at_four_and_fires_at_five():
    thin = _score(4)
    assert thin["publishable"] == {}
    assert thin["local"]["cost_claims"] == {}
    assert _score(5)["publishable"]
    assert _score(5)["local"]["cost_claims"]


@pytest.mark.parametrize("ambiguity", ["model", "date", "cache-duration"])
def test_missing_or_ambiguous_pricing_dimensions_are_unknown(ambiguity):
    events, episodes, sessions = _corpus()
    for event in events:
        if ambiguity == "model" and event["event_kind"] == "model":
            event["model"] = "gpt-5-codex-private-unmapped"
        elif ambiguity == "date" and event["event_kind"] == "token-usage":
            event["observed_at"] = "2026-07-18T00:00:00.000000Z"
        elif ambiguity == "cache-duration" and event["event_kind"] == "token-usage":
            event["token_usage"]["cache_creation_input_tokens"] = 1
    result = score_token_cost_profile(
        events,
        episodes=episodes,
        sessions=sessions,
        pricing_snapshot=load_pricing_snapshot("1.0.0"),
    )
    cells = result["local"]["cost_claims"][COST_BY_MODEL_ID]["cells"]
    assert cells[0]["cost_micro_usd"] == "UNKNOWN"
    assert result["local"]["cost_claims"][COST_PER_EPISODE_ID]["unknown_episode_count"] == 5
    assert result["local"]["pricing_unknown_observations"] == 15


def test_reasoning_effort_never_changes_price():
    events, episodes, sessions = _corpus()
    snapshot = load_pricing_snapshot("1.0.0")
    high = score_token_cost_profile(
        events, episodes=episodes, sessions=sessions, pricing_snapshot=snapshot
    )
    for event in events:
        if event["event_kind"] == "model":
            event["reasoning_effort"] = "minimal"
    minimal = score_token_cost_profile(
        events, episodes=episodes, sessions=sessions, pricing_snapshot=snapshot
    )
    assert canonical_bytes(high) == canonical_bytes(minimal)


def test_token_coverage_contribution_counts_missing_sessions_honestly():
    events, episodes, sessions = _corpus()
    extra_episode = "ep-ffffffffffffffffffffffffffffffff"
    episodes.append(
        {
            "task_episode_id": extra_episode,
            "episode_outcome": "unknown",
            "outcome_classifier_version": "1.0.0",
        }
    )
    sessions.append({"session_id": "synthetic-missing-token-session", "task_episode_id": extra_episode})
    result = score_token_cost_profile(
        events,
        episodes=episodes,
        sessions=sessions,
        pricing_snapshot=load_pricing_snapshot("1.0.0"),
    )
    assert result["coverage"]["observations"][0]["coverage_basis_points"] == 8333
    assert result["coverage"]["missing_ambiguous"] == [
        {"category": "missing-token-data", "count": 1}
    ]


def test_scorer_does_not_read_network_clock_or_environment(monkeypatch):
    events, episodes, sessions = _corpus()
    snapshot = load_pricing_snapshot("1.0.0")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("ambient dependency read")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    result = score_token_cost_profile(
        events,
        episodes=episodes,
        sessions=sessions,
        pricing_snapshot=snapshot,
    )
    assert result["pricing_snapshot"] == snapshot.reference()


def test_emitted_section_and_logs_are_leak_free_and_scanner_fires(tmp_path, caplog):
    fixtures = generate_fixtures(tmp_path / "fixtures")
    result = _score()
    safe = tmp_path / "token-cost.json"
    log = tmp_path / "token-cost.log"
    safe.write_bytes(canonical_bytes(result) + b"\n")
    log.write_text(caplog.text)
    canaries = [
        *fixtures.all_canaries(),
        SESSION_CANARY.encode(),
        CONTENT_CANARY.encode(),
        FILENAME_CANARY.encode(),
    ]
    assert assert_no_canaries([safe, log], canaries) == 2
    encoded = safe.read_bytes()
    for canary in canaries:
        assert canary not in encoded
        assert canary.hex().encode() not in encoded
        assert base64.b64encode(canary) not in encoded

    planted = tmp_path / "planted.json"
    planted.write_bytes(canonical_bytes(result) + CONTENT_CANARY.encode())
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], canaries)


def test_closed_section_rejects_identifier_or_invoice_claims():
    bad = deepcopy(_score())
    bad["publishable"][TOKENS_BY_MODEL_ID]["session_id"] = SESSION_CANARY
    with pytest.raises(ValidationError):
        load_validator("token_cost_profile.schema.json").validate(bad)

    bad = deepcopy(_score())
    bad["local"]["cost_claims"][COST_BY_MODEL_ID]["actual_spend"] = 1
    with pytest.raises(ValidationError):
        load_validator("token_cost_profile.schema.json").validate(bad)

    assert "session_id" not in json.dumps(_score(), sort_keys=True)
