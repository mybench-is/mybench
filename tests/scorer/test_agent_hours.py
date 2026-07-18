"""MYB-19.10: registry-governed lifecycle duration bands."""

from __future__ import annotations

import json

import pytest

from mybench.claims.canonical import canonical_bytes
from mybench.normalizer import SessionTiming
from mybench.registry import Registry, _packaged_registry_bytes
from mybench.scorer import AgentHoursScoringError, score_agent_hours
from mybench.scorer.agent_hours import _timestamp
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures


def _timing(
    *,
    opened_at: str = "2026-01-01T00:00:00.000000Z",
    closed_at: str | None = "2026-01-01T02:00:00.000000Z",
    complete: bool = True,
) -> SessionTiming:
    if closed_at is None:
        return SessionTiming(
            source="codex",
            open_status="scan-inferred",
            close_status="unknown",
            observed_at_status="partial",
            opened_at=opened_at,
            closed_at=None,
            event_observed_at=(opened_at,),
        )
    events = (
        opened_at,
        "2026-01-01T00:10:00.000000Z",
        "2026-01-01T00:20:00.000000Z",
        closed_at,
    )
    return SessionTiming(
        source="codex",
        open_status="scan-inferred",
        close_status="scan-inferred",
        observed_at_status="complete" if complete else "partial",
        opened_at=opened_at,
        closed_at=closed_at,
        event_observed_at=events,
    )


def test_active_and_wall_definitions_use_registry_bands_and_exclude_long_idle_gap():
    result = score_agent_hours([_timing() for _ in range(5)], anchored_span_days=20)
    assert result == {
        "active_time_band": "1h-to-under-8h",
        "wall_clock_time_band": "8h-to-under-40h",
        "observed_boundary_coverage_band": "90-to-100-percent",
        "active_time_coverage_band": "90-to-100-percent",
        "backfill_annotation": "14-days-plus",
        "active_time_definition": "sum-observed-gaps-no-greater-than-30m",
        "wall_clock_definition": "sum-observed-open-to-observed-or-scan-inferred-close",
        "close_normalizer_version": "1.0.0",
        "trust_tier": "ANCHORED",
        "caveats": [
            "capture-dependent-and-inflatable",
            "observed-at-coverage-limits-backfill",
        ],
    }


def test_min_support_suppresses_and_fires_at_five_sessions():
    assert score_agent_hours([_timing() for _ in range(4)], anchored_span_days=20) is None
    assert score_agent_hours([_timing() for _ in range(5)], anchored_span_days=20) is not None


@pytest.mark.parametrize(
    "value",
    ["2026-01-01T00:00:00.000000+00:00", "not-a-timestamp"],
)
def test_timestamp_parser_defensively_rejects_noncanonical_values(value):
    with pytest.raises(AgentHoursScoringError, match="not canonical UTC"):
        _timestamp(value)


def test_unknowns_coverage_backfill_and_top_coding_are_honest():
    mixed = [_timing() for _ in range(4)] + [_timing(closed_at=None)]
    result = score_agent_hours(mixed, anchored_span_days=13)
    assert result["observed_boundary_coverage_band"] == "75-to-under-90-percent"
    assert result["active_time_coverage_band"] == "75-to-under-90-percent"
    assert result["backfill_annotation"] == "under-14-days"

    top_coded = [_timing(closed_at="2026-01-09T08:00:00.000000Z", complete=False) for _ in range(5)]
    result = score_agent_hours(top_coded, anchored_span_days=20)
    assert result["wall_clock_time_band"] == "160h-plus"
    assert result["active_time_band"] == "unknown"


def test_scorer_is_deterministic_and_never_emits_exact_points_or_timestamps():
    values = [_timing() for _ in range(4)] + [_timing(closed_at=None)]
    first = score_agent_hours(values, anchored_span_days=20)
    second = score_agent_hours(list(reversed(values)), anchored_span_days=20)
    assert canonical_bytes(first) == canonical_bytes(second)
    encoded = canonical_bytes(first)
    assert b"2026-" not in encoded
    assert b"session_id" not in encoded
    assert b"seconds" not in encoded
    assert b'"trust_tier":"PROVEN"' not in encoded


def test_registry_tier_guard_fires_if_contract_is_mutated_to_proven():
    doc = json.loads(_packaged_registry_bytes())
    entry = next(item for item in doc["entries"] if item["id"] == "transcript.agent_hours")
    entry["output_schema"]["properties"]["trust_tier"]["const"] = "PROVEN"
    with pytest.raises(AgentHoursScoringError, match="must remain ANCHORED"):
        score_agent_hours(
            [_timing() for _ in range(5)],
            anchored_span_days=20,
            registry=Registry(doc),
        )


def test_public_bands_are_leak_free_and_scanner_fires(tmp_path):
    fixtures = generate_fixtures(tmp_path / "fixtures")
    result = score_agent_hours([_timing() for _ in range(5)], anchored_span_days=20)
    safe = tmp_path / "agent-hours.json"
    safe.write_bytes(canonical_bytes(result) + b"\n")
    assert assert_no_canaries([safe], fixtures.all_canaries()) == 1

    planted = tmp_path / "planted.json"
    planted.write_bytes(canonical_bytes(result) + fixtures.all_canaries()[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], fixtures.all_canaries())
