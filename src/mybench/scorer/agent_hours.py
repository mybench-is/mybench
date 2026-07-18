"""Deterministic coarse lifecycle-duration scorer (MYB-19.10).

Exact per-session observations exist only in memory.  This scorer emits the
ACTIVE registry descriptor's coarse evidence-period bands, coverage bands,
controlled caveats, and ANCHORED ceiling.  It has no wall-clock, filesystem,
environment, or network dependency.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from mybench.normalizer.session_timing import SessionTiming
from mybench.registry import Registry, RegistryError

AGENT_HOURS_REGISTRY_ID = "transcript.agent_hours"
AGENT_HOURS_SCORER_VERSION = "1.0.0"

_DURATION_UNDER = re.compile(r"under-([0-9]+)h\Z")
_DURATION_RANGE = re.compile(r"([0-9]+)h-to-under-([0-9]+)h\Z")
_DURATION_PLUS = re.compile(r"([0-9]+)h-plus\Z")
_COVERAGE_UNDER = re.compile(r"under-([0-9]+)-percent\Z")
_COVERAGE_RANGE = re.compile(r"([0-9]+)-to-under-([0-9]+)-percent\Z")
_COVERAGE_FINAL = re.compile(r"([0-9]+)-to-100-percent\Z")
_BACKFILL_UNDER = re.compile(r"under-([0-9]+)-days\Z")
_BACKFILL_PLUS = re.compile(r"([0-9]+)-days-plus\Z")
_IDLE_GAP = re.compile(r"sum-observed-gaps-no-greater-than-([0-9]+)m\Z")


class AgentHoursScoringError(ValueError):
    """The registry contract or private structural input is invalid."""


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != timezone.utc:
        raise AgentHoursScoringError("session timing is not UTC")
    return parsed


def _bands(entry: dict, field: str) -> list[str]:
    for definition in entry["band_definitions"]:
        if definition["field"] == field:
            return list(definition["bands"])
    raise AgentHoursScoringError("agent-hours registry contract is incomplete")


def _const(entry: dict, field: str):
    try:
        return entry["output_schema"]["properties"][field]["const"]
    except (KeyError, TypeError):
        raise AgentHoursScoringError("agent-hours registry contract is incomplete") from None


def _duration_band(value: timedelta | None, bands: Sequence[str]) -> str:
    if value is None:
        if "unknown" not in bands:
            raise AgentHoursScoringError("agent-hours registry omits the unknown band")
        return "unknown"
    for band in bands:
        match = _DURATION_UNDER.fullmatch(band)
        if match and value < timedelta(hours=int(match.group(1))):
            return band
        match = _DURATION_RANGE.fullmatch(band)
        if match and timedelta(hours=int(match.group(1))) <= value < timedelta(
            hours=int(match.group(2))
        ):
            return band
        match = _DURATION_PLUS.fullmatch(band)
        if match and value >= timedelta(hours=int(match.group(1))):
            return band
    raise AgentHoursScoringError("agent-hours duration bands do not cover the value")


def _coverage_band(numerator: int, denominator: int, bands: Sequence[str]) -> str:
    if denominator <= 0 or numerator < 0 or numerator > denominator:
        raise AgentHoursScoringError("agent-hours coverage input is invalid")
    for band in bands:
        match = _COVERAGE_UNDER.fullmatch(band)
        if match and numerator * 100 < int(match.group(1)) * denominator:
            return band
        match = _COVERAGE_RANGE.fullmatch(band)
        if (
            match
            and int(match.group(1)) * denominator
            <= numerator * 100
            < int(match.group(2)) * denominator
        ):
            return band
        match = _COVERAGE_FINAL.fullmatch(band)
        if match and int(match.group(1)) * denominator <= numerator * 100 <= 100 * denominator:
            return band
    raise AgentHoursScoringError("agent-hours coverage bands do not cover the value")


def _backfill_band(anchored_span_days: int, bands: Sequence[str]) -> str:
    for band in bands:
        match = _BACKFILL_UNDER.fullmatch(band)
        if match and anchored_span_days < int(match.group(1)):
            return band
        match = _BACKFILL_PLUS.fullmatch(band)
        if match and anchored_span_days >= int(match.group(1)):
            return band
    raise AgentHoursScoringError("agent-hours backfill bands do not cover the value")


def _active_duration(timing: SessionTiming, idle_gap: timedelta) -> timedelta:
    assert timing.opened_at is not None and timing.closed_at is not None
    points = {
        _timestamp(timing.opened_at),
        _timestamp(timing.closed_at),
        *(_timestamp(value) for value in timing.event_observed_at),
    }
    ordered = sorted(points)
    total = timedelta()
    for earlier, later in zip(ordered, ordered[1:]):
        gap = later - earlier
        # The pinned idle rule excludes the whole gap when it exceeds the
        # threshold.  It does not fabricate a threshold-sized activity tail.
        if gap <= idle_gap:
            total += gap
    return total


def score_agent_hours(
    timings: Sequence[SessionTiming],
    *,
    anchored_span_days: int,
    registry: Registry | None = None,
) -> dict | None:
    """Return one registry-conforming coarse profile, or ``None`` below k.

    ``anchored_span_days`` is an explicit caller input.  The scorer never reads
    ambient time.  Session overlaps are intentionally summed: this is an
    agent-hours profile, not a global elapsed-time or concurrency claim.
    """

    if isinstance(timings, (str, bytes)) or not isinstance(timings, Sequence):
        raise AgentHoursScoringError("session timings must be an explicit sequence")
    if type(anchored_span_days) is not int or anchored_span_days < 0:
        raise AgentHoursScoringError("anchored span must be a non-negative integer")
    if any(not isinstance(timing, SessionTiming) for timing in timings):
        raise AgentHoursScoringError("session timing input has the wrong type")

    registry = registry or Registry.load()
    entry = registry.entry(AGENT_HOURS_REGISTRY_ID)
    if entry["status"] != "active":
        raise AgentHoursScoringError("agent-hours descriptor is not active")
    support = registry.min_support(AGENT_HOURS_REGISTRY_ID)
    if set(support) != {"sessions"} or type(support["sessions"]) is not int:
        raise AgentHoursScoringError("agent-hours support contract is invalid")
    if len(timings) < support["sessions"]:
        return None

    trust_tier = _const(entry, "trust_tier")
    if trust_tier != "ANCHORED":
        raise AgentHoursScoringError("agent-hours trust ceiling must remain ANCHORED")
    expected_normalizer = _const(entry, "close_normalizer_version")
    if any(timing.normalizer_version != expected_normalizer for timing in timings):
        raise AgentHoursScoringError("session timing normalizer version is unsupported")
    active_definition = _const(entry, "active_time_definition")
    idle_match = _IDLE_GAP.fullmatch(active_definition)
    if idle_match is None or int(idle_match.group(1)) <= 0:
        raise AgentHoursScoringError("agent-hours idle-gap contract is invalid")
    idle_gap = timedelta(minutes=int(idle_match.group(1)))

    boundary_known = [
        timing
        for timing in timings
        if timing.opened_at is not None and timing.closed_at is not None
    ]
    active_known = [timing for timing in boundary_known if timing.observed_at_status == "complete"]
    wall_total = (
        sum(
            (
                _timestamp(timing.closed_at) - _timestamp(timing.opened_at)
                for timing in boundary_known
            ),
            timedelta(),
        )
        if boundary_known
        else None
    )
    active_total = (
        sum((_active_duration(timing, idle_gap) for timing in active_known), timedelta())
        if active_known
        else None
    )

    output = {
        "active_time_band": _duration_band(active_total, _bands(entry, "active_time_band")),
        "wall_clock_time_band": _duration_band(wall_total, _bands(entry, "wall_clock_time_band")),
        "observed_boundary_coverage_band": _coverage_band(
            len(boundary_known),
            len(timings),
            _bands(entry, "observed_boundary_coverage_band"),
        ),
        "active_time_coverage_band": _coverage_band(
            len(active_known),
            len(timings),
            _bands(entry, "active_time_coverage_band"),
        ),
        "backfill_annotation": _backfill_band(
            anchored_span_days, _bands(entry, "backfill_annotation")
        ),
        "active_time_definition": active_definition,
        "wall_clock_definition": _const(entry, "wall_clock_definition"),
        "close_normalizer_version": expected_normalizer,
        "trust_tier": trust_tier,
        "caveats": _const(entry, "caveats"),
    }

    try:
        registry.check_claim(
            {
                "registry_id": AGENT_HOURS_REGISTRY_ID,
                "registry_version": entry["version"],
                "derivation_class": entry["class"],
                "output": output,
            }
        )
    except RegistryError as exc:
        raise AgentHoursScoringError("agent-hours output failed registry conformance") from exc
    return output


__all__ = [
    "AGENT_HOURS_REGISTRY_ID",
    "AGENT_HOURS_SCORER_VERSION",
    "AgentHoursScoringError",
    "score_agent_hours",
]
