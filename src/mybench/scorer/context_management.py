"""Deterministic context-management aggregates over private structural evidence.

The scorer joins the closed MYB-10.4 normalized session/event projection with
the whitelisted MYB-12.4 lifecycle-row projection.  Opaque identities are used
only as in-memory join keys.  They, ordered event streams, model strings, and
boundary positions never enter either output form.

Missing markers reduce the adjacent per-field coverage.  They are never
treated as observed inactivity: unsupported rates, counts, and distributions
remain ``UNKNOWN``.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence

from mybench.normalizer.workflow_phase import (
    WORKFLOW_PHASE_CLASSIFIER_VERSION,
    classify_workflow_phases,
)
from mybench.registry import Registry, RegistryError
from mybench.schemas import load_validator
from mybench.scorer.evidence_coverage import build_coverage_contribution

CONTEXT_MANAGEMENT_SCHEMA_VERSION = "1"
CONTEXT_MANAGEMENT_SCORER_VERSION = "1.0.0"
CONTEXT_DEFINITION_VERSION = "1.0.0"
CONTEXT_IDENTITY_VERSION = "1.0.0"
EPISODE_STITCHER_VERSION = "2.0.0"

FRESH_SESSION_RATE_ID = "fingerprint.context.fresh_session_rate.band"
RESUME_RATE_ID = "fingerprint.context.resume_rate.band"
CLEAR_RATE_ID = "fingerprint.context.clear_rate.band"
MANUAL_COMPACTIONS_ID = "fingerprint.context.manual_compactions.band"
AUTOMATIC_COMPACTIONS_ID = "fingerprint.context.automatic_compactions.band"
GENERATIONS_PER_EPISODE_ID = "fingerprint.context.generations_per_episode.band"
ONE_CONTEXT_EPISODE_RATE_ID = "fingerprint.context.one_context_episode_rate.band"
FRESH_PHASE_SPLIT_ID = "fingerprint.context.fresh_phase_split.band"
MODEL_CHANGE_BOUNDARY_RATE_ID = "fingerprint.context.model_change_boundary_rate.band"

CONTEXT_MANAGEMENT_REGISTRY_IDS = (
    FRESH_SESSION_RATE_ID,
    RESUME_RATE_ID,
    CLEAR_RATE_ID,
    MANUAL_COMPACTIONS_ID,
    AUTOMATIC_COMPACTIONS_ID,
    GENERATIONS_PER_EPISODE_ID,
    ONE_CONTEXT_EPISODE_RATE_ID,
    FRESH_PHASE_SPLIT_ID,
    MODEL_CHANGE_BOUNDARY_RATE_ID,
)

_OPAQUE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_EPISODE_ID = re.compile(r"ep-[0-9a-f]{32}\Z")
_SOURCES = frozenset({"claude-code", "codex"})
_LIFECYCLE_KINDS = frozenset({"session_start", "session_end", "compact_pre", "model_change"})
_START_TRIGGERS = frozenset({"startup", "resume", "clear", "compact", "unknown"})
_EVENT_TRIGGERS = {
    "session_start": _START_TRIGGERS,
    "session_end": frozenset({"clear", "resume", "unknown"}),
    "compact_pre": frozenset({"manual", "auto", "unknown"}),
    "model_change": frozenset({"unknown"}),
}
_IMPLEMENTATION_PHASES = frozenset({"BUILD", "TEST", "DEBUG", "REVIEW", "COMMIT"})
_SHARE_BANDS = ("0-9%", "10-24%", "25-49%", "50-74%", "75-100%", "UNKNOWN")
_COUNT_BANDS = ("0", "1-4", "5-19", "20-99", "100-999", "1000+")


class ContextManagementScoringError(ValueError):
    """The registry contract or private structural input is invalid."""


def _basis_points(numerator: int, denominator: int) -> int | str:
    if denominator == 0:
        return "UNKNOWN"
    if numerator < 0 or numerator > denominator:
        raise ContextManagementScoringError("context-management rate input is invalid")
    return min(10000, (10000 * numerator + denominator // 2) // denominator)


def _confidence(coverage: int | str) -> str:
    if coverage == "UNKNOWN":
        return "UNKNOWN"
    if type(coverage) is not int or not 0 <= coverage <= 10000:
        raise ContextManagementScoringError("context-management coverage is invalid")
    if coverage < 5000:
        return "LOW"
    if coverage < 7500:
        return "MEDIUM"
    return "HIGH"


def _share_band(value: int | str, bands: Sequence[str]) -> str:
    if tuple(bands) != _SHARE_BANDS:
        raise ContextManagementScoringError("context-management share bands are invalid")
    if value == "UNKNOWN":
        return bands[-1]
    if type(value) is not int or not 0 <= value <= 10000:
        raise ContextManagementScoringError("context-management basis points are invalid")
    if value < 1000:
        return bands[0]
    if value < 2500:
        return bands[1]
    if value < 5000:
        return bands[2]
    if value < 7500:
        return bands[3]
    return bands[4]


def _count_band(value: int, bands: Sequence[str]) -> str:
    if tuple(bands) != _COUNT_BANDS or type(value) is not int or value < 0:
        raise ContextManagementScoringError("context-management count bands are invalid")
    if value == 0:
        return bands[0]
    if value < 5:
        return bands[1]
    if value < 20:
        return bands[2]
    if value < 100:
        return bands[3]
    if value < 1000:
        return bands[4]
    return bands[5]


def _bands(entry: dict, field: str) -> tuple[str, ...]:
    for definition in entry["band_definitions"]:
        if definition["field"] == field:
            return tuple(definition["bands"])
    raise ContextManagementScoringError("context-management registry contract is incomplete")


def _registry_contract(
    registry: Registry,
) -> tuple[dict[str, dict], tuple[str, ...], tuple[str, ...]]:
    entries = {
        registry_id: registry.entry(registry_id) for registry_id in CONTEXT_MANAGEMENT_REGISTRY_IDS
    }
    for entry in entries.values():
        if entry["status"] != "active" or entry["class"] != "measured":
            raise ContextManagementScoringError("context-management descriptor is not active")
    expected_support = {
        FRESH_SESSION_RATE_ID: {"sessions": 5},
        RESUME_RATE_ID: {"sessions": 5},
        CLEAR_RATE_ID: {"events": 5},
        MANUAL_COMPACTIONS_ID: {"events": 5},
        AUTOMATIC_COMPACTIONS_ID: {"events": 5},
        GENERATIONS_PER_EPISODE_ID: {"episodes": 5},
        ONE_CONTEXT_EPISODE_RATE_ID: {"episodes": 5},
        FRESH_PHASE_SPLIT_ID: {"sessions": 5},
        MODEL_CHANGE_BOUNDARY_RATE_ID: {"events": 5},
    }
    for registry_id, support in expected_support.items():
        if registry.min_support(registry_id) != support:
            raise ContextManagementScoringError("context-management support contract is invalid")
    share_bands = _bands(entries[FRESH_SESSION_RATE_ID], "rate_band")
    share_fields = {
        RESUME_RATE_ID: "rate_band",
        CLEAR_RATE_ID: "rate_band",
        GENERATIONS_PER_EPISODE_ID: "episode_share_band",
        ONE_CONTEXT_EPISODE_RATE_ID: "rate_band",
        FRESH_PHASE_SPLIT_ID: "share_band",
        MODEL_CHANGE_BOUNDARY_RATE_ID: "rate_band",
    }
    for registry_id, field in share_fields.items():
        if _bands(entries[registry_id], field) != share_bands:
            raise ContextManagementScoringError("context-management share-band contracts disagree")
    count_bands = _bands(entries[MANUAL_COMPACTIONS_ID], "count_band")
    if (
        _bands(entries[AUTOMATIC_COMPACTIONS_ID], "count_band") != count_bands
        or _bands(entries[GENERATIONS_PER_EPISODE_ID], "generation_count_band") != count_bands
    ):
        raise ContextManagementScoringError("context-management count-band contracts disagree")
    _share_band("UNKNOWN", share_bands)
    _count_band(0, count_bands)
    return entries, share_bands, count_bands


def _session_inputs(
    sessions: Sequence[Mapping[str, object]],
) -> tuple[tuple[tuple[str, str], ...], dict[tuple[str, str], str | None]]:
    if isinstance(sessions, (str, bytes)) or not isinstance(sessions, Sequence):
        raise ContextManagementScoringError("sessions must be an explicit sequence")
    keys = []
    episode_by_session = {}
    for session in sessions:
        if not isinstance(session, Mapping):
            raise ContextManagementScoringError("session input has the wrong type")
        source, session_id = session.get("source"), session.get("session_id")
        if (
            source not in _SOURCES
            or not isinstance(session_id, str)
            or not _OPAQUE_ID.fullmatch(session_id)
        ):
            raise ContextManagementScoringError("session input has an invalid opaque identity")
        key = (source, session_id)
        if key in episode_by_session:
            raise ContextManagementScoringError("session identities must be unique")
        episode_id = session.get("task_episode_id")
        if episode_id is not None and (
            not isinstance(episode_id, str) or not _EPISODE_ID.fullmatch(episode_id)
        ):
            raise ContextManagementScoringError("session has an invalid episode identity")
        keys.append(key)
        episode_by_session[key] = episode_id
    return tuple(sorted(keys)), episode_by_session


def _episode_inputs(episodes: Sequence[Mapping[str, object]]) -> tuple[str, ...]:
    if isinstance(episodes, (str, bytes)) or not isinstance(episodes, Sequence):
        raise ContextManagementScoringError("episodes must be an explicit sequence")
    values = []
    for episode in episodes:
        if not isinstance(episode, Mapping):
            raise ContextManagementScoringError("episode input has the wrong type")
        value = episode.get("task_episode_id")
        if not isinstance(value, str) or not _EPISODE_ID.fullmatch(value):
            raise ContextManagementScoringError("episode input has an invalid identity")
        values.append(value)
    if len(values) != len(set(values)):
        raise ContextManagementScoringError("episode identities must be unique")
    return tuple(sorted(values))


def _normalized_events(
    events: Sequence[Mapping[str, object]], session_keys: set[tuple[str, str]]
) -> dict[tuple[str, str], list[Mapping[str, object]]]:
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise ContextManagementScoringError("normalized events must be an explicit sequence")
    grouped = {key: [] for key in session_keys}
    ordinals = set()
    for event in events:
        if not isinstance(event, Mapping):
            raise ContextManagementScoringError("normalized event has the wrong type")
        source, session_id = event.get("source"), event.get("session_id")
        key = (source, session_id)
        record_index, subevent_index = event.get("record_index"), event.get("subevent_index")
        if key not in grouped:
            raise ContextManagementScoringError("normalized event has no declared session")
        if (
            type(record_index) is not int
            or record_index < 0
            or type(subevent_index) is not int
            or subevent_index < 0
        ):
            raise ContextManagementScoringError("normalized event has an invalid ordinal")
        ordinal = (key, record_index, subevent_index)
        if ordinal in ordinals:
            raise ContextManagementScoringError("normalized event ordinals must be unique")
        ordinals.add(ordinal)
        grouped[key].append(event)
    for values in grouped.values():
        values.sort(key=lambda item: (item["record_index"], item["subevent_index"]))
    return grouped


def _lifecycle_rows(
    rows: Sequence[Mapping[str, object]], session_keys: set[tuple[str, str]]
) -> dict[tuple[str, str], list[Mapping[str, object]]]:
    if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
        raise ContextManagementScoringError("lifecycle rows must be an explicit sequence")
    grouped = {key: [] for key in session_keys}
    indexes = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise ContextManagementScoringError("lifecycle row has the wrong type")
        index = row.get("i")
        kind, trigger = row.get("event_kind"), row.get("trigger")
        key = (row.get("harness"), row.get("session_id"))
        generation = row.get("context_gen")
        if (
            row.get("type") != "event"
            or type(index) is not int
            or index < 0
            or index in indexes
            or key not in grouped
            or kind not in _LIFECYCLE_KINDS
            or trigger not in _EVENT_TRIGGERS[kind]
            or type(generation) is not int
            or generation < 0
        ):
            raise ContextManagementScoringError("lifecycle row violates the closed projection")
        indexes.add(index)
        grouped[key].append(row)
    for values in grouped.values():
        values.sort(key=lambda item: item["i"])
    return grouped


def _known_or_conflicting(
    values: Sequence[str], known: set[str] | frozenset[str]
) -> tuple[str | None, bool]:
    observed = {value for value in values if value in known}
    if len(observed) > 1:
        return None, True
    return (next(iter(observed)) if observed else None), False


def _local_value(value: object, coverage: int | str) -> dict:
    return {
        "value": value,
        "coverage_basis_points": coverage,
        "confidence": _confidence(coverage),
    }


def _claim_output(registry: Registry, entry: dict, output: dict) -> dict:
    try:
        registry.check_claim(
            {
                "registry_id": entry["id"],
                "registry_version": entry["version"],
                "derivation_class": entry["class"],
                "output": output,
            }
        )
    except RegistryError as exc:
        raise ContextManagementScoringError(
            "context-management output failed registry conformance"
        ) from exc
    return output


def score_context_management(
    events: Sequence[Mapping[str, object]],
    *,
    sessions: Sequence[Mapping[str, object]],
    episodes: Sequence[Mapping[str, object]],
    lifecycle_events: Sequence[Mapping[str, object]],
    episode_stitcher_version: str,
    registry: Registry | None = None,
) -> dict:
    """Return a closed local profile and support-qualified public atoms.

    ``events`` and ``sessions`` are the private MYB-10.4 projection.
    ``lifecycle_events`` is the A3 event-row whitelist only; full ledger rows
    and content-bearing inputs are neither required nor accepted as authority.
    """

    if episode_stitcher_version != EPISODE_STITCHER_VERSION:
        raise ContextManagementScoringError("episode stitcher version is unsupported")
    registry = registry or Registry.load()
    entries, share_bands, count_bands = _registry_contract(registry)
    session_order, episode_by_session = _session_inputs(sessions)
    episode_order = _episode_inputs(episodes)
    if not set(value for value in episode_by_session.values() if value is not None) <= set(
        episode_order
    ):
        raise ContextManagementScoringError("session references an undeclared episode")
    normalized = _normalized_events(events, set(session_order))
    lifecycle = _lifecycle_rows(lifecycle_events, set(session_order))

    reliable_sessions = 0
    conflicts = 0
    start_trigger_by_session: dict[tuple[str, str], str] = {}
    generation_trigger_values: dict[tuple[tuple[str, str], int], list[str]] = defaultdict(list)
    generation_ids: dict[tuple[str, str], set[int]] = defaultdict(set)
    compaction_triggers: dict[tuple[tuple[str, str], int], list[str]] = defaultdict(list)
    lifecycle_event_total = 0
    normalized_boundaries: dict[tuple[tuple[str, str], int], tuple[int, Mapping[str, object]]] = {}
    unjoined_compaction_rows = 0
    model_change_generations: set[tuple[tuple[str, str], int]] = set()
    fresh_sessions: set[tuple[str, str]] = set()

    for key in session_order:
        normalized_rows = normalized[key]
        live_rows = lifecycle[key]
        normalized_lifecycle = [
            event for event in normalized_rows if event.get("event_kind") == "lifecycle"
        ]
        if normalized_lifecycle or live_rows:
            reliable_sessions += 1
        lifecycle_event_total += len(normalized_lifecycle) + len(live_rows)

        saw_normalized_start = False
        for position, event in enumerate(normalized_rows):
            if event.get("event_kind") != "lifecycle":
                continue
            marker = event.get("lifecycle_marker")
            if marker == "session-start":
                saw_normalized_start = True
            if marker != "context-boundary":
                continue
            generation = event.get("context_generation_id")
            if type(generation) is not int or generation < 1:
                conflicts += 1
                continue
            boundary_key = (key, generation)
            if boundary_key in normalized_boundaries:
                conflicts += 1
                continue
            normalized_boundaries[boundary_key] = (position, event)
            generation_ids[key].add(generation)
            compaction_triggers.setdefault(boundary_key, [])
        if saw_normalized_start:
            generation_ids[key].add(0)

        starts = [row["trigger"] for row in live_rows if row["event_kind"] == "session_start"]
        start_trigger, start_conflict = _known_or_conflicting(starts, _START_TRIGGERS - {"unknown"})
        conflicts += start_conflict
        if start_trigger is not None:
            start_trigger_by_session[key] = start_trigger
            if start_trigger == "startup":
                fresh_sessions.add(key)

        for row in live_rows:
            generation = row["context_gen"]
            event_kind = row["event_kind"]
            generation_key = (key, generation)
            if event_kind == "compact_pre":
                if generation_key not in normalized_boundaries:
                    unjoined_compaction_rows += 1
                    continue
                generation_ids[key].add(generation)
                generation_trigger_values[generation_key].append("compact")
                compaction_triggers[generation_key].append(row["trigger"])
                continue

            generation_ids[key].add(generation)
            if event_kind == "session_start" and row["trigger"] != "unknown":
                generation_trigger_values[generation_key].append(row["trigger"])
            elif event_kind == "model_change":
                model_change_generations.add(generation_key)

    known_start_count = len(start_trigger_by_session)
    session_count = len(session_order)
    start_coverage = _basis_points(known_start_count, session_count)
    fresh_rate = _basis_points(
        sum(trigger == "startup" for trigger in start_trigger_by_session.values()),
        known_start_count,
    )
    resume_rate = _basis_points(
        sum(trigger == "resume" for trigger in start_trigger_by_session.values()),
        known_start_count,
    )

    generation_triggers = {}
    for key, values in sorted(generation_trigger_values.items()):
        trigger, conflict = _known_or_conflicting(values, _START_TRIGGERS - {"unknown"})
        conflicts += conflict
        if trigger is not None:
            generation_triggers[key] = trigger
    eligible_generations = sum(max(values) + 1 for values in generation_ids.values() if values)
    known_generation_triggers = len(generation_triggers)
    clear_coverage = _basis_points(known_generation_triggers, eligible_generations)
    clear_rate = _basis_points(
        sum(trigger == "clear" for trigger in generation_triggers.values()),
        known_generation_triggers,
    )

    compaction_candidates = len(compaction_triggers)
    known_compaction_triggers = {}
    for key, values in sorted(compaction_triggers.items()):
        trigger, conflict = _known_or_conflicting(values, {"manual", "auto"})
        conflicts += conflict
        if trigger is not None:
            known_compaction_triggers[key] = trigger
    compaction_coverage = (
        "UNKNOWN"
        if unjoined_compaction_rows
        else _basis_points(len(known_compaction_triggers), compaction_candidates)
    )
    compaction_counts_known = (
        not unjoined_compaction_rows
        and compaction_candidates > 0
        and len(known_compaction_triggers) == compaction_candidates
    )
    manual_count: int | str = (
        sum(trigger == "manual" for trigger in known_compaction_triggers.values())
        if compaction_counts_known
        else "UNKNOWN"
    )
    automatic_count: int | str = (
        sum(trigger == "auto" for trigger in known_compaction_triggers.values())
        if compaction_counts_known
        else "UNKNOWN"
    )

    generation_count_by_session = {
        key: max(values) + 1 for key, values in generation_ids.items() if values
    }
    members_by_episode: dict[str, list[tuple[str, str]]] = {
        episode: [] for episode in episode_order
    }
    for key, episode in episode_by_session.items():
        if episode is not None:
            members_by_episode[episode].append(key)
    generation_counts = []
    for episode in episode_order:
        members = members_by_episode[episode]
        if members and all(member in generation_count_by_session for member in members):
            generation_counts.append(sum(generation_count_by_session[member] for member in members))
    episode_coverage = _basis_points(len(generation_counts), len(episode_order))
    generation_distribution: list[dict] | str
    if generation_counts:
        counts = Counter(_count_band(value, count_bands) for value in generation_counts)
        generation_distribution = [
            {"generation_count_band": band, "episode_count": counts[band]}
            for band in count_bands
            if counts[band]
        ]
    else:
        generation_distribution = "UNKNOWN"
    one_context_rate = _basis_points(
        sum(value == 1 for value in generation_counts), len(generation_counts)
    )

    phase_categories = Counter()
    for key in sorted(fresh_sessions):
        phases = classify_workflow_phases(normalized[key])
        first = next((item.phase for item in phases if item.phase != "UNKNOWN"), "UNKNOWN")
        if first == "PLAN":
            phase_categories["PLAN"] += 1
        elif first in _IMPLEMENTATION_PHASES:
            phase_categories["IMPLEMENTATION"] += 1
        else:
            phase_categories["UNKNOWN"] += 1
    fresh_phase_coverage = _basis_points(
        phase_categories["PLAN"] + phase_categories["IMPLEMENTATION"], len(fresh_sessions)
    )
    fresh_phase_split: list[dict] | str
    if fresh_sessions:
        fresh_phase_split = [
            {
                "phase_group": category,
                "basis_points": _basis_points(phase_categories[category], len(fresh_sessions)),
            }
            for category in ("IMPLEMENTATION", "PLAN", "UNKNOWN")
        ]
    else:
        fresh_phase_split = "UNKNOWN"

    boundary_candidates = {
        (key, generation)
        for key, generations in generation_ids.items()
        for generation in generations
        if generation > 0
    }
    boundary_candidates.update(normalized_boundaries)
    boundary_total = len(boundary_candidates)
    model_covered = 0
    model_changed = 0
    for boundary_key, (position, _event) in sorted(normalized_boundaries.items()):
        key, _generation = boundary_key
        session_events = normalized[key]
        prior = next(
            (
                item.get("model")
                for item in reversed(session_events[:position])
                if item.get("event_kind") == "model" and isinstance(item.get("model"), str)
            ),
            None,
        )
        next_boundary = next(
            (
                candidate
                for candidate in range(position + 1, len(session_events))
                if session_events[candidate].get("event_kind") == "lifecycle"
                and session_events[candidate].get("lifecycle_marker") == "context-boundary"
            ),
            len(session_events),
        )
        following = next(
            (
                item.get("model")
                for item in session_events[position + 1 : next_boundary]
                if item.get("event_kind") == "model" and isinstance(item.get("model"), str)
            ),
            None,
        )
        if prior is None or following is None:
            continue
        changed = prior != following
        if boundary_key in model_change_generations and not changed:
            conflicts += 1
            continue
        model_covered += 1
        model_changed += changed
    model_coverage = _basis_points(model_covered, boundary_total)
    model_change_rate = _basis_points(model_changed, model_covered)

    contribution = build_coverage_contribution(
        "context-management-profile",
        {"context-lifecycle": (reliable_sessions, session_count)},
        missing_ambiguous={
            "missing-marker": session_count - reliable_sessions,
            "conflicting-evidence": conflicts,
        },
    )

    local = {
        "fresh_session_rate": _local_value(fresh_rate, start_coverage),
        "resume_rate": _local_value(resume_rate, start_coverage),
        "clear_rate": _local_value(clear_rate, clear_coverage),
        "manual_compactions": _local_value(manual_count, compaction_coverage),
        "automatic_compactions": _local_value(automatic_count, compaction_coverage),
        "generations_per_episode": _local_value(generation_distribution, episode_coverage),
        "one_context_episode_rate": _local_value(one_context_rate, episode_coverage),
        "fresh_phase_split": _local_value(fresh_phase_split, fresh_phase_coverage),
        "model_change_boundary_rate": _local_value(model_change_rate, model_coverage),
    }

    def common(coverage: int | str) -> dict:
        return {
            "coverage_band": _share_band(coverage, share_bands),
            "confidence": _confidence(coverage),
            "definition_version": CONTEXT_DEFINITION_VERSION,
            "trust_tier": "ANCHORED",
        }

    publishable: dict[str, dict] = {}
    for registry_id, value, numerator_support in (
        (FRESH_SESSION_RATE_ID, fresh_rate, known_start_count),
        (RESUME_RATE_ID, resume_rate, known_start_count),
        (CLEAR_RATE_ID, clear_rate, known_generation_triggers),
        (ONE_CONTEXT_EPISODE_RATE_ID, one_context_rate, len(generation_counts)),
        (MODEL_CHANGE_BOUNDARY_RATE_ID, model_change_rate, model_covered),
    ):
        support = next(iter(registry.min_support(registry_id).values()))
        if value != "UNKNOWN" and numerator_support >= support:
            coverage = {
                FRESH_SESSION_RATE_ID: start_coverage,
                RESUME_RATE_ID: start_coverage,
                CLEAR_RATE_ID: clear_coverage,
                ONE_CONTEXT_EPISODE_RATE_ID: episode_coverage,
                MODEL_CHANGE_BOUNDARY_RATE_ID: model_coverage,
            }[registry_id]
            publishable[registry_id] = _claim_output(
                registry,
                entries[registry_id],
                {"rate_band": _share_band(value, share_bands), **common(coverage)},
            )

    if (
        compaction_counts_known
        and lifecycle_event_total >= registry.min_support(MANUAL_COMPACTIONS_ID)["events"]
    ):
        for registry_id, value in (
            (MANUAL_COMPACTIONS_ID, manual_count),
            (AUTOMATIC_COMPACTIONS_ID, automatic_count),
        ):
            assert type(value) is int
            publishable[registry_id] = _claim_output(
                registry,
                entries[registry_id],
                {"count_band": _count_band(value, count_bands), **common(compaction_coverage)},
            )

    if len(generation_counts) >= registry.min_support(GENERATIONS_PER_EPISODE_ID)["episodes"]:
        distribution_counts = Counter(
            _count_band(value, count_bands) for value in generation_counts
        )
        publishable[GENERATIONS_PER_EPISODE_ID] = _claim_output(
            registry,
            entries[GENERATIONS_PER_EPISODE_ID],
            {
                "cells": [
                    {
                        "generation_count_band": band,
                        "episode_share_band": _share_band(
                            _basis_points(distribution_counts[band], len(generation_counts)),
                            share_bands,
                        ),
                    }
                    for band in count_bands
                    if distribution_counts[band]
                ],
                **common(episode_coverage),
            },
        )

    if len(fresh_sessions) >= registry.min_support(FRESH_PHASE_SPLIT_ID)["sessions"]:
        publishable[FRESH_PHASE_SPLIT_ID] = _claim_output(
            registry,
            entries[FRESH_PHASE_SPLIT_ID],
            {
                "cells": [
                    {
                        "phase_group": category,
                        "share_band": _share_band(
                            _basis_points(phase_categories[category], len(fresh_sessions)),
                            share_bands,
                        ),
                    }
                    for category in ("IMPLEMENTATION", "PLAN", "UNKNOWN")
                ],
                "classifier_version": WORKFLOW_PHASE_CLASSIFIER_VERSION,
                **common(fresh_phase_coverage),
            },
        )

    section = {
        "schema_version": CONTEXT_MANAGEMENT_SCHEMA_VERSION,
        "kind": "context-management-profile",
        "scorer_version": CONTEXT_MANAGEMENT_SCORER_VERSION,
        "context_identity_version": CONTEXT_IDENTITY_VERSION,
        "coverage_contribution": contribution,
        "local": local,
        "publishable": dict(sorted(publishable.items())),
    }
    errors = sorted(
        load_validator("context_management_profile.schema.json").iter_errors(section), key=str
    )
    if errors:
        raise ContextManagementScoringError("context-management section failed schema validation")
    return section


__all__ = [
    "AUTOMATIC_COMPACTIONS_ID",
    "CLEAR_RATE_ID",
    "CONTEXT_MANAGEMENT_REGISTRY_IDS",
    "CONTEXT_MANAGEMENT_SCHEMA_VERSION",
    "CONTEXT_MANAGEMENT_SCORER_VERSION",
    "ContextManagementScoringError",
    "FRESH_PHASE_SPLIT_ID",
    "FRESH_SESSION_RATE_ID",
    "GENERATIONS_PER_EPISODE_ID",
    "MANUAL_COMPACTIONS_ID",
    "MODEL_CHANGE_BOUNDARY_RATE_ID",
    "ONE_CONTEXT_EPISODE_RATE_ID",
    "RESUME_RATE_ID",
    "score_context_management",
]
