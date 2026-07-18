"""Deterministic workflow-map aggregates over episode-bound structural events.

The scorer accepts the explicit MYB-10.4 episode identity projection and its
normalized structural events.  Episode/session identifiers are used only as
private grouping keys and are never copied into either output form.  Ordered
streams remain in memory; the local form contains exact corpus aggregates and
the publishable form contains only support-qualified bands and totals admitted
by THREAT_MODEL section 3.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence

from mybench.normalizer.workflow_phase import (
    WORKFLOW_PHASE_CLASSIFIER_VERSION,
    WorkflowPhase,
    classify_workflow_phases,
)
from mybench.registry import Registry, RegistryError
from mybench.schemas import load_validator

WORKFLOW_MAP_SCHEMA_VERSION = "1"
WORKFLOW_MAP_SCORER_VERSION = "1.0.0"
EPISODE_STITCHER_VERSION = "2.0.0"
MODEL_VOCABULARY_VERSION = "1.0.0"

RECURRING_SEQUENCES_ID = "fingerprint.summary.recurring_sequences"
TASK_EPISODE_TOTAL_ID = "fingerprint.summary.task_episode_total"
TRANSITION_SHARES_ID = "fingerprint.workflow_map.transition_shares.band"
AUTHORSHIP_SHARES_ID = "fingerprint.workflow_map.authorship_shares.band"
MODEL_ROUTING_ID = "fingerprint.workflow_map.model_routing.band"
REWORK_LOOP_RATE_ID = "fingerprint.workflow_map.rework_loop_rate.band"
CONTEXT_BOUNDARY_RATE_ID = "fingerprint.workflow_map.context_boundary_rate.band"
UNKNOWN_PHASE_SHARE_ID = "fingerprint.workflow_map.unknown_phase_share"

WORKFLOW_MAP_REGISTRY_IDS = (
    RECURRING_SEQUENCES_ID,
    TASK_EPISODE_TOTAL_ID,
    TRANSITION_SHARES_ID,
    AUTHORSHIP_SHARES_ID,
    MODEL_ROUTING_ID,
    REWORK_LOOP_RATE_ID,
    CONTEXT_BOUNDARY_RATE_ID,
    UNKNOWN_PHASE_SHARE_ID,
)

_EPISODE_ID = re.compile(r"ep-[0-9a-f]{32}\Z")
_KNOWN_PHASES = ("TASK", "PLAN", "BUILD", "TEST", "DEBUG", "REVIEW", "COMMIT")
_KNOWN_PHASE_SET = frozenset(_KNOWN_PHASES)
_REWORK_EDGES = frozenset(
    {
        ("BUILD", "PLAN"),
        ("TEST", "PLAN"),
        ("TEST", "BUILD"),
        ("DEBUG", "PLAN"),
        ("DEBUG", "BUILD"),
    }
)


class WorkflowMapScoringError(ValueError):
    """The registry contract or private structural input is invalid."""


def _basis_points(numerator: int, denominator: int) -> int | str:
    if denominator == 0:
        return "UNKNOWN"
    if numerator < 0 or numerator > denominator:
        raise WorkflowMapScoringError("workflow-map rate input is invalid")
    return min(10000, (10000 * numerator + denominator // 2) // denominator)


def _share_band(value: int | str, bands: Sequence[str]) -> str:
    if len(bands) != 6 or bands[-1] != "UNKNOWN":
        raise WorkflowMapScoringError("workflow-map share-band contract is invalid")
    if value == "UNKNOWN":
        return bands[-1]
    if type(value) is not int or value < 0 or value > 10000:
        raise WorkflowMapScoringError("workflow-map basis-point value is invalid")
    if value < 1000:
        return bands[0]
    if value < 2500:
        return bands[1]
    if value < 5000:
        return bands[2]
    if value < 7500:
        return bands[3]
    return bands[4]


def _confidence(value: int | str, bands: Sequence[str]) -> str:
    if len(bands) != 4 or bands[-1] != "UNKNOWN":
        raise WorkflowMapScoringError("workflow-map confidence contract is invalid")
    if value == "UNKNOWN":
        return bands[-1]
    if value < 5000:
        return bands[0]
    if value < 7500:
        return bands[1]
    return bands[2]


def _model_route(raw: object) -> str:
    """Reduce a normalized model string to the pinned public vocabulary."""

    if not isinstance(raw, str) or not raw:
        return "UNKNOWN"
    lowered = raw.casefold()
    if lowered.startswith("synthetic-"):
        return "synthetic"
    if lowered.startswith("gpt-5-codex") or lowered == "codex":
        return "gpt-5-codex"
    if lowered == "gpt-5" or lowered.startswith("gpt-5-"):
        return "gpt-5"
    if re.fullmatch(r"o[1-9](?:-[a-z0-9._-]+)?", lowered):
        return "o-series"
    if "sonnet" in lowered:
        return "claude-sonnet"
    if "opus" in lowered:
        return "claude-opus"
    if "haiku" in lowered:
        return "claude-haiku"
    return "other"


def _authorship(value: object) -> str:
    if value == "human-turn":
        return "HUMAN"
    if value == "agent-turn":
        return "AGENT"
    return "UNKNOWN"


def _bands(entry: dict, field: str) -> tuple[str, ...]:
    for definition in entry["band_definitions"]:
        if definition["field"] == field:
            return tuple(definition["bands"])
    raise WorkflowMapScoringError("workflow-map registry contract is incomplete")


def _registry_contract(
    registry: Registry,
) -> tuple[dict[str, dict], int, tuple[str, ...], tuple[str, ...]]:
    entries = {
        registry_id: registry.entry(registry_id) for registry_id in WORKFLOW_MAP_REGISTRY_IDS
    }
    for entry in entries.values():
        if entry["status"] != "active" or entry["class"] != "measured":
            raise WorkflowMapScoringError("workflow-map descriptor is not active")
    expected_support = {
        RECURRING_SEQUENCES_ID: {"episodes": 5},
        TASK_EPISODE_TOTAL_ID: {"episodes": 5},
        TRANSITION_SHARES_ID: {"transitions": 5},
        AUTHORSHIP_SHARES_ID: {"events": 5},
        MODEL_ROUTING_ID: {"events": 5},
        REWORK_LOOP_RATE_ID: {"episodes": 5},
        CONTEXT_BOUNDARY_RATE_ID: {"transitions": 5},
        UNKNOWN_PHASE_SHARE_ID: {"events": 5},
    }
    for registry_id, support in expected_support.items():
        if registry.min_support(registry_id) != support:
            raise WorkflowMapScoringError("workflow-map support contract is invalid")
    try:
        floor = entries[RECURRING_SEQUENCES_ID]["output_schema"]["properties"][
            "k_suppression_floor"
        ]["const"]
    except (KeyError, TypeError):
        raise WorkflowMapScoringError("workflow-map k-suppression contract is invalid") from None
    if type(floor) is not int or floor < 5:
        raise WorkflowMapScoringError("workflow-map k-suppression contract is invalid")
    share_bands = _bands(entries[RECURRING_SEQUENCES_ID], "share_band")
    share_fields = {
        TRANSITION_SHARES_ID: "share_band",
        AUTHORSHIP_SHARES_ID: "share_band",
        MODEL_ROUTING_ID: "share_band",
        REWORK_LOOP_RATE_ID: "rate_band",
        CONTEXT_BOUNDARY_RATE_ID: "rate_band",
        UNKNOWN_PHASE_SHARE_ID: "unknown_phase_share",
    }
    if any(
        _bands(entries[registry_id], field) != share_bands
        for registry_id, field in share_fields.items()
    ):
        raise WorkflowMapScoringError("workflow-map share-band contracts disagree")
    confidence_bands = _bands(entries[UNKNOWN_PHASE_SHARE_ID], "graph_confidence")
    # Validate shape now so a malformed registry cannot reach a partial score.
    _share_band("UNKNOWN", share_bands)
    _confidence("UNKNOWN", confidence_bands)
    return entries, floor, share_bands, confidence_bands


def _episode_ids(episodes: Sequence[Mapping[str, object]]) -> tuple[str, ...]:
    if isinstance(episodes, (str, bytes)) or not isinstance(episodes, Sequence):
        raise WorkflowMapScoringError("episode identities must be an explicit sequence")
    values: list[str] = []
    for episode in episodes:
        if not isinstance(episode, Mapping):
            raise WorkflowMapScoringError("episode identity input has the wrong type")
        value = episode.get("task_episode_id")
        if not isinstance(value, str) or _EPISODE_ID.fullmatch(value) is None:
            raise WorkflowMapScoringError("episode identity does not match the normalized schema")
        values.append(value)
    if len(values) != len(set(values)):
        raise WorkflowMapScoringError("episode identities must be unique")
    return tuple(values)


def _group_events(
    events: Sequence[Mapping[str, object]], episode_ids: tuple[str, ...]
) -> dict[str, list[Mapping[str, object]]]:
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise WorkflowMapScoringError("workflow-map events must be an explicit sequence")
    groups = {episode_id: [] for episode_id in episode_ids}
    for event in events:
        if not isinstance(event, Mapping):
            raise WorkflowMapScoringError("workflow-map event input has the wrong type")
        episode_id = event.get("task_episode_id")
        if not isinstance(episode_id, str) or episode_id not in groups:
            # This scorer deliberately accepts only the episode-bound projection.
            # Refusing an unbound row prevents a silently inflated/deflated badge total.
            raise WorkflowMapScoringError("workflow-map event lacks a declared episode identity")
        groups[episode_id].append(event)
    return groups


def _strict_segments(phases: Sequence[WorkflowPhase]) -> tuple[tuple[str, ...], ...]:
    segments: list[tuple[str, ...]] = []
    current: list[str] = []
    for item in phases:
        if item.phase == "UNKNOWN":
            if current:
                segments.append(tuple(current))
                current = []
            continue
        if not current or current[-1] != item.phase:
            current.append(item.phase)
    if current:
        segments.append(tuple(current))
    return tuple(segments)


def _context_counts(
    events: Sequence[Mapping[str, object]], phases: Sequence[WorkflowPhase]
) -> tuple[int, int]:
    """Count known phase adjacencies and those crossing observed contexts.

    Context/model carrier rows are annotations rather than workflow phases for
    this one rate.  Any other UNKNOWN row breaks adjacency without bridging.
    A context marker without its observed generation also breaks adjacency.
    """

    generations: dict[object, int] = defaultdict(int)
    previous: tuple[str, object, int] | None = None
    crossings = 0
    known_transitions = 0
    fallback_session = object()
    for event, phase in zip(events, phases, strict=True):
        session = event.get("session_id", fallback_session)
        if (
            event.get("event_kind") == "lifecycle"
            and event.get("lifecycle_marker") == "context-boundary"
        ):
            generation = event.get("context_generation_id")
            if type(generation) is not int or generation < 0:
                previous = None
            else:
                generations[session] = generation
            continue
        if event.get("event_kind") == "model":
            continue
        if phase.phase == "UNKNOWN":
            previous = None
            continue
        current = (phase.phase, session, generations[session])
        if previous is not None and previous[0] != current[0]:
            known_transitions += 1
            if previous[1:] != current[1:]:
                crossings += 1
        previous = current
    return crossings, known_transitions


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
        raise WorkflowMapScoringError("workflow-map output failed registry conformance") from exc
    return output


def score_workflow_map(
    events: Sequence[Mapping[str, object]],
    *,
    episodes: Sequence[Mapping[str, object]],
    episode_stitcher_version: str,
    registry: Registry | None = None,
) -> dict | None:
    """Return exact local aggregates and support-qualified publishable atoms.

    ``events`` must be the canonical-order, episode-bound projection of a
    normalized corpus.  ``episodes`` is its explicit manifest identity list;
    counting distinct valid manifest ids, rather than sessions or inferred
    boundaries, is the source for ``task_episode_total``.
    """

    if episode_stitcher_version != EPISODE_STITCHER_VERSION:
        raise WorkflowMapScoringError("episode stitcher version is unsupported")
    registry = registry or Registry.load()
    entries, floor, share_bands, confidence_bands = _registry_contract(registry)
    identities = _episode_ids(episodes)
    if len(identities) < registry.min_support(TASK_EPISODE_TOTAL_ID)["episodes"]:
        return None
    grouped = _group_events(events, identities)

    transition_counts: Counter[tuple[str, str]] = Counter()
    authorship_counts: Counter[tuple[str, str]] = Counter()
    authorship_totals: Counter[str] = Counter()
    model_counts: Counter[tuple[str, str]] = Counter()
    model_totals: Counter[str] = Counter()
    recurring_support: Counter[tuple[str, ...]] = Counter()
    phase_total = 0
    unknown_total = 0
    episodes_with_events = 0
    rework_episodes = 0
    context_crossings = 0
    context_transitions = 0

    for episode_id in identities:
        episode_events = grouped[episode_id]
        phases = classify_workflow_phases(episode_events)
        if episode_events:
            episodes_with_events += 1
        phase_total += len(phases)
        unknown_total += sum(item.phase == "UNKNOWN" for item in phases)

        model_by_session: dict[object, str] = {}
        fallback_session = object()
        for event, phase in zip(episode_events, phases, strict=True):
            session = event.get("session_id", fallback_session)
            if event.get("event_kind") == "model":
                model_by_session[session] = _model_route(event.get("model"))
            if phase.phase not in _KNOWN_PHASE_SET:
                continue
            authorship = _authorship(event.get("authorship"))
            authorship_counts[(phase.phase, authorship)] += 1
            authorship_totals[phase.phase] += 1
            route = model_by_session.get(session, "UNKNOWN")
            model_counts[(phase.phase, route)] += 1
            model_totals[phase.phase] += 1

        segments = _strict_segments(phases)
        episode_edges: set[tuple[str, str]] = set()
        episode_ngrams: set[tuple[str, ...]] = set()
        for segment in segments:
            for edge in zip(segment, segment[1:]):
                transition_counts[edge] += 1
                episode_edges.add(edge)
            for size in range(2, min(5, len(segment)) + 1):
                episode_ngrams.update(
                    tuple(segment[start : start + size]) for start in range(len(segment) - size + 1)
                )
        recurring_support.update(episode_ngrams)
        if episode_edges & _REWORK_EDGES:
            rework_episodes += 1
        crossings, transitions = _context_counts(episode_events, phases)
        context_crossings += crossings
        context_transitions += transitions

    outgoing_counts: Counter[str] = Counter()
    for (from_phase, _to_phase), count in transition_counts.items():
        outgoing_counts[from_phase] += count

    phase_coverage = _basis_points(phase_total - unknown_total, phase_total)
    episode_event_coverage = _basis_points(episodes_with_events, len(identities))
    if phase_coverage == "UNKNOWN" or episode_event_coverage == "UNKNOWN":
        graph_coverage: int | str = "UNKNOWN"
    else:
        graph_coverage = min(phase_coverage, episode_event_coverage)

    supported_sequences = sorted(
        (
            (sequence, support)
            for sequence, support in recurring_support.items()
            if support >= floor
        ),
        key=lambda item: (-item[1], item[0]),
    )[:5]
    local = {
        "task_episode_total": len(identities),
        "episode_stitcher_version": EPISODE_STITCHER_VERSION,
        "episodes_with_events": episodes_with_events,
        "transition_counts": [
            {"from_phase": edge[0], "to_phase": edge[1], "count": count}
            for edge, count in sorted(transition_counts.items())
        ],
        "authorship_shares_basis_points": [
            {
                "phase": phase,
                "authorship": authorship,
                "basis_points": _basis_points(count, authorship_totals[phase]),
            }
            for (phase, authorship), count in sorted(authorship_counts.items())
        ],
        "model_routing_basis_points": [
            {
                "phase": phase,
                "model": model,
                "basis_points": _basis_points(count, model_totals[phase]),
            }
            for (phase, model), count in sorted(model_counts.items())
        ],
        "rework_loop_rate_basis_points": _basis_points(rework_episodes, len(identities)),
        "context_boundary_rate_basis_points": _basis_points(context_crossings, context_transitions),
        "unknown_phase_share_basis_points": _basis_points(unknown_total, phase_total),
        "graph_coverage_basis_points": graph_coverage,
        "recurring_sequences": [
            {
                "sequence": list(sequence),
                "supporting_episodes": support,
                "eligible_episodes": len(identities),
            }
            for sequence, support in supported_sequences
        ],
    }

    publishable: dict[str, dict] = {}
    publishable[TASK_EPISODE_TOTAL_ID] = _claim_output(
        registry,
        entries[TASK_EPISODE_TOTAL_ID],
        {
            "task_episode_total": len(identities),
            "episode_stitcher_version": EPISODE_STITCHER_VERSION,
            "trust_tier": "ANCHORED",
        },
    )
    publishable[REWORK_LOOP_RATE_ID] = _claim_output(
        registry,
        entries[REWORK_LOOP_RATE_ID],
        {
            "rate_band": _share_band(_basis_points(rework_episodes, len(identities)), share_bands),
            "definition_version": "1.0.0",
            "trust_tier": "ANCHORED",
        },
    )
    if phase_total >= registry.min_support(UNKNOWN_PHASE_SHARE_ID)["events"]:
        publishable[UNKNOWN_PHASE_SHARE_ID] = _claim_output(
            registry,
            entries[UNKNOWN_PHASE_SHARE_ID],
            {
                "unknown_phase_share": _share_band(
                    _basis_points(unknown_total, phase_total), share_bands
                ),
                "graph_confidence": _confidence(graph_coverage, confidence_bands),
                "classifier_version": WORKFLOW_PHASE_CLASSIFIER_VERSION,
                "trust_tier": "ANCHORED",
            },
        )

    if supported_sequences:
        publishable[RECURRING_SEQUENCES_ID] = _claim_output(
            registry,
            entries[RECURRING_SEQUENCES_ID],
            {
                "sequences": [
                    {
                        "sequence": list(sequence),
                        "share_band": _share_band(
                            _basis_points(support, len(identities)), share_bands
                        ),
                    }
                    for sequence, support in supported_sequences
                ],
                "classifier_version": WORKFLOW_PHASE_CLASSIFIER_VERSION,
                "k_suppression_floor": floor,
                "trust_tier": "ANCHORED",
            },
        )

    transition_cells = [
        {
            "from_phase": edge[0],
            "to_phase": edge[1],
            "share_band": _share_band(_basis_points(count, outgoing_counts[edge[0]]), share_bands),
        }
        for edge, count in sorted(transition_counts.items())
        if count >= registry.min_support(TRANSITION_SHARES_ID)["transitions"]
    ]
    if transition_cells:
        publishable[TRANSITION_SHARES_ID] = _claim_output(
            registry,
            entries[TRANSITION_SHARES_ID],
            {
                "cells": transition_cells,
                "classifier_version": WORKFLOW_PHASE_CLASSIFIER_VERSION,
                "cell_support_floor": floor,
                "trust_tier": "ANCHORED",
            },
        )

    authorship_cells = [
        {
            "phase": phase,
            "authorship": authorship,
            "share_band": _share_band(_basis_points(count, authorship_totals[phase]), share_bands),
        }
        for (phase, authorship), count in sorted(authorship_counts.items())
        if count >= registry.min_support(AUTHORSHIP_SHARES_ID)["events"]
    ]
    if authorship_cells:
        publishable[AUTHORSHIP_SHARES_ID] = _claim_output(
            registry,
            entries[AUTHORSHIP_SHARES_ID],
            {
                "cells": authorship_cells,
                "authorship_policy_version": "1.0.0",
                "cell_support_floor": floor,
                "trust_tier": "ANCHORED",
            },
        )

    model_cells = [
        {
            "phase": phase,
            "model": model,
            "share_band": _share_band(_basis_points(count, model_totals[phase]), share_bands),
        }
        for (phase, model), count in sorted(model_counts.items())
        if count >= registry.min_support(MODEL_ROUTING_ID)["events"]
    ]
    if model_cells:
        publishable[MODEL_ROUTING_ID] = _claim_output(
            registry,
            entries[MODEL_ROUTING_ID],
            {
                "cells": model_cells,
                "model_vocabulary_version": MODEL_VOCABULARY_VERSION,
                "cell_support_floor": floor,
                "trust_tier": "ANCHORED",
            },
        )

    if context_transitions >= registry.min_support(CONTEXT_BOUNDARY_RATE_ID)["transitions"]:
        publishable[CONTEXT_BOUNDARY_RATE_ID] = _claim_output(
            registry,
            entries[CONTEXT_BOUNDARY_RATE_ID],
            {
                "rate_band": _share_band(
                    _basis_points(context_crossings, context_transitions), share_bands
                ),
                "context_identity_version": "1.0.0",
                "trust_tier": "ANCHORED",
            },
        )

    section = {
        "schema_version": WORKFLOW_MAP_SCHEMA_VERSION,
        "kind": "workflow-map-section",
        "scorer_version": WORKFLOW_MAP_SCORER_VERSION,
        "classifier_version": WORKFLOW_PHASE_CLASSIFIER_VERSION,
        "local": local,
        "publishable": dict(sorted(publishable.items())),
    }
    errors = sorted(load_validator("workflow_map.schema.json").iter_errors(section), key=str)
    if errors:
        raise WorkflowMapScoringError("workflow-map section failed schema validation")
    return section


__all__ = [
    "AUTHORSHIP_SHARES_ID",
    "CONTEXT_BOUNDARY_RATE_ID",
    "MODEL_ROUTING_ID",
    "RECURRING_SEQUENCES_ID",
    "REWORK_LOOP_RATE_ID",
    "TASK_EPISODE_TOTAL_ID",
    "TRANSITION_SHARES_ID",
    "UNKNOWN_PHASE_SHARE_ID",
    "WORKFLOW_MAP_REGISTRY_IDS",
    "WORKFLOW_MAP_SCHEMA_VERSION",
    "WORKFLOW_MAP_SCORER_VERSION",
    "WorkflowMapScoringError",
    "score_workflow_map",
]
