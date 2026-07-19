"""Deterministic model/provider/effort role profile (MYB-13.5).

The scorer joins normalized metadata carrier events to the pinned workflow
phase classifier in memory.  Session identifiers are routing keys only and
never enter the output.  Missing metadata becomes an explicit ``UNKNOWN``
cell and reduces the adjacent evidence-quality rate; it is never imputed.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence

from mybench.normalizer.workflow_phase import (
    WORKFLOW_PHASE_CLASSIFIER_VERSION,
    classify_workflow_phases,
)
from mybench.registry import Registry, RegistryError
from mybench.schemas import load_validator
from mybench.scorer.evidence_coverage import (
    EvidenceCoverageError,
    basis_points,
    build_coverage_contribution,
    confidence,
)

MODEL_ROLE_SCHEMA_VERSION = "1"
MODEL_ROLE_SCORER_VERSION = "1.0.0"
ROLE_PHASE_TAXONOMY_VERSION = "1.0.0"
MODEL_VOCABULARY_VERSION = "1.0.0"
PROVIDER_VOCABULARY_VERSION = "1.0.0"
EFFORT_VOCABULARY_VERSION = "1.0.0"

MODEL_SHARES_EXACT_ID = "fingerprint.model_role.model_shares.exact"
MODEL_SHARES_BAND_ID = "fingerprint.model_role.model_shares.band"
PROVIDER_SHARES_EXACT_ID = "fingerprint.model_role.provider_shares.exact"
PROVIDER_SHARES_BAND_ID = "fingerprint.model_role.provider_shares.band"
EFFORT_SHARES_EXACT_ID = "fingerprint.model_role.effort_shares.exact"
EFFORT_SHARES_BAND_ID = "fingerprint.model_role.effort_shares.band"
EVIDENCE_QUALITY_ID = "fingerprint.model_role.evidence_quality"

MODEL_ROLE_REGISTRY_IDS = (
    MODEL_SHARES_EXACT_ID,
    MODEL_SHARES_BAND_ID,
    PROVIDER_SHARES_EXACT_ID,
    PROVIDER_SHARES_BAND_ID,
    EFFORT_SHARES_EXACT_ID,
    EFFORT_SHARES_BAND_ID,
    EVIDENCE_QUALITY_ID,
)

ROLE_PHASES = ("planning", "implementation", "debugging", "review", "unknown")
INPUT_CLASSES = ("model", "provider", "effort")

MODEL_VALUES = (
    "gpt-5",
    "gpt-5-codex",
    "o-series",
    "claude-sonnet",
    "claude-opus",
    "claude-haiku",
    "synthetic",
    "other",
    "UNKNOWN",
)
PROVIDER_VALUES = (
    "anthropic",
    "aws-bedrock",
    "google-vertex",
    "openai",
    "azure-openai",
    "synthetic",
    "other",
    "UNKNOWN",
)
EFFORT_VALUES = ("low", "medium", "high", "max", "UNKNOWN")

TRUST_BASIS = "signatures-commitments-and-timestamps-only"
PROVIDER_SEMANTICS = "operational-metadata-only"

_CARRIER_KINDS = frozenset({"model", "token-usage", "lifecycle"})
_PROVIDERS = frozenset(PROVIDER_VALUES[:-2])
_EFFORT_MAP = {
    "none": "low",
    "minimal": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "max": "max",
    "xhigh": "max",
}
_PHASE_MAP = {
    "TASK": "planning",
    "PLAN": "planning",
    "BUILD": "implementation",
    "TEST": "implementation",
    "COMMIT": "implementation",
    "DEBUG": "debugging",
    "REVIEW": "review",
    "UNKNOWN": "unknown",
}


class ModelRoleScoringError(ValueError):
    """The registry contract or private normalized input is invalid."""


def _model_value(raw: object) -> str:
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


def _provider_value(raw: object) -> str:
    if not isinstance(raw, str) or not raw:
        return "UNKNOWN"
    lowered = raw.casefold()
    return lowered if lowered in _PROVIDERS else "other"


def _effort_value(raw: object) -> str:
    if not isinstance(raw, str) or not raw:
        return "UNKNOWN"
    return _EFFORT_MAP.get(raw.casefold(), "UNKNOWN")


def _bands(entry: dict, field: str) -> tuple[str, ...]:
    for definition in entry["band_definitions"]:
        if definition["field"] == field:
            return tuple(definition["bands"])
    raise ModelRoleScoringError("model-role registry contract is incomplete")


def _share_band(value: int | str, bands: Sequence[str]) -> str:
    if len(bands) != 6 or bands[-1] != "UNKNOWN":
        raise ModelRoleScoringError("model-role share-band contract is invalid")
    if value == "UNKNOWN":
        return bands[-1]
    if type(value) is not int or not 0 <= value <= 10000:
        raise ModelRoleScoringError("model-role basis-point value is invalid")
    if value < 1000:
        return bands[0]
    if value < 2500:
        return bands[1]
    if value < 5000:
        return bands[2]
    if value < 7500:
        return bands[3]
    return bands[4]


def _evidence_state(rate: int | str) -> str:
    if rate == "UNKNOWN":
        return "unknown"
    return "available" if rate == 10000 else "partial"


def _registry_contract(registry: Registry) -> tuple[dict[str, dict], tuple[str, ...]]:
    entries = {registry_id: registry.entry(registry_id) for registry_id in MODEL_ROLE_REGISTRY_IDS}
    for registry_id, entry in entries.items():
        if entry["status"] != "active" or entry["class"] != "measured":
            raise ModelRoleScoringError("model-role descriptor is not active")
        if registry.min_support(registry_id) != {"events": 5}:
            raise ModelRoleScoringError("model-role support contract is invalid")

    share_bands = _bands(entries[MODEL_SHARES_BAND_ID], "share_band")
    if any(
        _bands(entries[registry_id], "share_band") != share_bands
        for registry_id in (PROVIDER_SHARES_BAND_ID, EFFORT_SHARES_BAND_ID)
    ):
        raise ModelRoleScoringError("model-role share-band contracts disagree")
    if _bands(entries[EVIDENCE_QUALITY_ID], "coverage_band") != share_bands:
        raise ModelRoleScoringError("model-role coverage-band contract disagrees")
    if _bands(entries[EVIDENCE_QUALITY_ID], "confidence") != (
        "LOW",
        "MEDIUM",
        "HIGH",
        "UNKNOWN",
    ):
        raise ModelRoleScoringError("model-role confidence contract is invalid")
    if _bands(entries[EVIDENCE_QUALITY_ID], "evidence_state") != (
        "available",
        "partial",
        "unknown",
    ):
        raise ModelRoleScoringError("model-role evidence-state contract is invalid")
    _share_band("UNKNOWN", share_bands)
    return entries, share_bands


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
        raise ModelRoleScoringError("model-role output failed registry conformance") from exc
    return output


def _dimension_value(input_class: str, state: Mapping[str, object]) -> str:
    value = state[input_class]
    if not isinstance(value, str):
        raise ModelRoleScoringError("model-role metadata state is invalid")
    return value


def score_model_role_profile(
    events: Sequence[Mapping[str, object]],
    *,
    registry: Registry | None = None,
) -> dict:
    """Return a closed local profile plus support-qualified registry outputs.

    Metadata carrier rows update the latest observed fields for their session
    but are not counted as workflow activity.  All other structural rows are
    eligible, including UNKNOWN-classified rows.  This makes missing metadata
    and unknown phases visible without copying any private grouping identity.
    """

    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise ModelRoleScoringError("model-role events must be an explicit sequence")
    for event in events:
        if not isinstance(event, Mapping):
            raise ModelRoleScoringError("model-role event input has the wrong type")
        if not isinstance(event.get("session_id"), str) or not event["session_id"]:
            raise ModelRoleScoringError("model-role event lacks a normalized session identity")

    registry = registry or Registry.load()
    entries, share_bands = _registry_contract(registry)
    try:
        phases = classify_workflow_phases(events)
    except Exception as exc:  # noqa: BLE001 - sanitize private input failures
        raise ModelRoleScoringError("model-role phase classification failed") from exc

    states: dict[str, dict[str, str]] = {}
    counts: Counter[tuple[str, str, str]] = Counter()
    totals: Counter[str] = Counter()
    covered: Counter[tuple[str, str]] = Counter()

    for event, classified in zip(events, phases, strict=True):
        session_id = event["session_id"]
        state = states.setdefault(
            session_id,
            {"model": "UNKNOWN", "provider": "UNKNOWN", "effort": "UNKNOWN"},
        )
        if event.get("event_kind") == "model":
            if "model" in event:
                state["model"] = _model_value(event.get("model"))
            if "provider" in event:
                state["provider"] = _provider_value(event.get("provider"))
            if "reasoning_effort" in event:
                state["effort"] = _effort_value(event.get("reasoning_effort"))
            continue
        if event.get("event_kind") in _CARRIER_KINDS:
            continue

        try:
            role_phase = _PHASE_MAP[classified.phase]
        except KeyError:
            raise ModelRoleScoringError("model-role phase taxonomy is invalid") from None
        totals[role_phase] += 1
        for input_class in INPUT_CLASSES:
            value = _dimension_value(input_class, state)
            counts[(role_phase, input_class, value)] += 1
            if value != "UNKNOWN":
                covered[(role_phase, input_class)] += 1

    quality: dict[tuple[str, str], dict[str, int | str]] = {}
    for role_phase in sorted(totals):
        for input_class in INPUT_CLASSES:
            try:
                rate = basis_points(covered[(role_phase, input_class)], totals[role_phase])
                quality[(role_phase, input_class)] = {
                    "coverage_basis_points": rate,
                    "confidence": confidence(rate),
                    "evidence_state": _evidence_state(rate),
                }
            except EvidenceCoverageError as exc:
                raise ModelRoleScoringError("model-role evidence quality is invalid") from exc

    local_cells = []
    for (role_phase, input_class, value), count in sorted(counts.items()):
        local_cells.append(
            {
                "phase": role_phase,
                "input_class": input_class,
                "value": value,
                "share_basis_points": basis_points(count, totals[role_phase]),
                "evidence_quality": quality[(role_phase, input_class)],
            }
        )

    phase_counts = [
        {"phase": role_phase, "eligible_events": totals[role_phase]}
        for role_phase in sorted(totals)
    ]

    dimension_contract = {
        "model": (
            MODEL_SHARES_EXACT_ID,
            MODEL_SHARES_BAND_ID,
            "model",
            MODEL_VOCABULARY_VERSION,
            "model_vocabulary_version",
        ),
        "provider": (
            PROVIDER_SHARES_EXACT_ID,
            PROVIDER_SHARES_BAND_ID,
            "provider",
            PROVIDER_VOCABULARY_VERSION,
            "provider_vocabulary_version",
        ),
        "effort": (
            EFFORT_SHARES_EXACT_ID,
            EFFORT_SHARES_BAND_ID,
            "effort",
            EFFORT_VOCABULARY_VERSION,
            "effort_vocabulary_version",
        ),
    }
    local_registry_outputs: dict[str, dict] = {}
    publishable: dict[str, dict] = {}
    support_floor = 5
    for input_class in INPUT_CLASSES:
        exact_id, band_id, value_key, vocabulary_version, version_key = dimension_contract[
            input_class
        ]
        supported = [
            (role_phase, value, count)
            for (role_phase, dimension, value), count in sorted(counts.items())
            if dimension == input_class and count >= support_floor
        ]
        if not supported:
            continue
        exact_output = {
            "cells": [
                {
                    "phase": role_phase,
                    value_key: value,
                    "share_basis_points": basis_points(count, totals[role_phase]),
                }
                for role_phase, value, count in supported
            ],
            version_key: vocabulary_version,
            "role_phase_taxonomy_version": ROLE_PHASE_TAXONOMY_VERSION,
            "cell_support_floor": support_floor,
            "trust_tier": "ANCHORED",
        }
        local_registry_outputs[exact_id] = _claim_output(registry, entries[exact_id], exact_output)
        band_output = {
            "cells": [
                {
                    "phase": role_phase,
                    value_key: value,
                    "share_band": _share_band(basis_points(count, totals[role_phase]), share_bands),
                }
                for role_phase, value, count in supported
            ],
            version_key: vocabulary_version,
            "role_phase_taxonomy_version": ROLE_PHASE_TAXONOMY_VERSION,
            "cell_support_floor": support_floor,
            "trust_tier": "ANCHORED",
        }
        publishable[band_id] = _claim_output(registry, entries[band_id], band_output)

    quality_cells = []
    for (role_phase, input_class), item in sorted(quality.items()):
        if totals[role_phase] < support_floor:
            continue
        quality_cells.append(
            {
                "phase": role_phase,
                "input_class": input_class,
                "coverage_band": _share_band(item["coverage_basis_points"], share_bands),
                "confidence": item["confidence"],
                "evidence_state": item["evidence_state"],
            }
        )
    if quality_cells:
        quality_output = {
            "cells": quality_cells,
            "role_phase_taxonomy_version": ROLE_PHASE_TAXONOMY_VERSION,
            "cell_support_floor": support_floor,
            "trust_tier": "ANCHORED",
        }
        publishable[EVIDENCE_QUALITY_ID] = _claim_output(
            registry, entries[EVIDENCE_QUALITY_ID], quality_output
        )

    eligible_total = sum(totals.values())
    missing_model = eligible_total - sum(
        count for (role_phase, input_class), count in covered.items() if input_class == "model"
    )
    missing_effort = eligible_total - sum(
        count for (role_phase, input_class), count in covered.items() if input_class == "effort"
    )
    coverage_contribution = build_coverage_contribution(
        "model-role-profile",
        {
            "model": (eligible_total - missing_model, eligible_total),
            "effort": (eligible_total - missing_effort, eligible_total),
        },
        missing_ambiguous={
            "missing-model": missing_model,
            "missing-effort": missing_effort,
        },
    )

    section = {
        "schema_version": MODEL_ROLE_SCHEMA_VERSION,
        "kind": "model-role-profile-section",
        "scorer_version": MODEL_ROLE_SCORER_VERSION,
        "classifier_version": WORKFLOW_PHASE_CLASSIFIER_VERSION,
        "role_phase_taxonomy_version": ROLE_PHASE_TAXONOMY_VERSION,
        "trust_basis": TRUST_BASIS,
        "provider_semantics": PROVIDER_SEMANTICS,
        "local": {
            "eligible_event_count": eligible_total,
            "phase_counts": phase_counts,
            "distribution_cells": local_cells,
            "registry_outputs": dict(sorted(local_registry_outputs.items())),
        },
        "publishable": dict(sorted(publishable.items())),
        "coverage_contribution": coverage_contribution,
    }
    errors = sorted(load_validator("model_role_profile.schema.json").iter_errors(section), key=str)
    if errors:
        raise ModelRoleScoringError("model-role section failed schema validation")
    return section


__all__ = [
    "EFFORT_SHARES_BAND_ID",
    "EFFORT_SHARES_EXACT_ID",
    "EVIDENCE_QUALITY_ID",
    "MODEL_ROLE_REGISTRY_IDS",
    "MODEL_ROLE_SCHEMA_VERSION",
    "MODEL_ROLE_SCORER_VERSION",
    "MODEL_SHARES_BAND_ID",
    "MODEL_SHARES_EXACT_ID",
    "ModelRoleScoringError",
    "PROVIDER_SHARES_BAND_ID",
    "PROVIDER_SHARES_EXACT_ID",
    "score_model_role_profile",
]
