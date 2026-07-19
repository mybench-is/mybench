"""Deterministic token and public-list-price-equivalent profile (MYB-13.6).

The scorer consumes only explicit normalized structural inputs and one owned,
checksummed pricing snapshot.  Session and episode identifiers are private
grouping keys and never appear in output.  Unmapped SKUs, dates outside the
snapshot interval, and ambiguous billable dimensions produce ``UNKNOWN``.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date

from mybench.normalizer.workflow_phase import (
    WORKFLOW_PHASE_CLASSIFIER_VERSION,
    classify_workflow_phases,
)
from mybench.registry import Registry, RegistryError
from mybench.schemas import load_validator
from mybench.scorer.evidence_coverage import build_coverage_contribution
from mybench.scorer.pricing import PricingSnapshot

TOKEN_COST_SCHEMA_VERSION = "1"
TOKEN_COST_SCORER_VERSION = "1.0.0"
TOKEN_ACCOUNTING_POLICY_VERSION = "1.0.0"
REWORK_TOKEN_DEFINITION_VERSION = "1.0.0"
ABANDONED_TOKEN_DEFINITION_VERSION = "1.0.0"
MODEL_VOCABULARY_VERSION = "1.0.0"

TOKENS_BY_MODEL_ID = "fingerprint.token_cost.tokens_by_model.band"
TOKENS_BY_PHASE_ID = "fingerprint.token_cost.tokens_by_phase.band"
COST_BY_MODEL_ID = "fingerprint.token_cost.cost_by_model.exact"
COST_PER_EPISODE_ID = "fingerprint.token_cost.cost_per_episode.exact"
PLANNING_RATIO_ID = "fingerprint.token_cost.planning_to_implementation_ratio.band"
REWORK_TOKEN_SHARE_ID = "fingerprint.token_cost.rework_token_share"
ABANDONED_TOKEN_SHARE_ID = "fingerprint.token_cost.abandoned_session_token_share"

TOKEN_COST_REGISTRY_IDS = (
    TOKENS_BY_MODEL_ID,
    TOKENS_BY_PHASE_ID,
    COST_BY_MODEL_ID,
    COST_PER_EPISODE_ID,
    PLANNING_RATIO_ID,
    REWORK_TOKEN_SHARE_ID,
    ABANDONED_TOKEN_SHARE_ID,
)

_EPISODE_ID = re.compile(r"ep-[0-9a-f]{32}\Z")
_TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)
_KNOWN_PHASES = ("TASK", "PLAN", "BUILD", "TEST", "DEBUG", "REVIEW", "COMMIT")
_IMPLEMENTATION_PHASES = frozenset({"BUILD", "TEST", "DEBUG", "REVIEW", "COMMIT"})
_REWORK_EDGES = frozenset(
    {
        ("BUILD", "PLAN"),
        ("TEST", "PLAN"),
        ("TEST", "BUILD"),
        ("DEBUG", "PLAN"),
        ("DEBUG", "BUILD"),
    }
)
_CAVEATS = ["provider-reported-inflatable"]


class TokenCostScoringError(ValueError):
    """The registry, pricing snapshot, or normalized input is invalid."""


@dataclass(frozen=True)
class _Observation:
    session: str
    episode: str
    public_model: str
    priced_model: str
    phase: str
    token_count: int
    cost_micro_usd: int | str
    rework: bool


def _basis_points(numerator: int, denominator: int) -> int | str:
    if denominator == 0:
        return "UNKNOWN"
    if numerator < 0 or numerator > denominator:
        raise TokenCostScoringError("token-cost rate input is invalid")
    return min(10000, (10000 * numerator + denominator // 2) // denominator)


def _bands(entry: dict, field: str) -> tuple[str, ...]:
    for definition in entry["band_definitions"]:
        if definition["field"] == field:
            return tuple(definition["bands"])
    raise TokenCostScoringError("token-cost registry contract is incomplete")


def _token_band(value: int, bands: Sequence[str]) -> str:
    if type(value) is not int or value < 0 or len(bands) != 6:
        raise TokenCostScoringError("token-band input or contract is invalid")
    if value == 0:
        return bands[0]
    if value < 10_000:
        return bands[1]
    if value < 100_000:
        return bands[2]
    if value < 1_000_000:
        return bands[3]
    if value < 10_000_000:
        return bands[4]
    return bands[5]


def _cost_band(value: int, bands: Sequence[str]) -> str:
    if type(value) is not int or value < 0 or len(bands) != 6:
        raise TokenCostScoringError("cost-band input or contract is invalid")
    if value == 0:
        return bands[0]
    if value < 1_000_000:
        return bands[1]
    if value < 10_000_000:
        return bands[2]
    if value < 100_000_000:
        return bands[3]
    if value < 1_000_000_000:
        return bands[4]
    return bands[5]


def _share_band(value: int | str, bands: Sequence[str]) -> str:
    if len(bands) != 6 or bands[-1] != "UNKNOWN":
        raise TokenCostScoringError("share-band contract is invalid")
    if value == "UNKNOWN":
        return bands[-1]
    if type(value) is not int or value < 0 or value > 10000:
        raise TokenCostScoringError("share-band input is invalid")
    if value < 1000:
        return bands[0]
    if value < 2500:
        return bands[1]
    if value < 5000:
        return bands[2]
    if value < 7500:
        return bands[3]
    return bands[4]


def _ratio_band(numerator: int, denominator: int, bands: Sequence[str]) -> str:
    if len(bands) != 5 or bands[0] != "UNKNOWN" or numerator < 0 or denominator < 0:
        raise TokenCostScoringError("ratio-band input or contract is invalid")
    if denominator == 0:
        return bands[0]
    if 2 * numerator < denominator:
        return bands[1]
    if numerator < denominator:
        return bands[2]
    if numerator < 2 * denominator:
        return bands[3]
    return bands[4]


def _model_route(raw: object) -> str:
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


def _episode_contract(episodes: Sequence[Mapping[str, object]]) -> dict[str, str]:
    if isinstance(episodes, (str, bytes)) or not isinstance(episodes, Sequence):
        raise TokenCostScoringError("episode inputs must be an explicit sequence")
    result: dict[str, str] = {}
    for episode in episodes:
        if not isinstance(episode, Mapping):
            raise TokenCostScoringError("episode input has the wrong type")
        episode_id = episode.get("task_episode_id")
        outcome = episode.get("episode_outcome")
        if (
            not isinstance(episode_id, str)
            or _EPISODE_ID.fullmatch(episode_id) is None
            or outcome not in {"closed-with-bound-commit", "abandoned", "unknown"}
            or episode.get("outcome_classifier_version") != "1.0.0"
        ):
            raise TokenCostScoringError("episode input violates the normalized contract")
        if episode_id in result:
            raise TokenCostScoringError("episode identities must be unique")
        result[episode_id] = outcome
    return result


def _session_contract(
    sessions: Sequence[Mapping[str, object]], episodes: Mapping[str, str]
) -> dict[str, str]:
    if isinstance(sessions, (str, bytes)) or not isinstance(sessions, Sequence):
        raise TokenCostScoringError("session inputs must be an explicit sequence")
    result: dict[str, str] = {}
    for session in sessions:
        if not isinstance(session, Mapping):
            raise TokenCostScoringError("session input has the wrong type")
        session_id = session.get("session_id")
        episode_id = session.get("task_episode_id")
        if (
            not isinstance(session_id, str)
            or not session_id
            or not isinstance(episode_id, str)
            or episode_id not in episodes
        ):
            raise TokenCostScoringError("session input violates the normalized contract")
        if session_id in result:
            raise TokenCostScoringError("session identities must be unique")
        result[session_id] = episode_id
    return result


def _usage(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value or not set(value) <= set(_TOKEN_FIELDS):
        raise TokenCostScoringError("token usage violates the normalized contract")
    usage = {}
    for field, count in value.items():
        if type(count) is not int or count < 0:
            raise TokenCostScoringError("token usage violates the normalized contract")
        usage[field] = count
    return usage


def _observed_date(value: object) -> str | None:
    if not isinstance(value, str) or len(value) < 10:
        return None
    try:
        parsed = date.fromisoformat(value[:10])
    except ValueError:
        return None
    return parsed.isoformat() if value[:10] == parsed.isoformat() else None


def _matching_rate(
    snapshot: PricingSnapshot,
    *,
    provider: object,
    model: object,
    observed_on: str | None,
) -> dict | None:
    if not isinstance(provider, str) or not isinstance(model, str) or observed_on is None:
        return None
    matches = []
    for rate in snapshot.document()["rates"]:
        if provider != rate["provider"] or model.casefold() not in rate["aliases"]:
            continue
        if observed_on < rate["effective_from"]:
            continue
        if rate["effective_until"] is not None and observed_on > rate["effective_until"]:
            continue
        matches.append(rate)
    return matches[0] if len(matches) == 1 else None


def _price_usage(rate: dict | None, usage: Mapping[str, int]) -> int | str:
    if rate is None:
        return "UNKNOWN"
    input_tokens = usage.get("input_tokens", 0)
    output_tokens = usage.get("output_tokens", 0)
    cache_read = usage.get("cache_read_input_tokens", 0)
    cache_write = usage.get("cache_creation_input_tokens", 0)
    if rate["input_accounting"] == "includes-cache-read":
        if cache_read > input_tokens:
            return "UNKNOWN"
        input_tokens -= cache_read

    components = (
        (input_tokens, rate["input"]),
        (output_tokens, rate["output"]),
        (cache_read, rate["cache_read"]),
    )
    if any(tokens and price == "UNKNOWN" for tokens, price in components):
        return "UNKNOWN"
    numerator = sum(tokens * price for tokens, price in components if price != "UNKNOWN")
    if cache_write:
        five = rate["cache_write_5m"]
        hour = rate["cache_write_1h"]
        # The normalized v5 usage contract does not retain cache duration.
        # Equal rates are unambiguous; differing or unavailable rates are not.
        if five == "UNKNOWN" or hour == "UNKNOWN" or five != hour:
            return "UNKNOWN"
        numerator += cache_write * five
    return (numerator + 500_000) // 1_000_000


def _claim(registry: Registry, entry: dict, output: dict) -> dict:
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
        raise TokenCostScoringError("token-cost output failed registry conformance") from exc
    return output


def _registry_contract(registry: Registry) -> dict[str, dict]:
    entries = {registry_id: registry.entry(registry_id) for registry_id in TOKEN_COST_REGISTRY_IDS}
    if any(entry["status"] != "active" or entry["class"] != "measured" for entry in entries.values()):
        raise TokenCostScoringError("token-cost descriptor is not active")
    expected = {
        TOKENS_BY_MODEL_ID: {"sessions": 5},
        TOKENS_BY_PHASE_ID: {"sessions": 5},
        COST_BY_MODEL_ID: {"sessions": 5},
        COST_PER_EPISODE_ID: {"episodes": 5},
        PLANNING_RATIO_ID: {"episodes": 5},
        REWORK_TOKEN_SHARE_ID: {"episodes": 5},
        ABANDONED_TOKEN_SHARE_ID: {"sessions": 5},
    }
    if any(registry.min_support(key) != support for key, support in expected.items()):
        raise TokenCostScoringError("token-cost support contract is invalid")
    return entries


def score_token_cost_profile(
    events: Sequence[Mapping[str, object]],
    *,
    episodes: Sequence[Mapping[str, object]],
    sessions: Sequence[Mapping[str, object]],
    pricing_snapshot: PricingSnapshot,
    registry: Registry | None = None,
) -> dict:
    """Score token volume and standardized list-price equivalents locally."""

    if not isinstance(pricing_snapshot, PricingSnapshot):
        raise TokenCostScoringError("pricing snapshot must be an explicit owned input")
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise TokenCostScoringError("token-cost events must be an explicit sequence")
    registry = registry or Registry.load()
    entries = _registry_contract(registry)
    episode_outcomes = _episode_contract(episodes)
    session_episodes = _session_contract(sessions, episode_outcomes)
    if any(not isinstance(event, Mapping) for event in events):
        raise TokenCostScoringError("token-cost event input has the wrong type")
    phases = classify_workflow_phases(events)

    model_state: dict[str, tuple[object, object]] = {}
    phase_state: dict[str, str] = {}
    rework_state: dict[str, bool] = {}
    previous_phase: dict[str, str] = {}
    observations: list[_Observation] = []

    for event, classified in zip(events, phases, strict=True):
        session_id = event.get("session_id")
        episode_id = event.get("task_episode_id")
        if (
            not isinstance(session_id, str)
            or session_id not in session_episodes
            or episode_id != session_episodes[session_id]
        ):
            raise TokenCostScoringError("token-cost event lacks a declared normalized identity")
        if classified.phase in _KNOWN_PHASES:
            previous = previous_phase.get(episode_id)
            rework_state[session_id] = (previous, classified.phase) in _REWORK_EDGES
            previous_phase[episode_id] = classified.phase
            phase_state[session_id] = classified.phase
        if event.get("event_kind") == "model":
            model_state[session_id] = (event.get("provider"), event.get("model"))
            continue
        if event.get("event_kind") != "token-usage":
            continue

        usage = _usage(event.get("token_usage"))
        provider, model = model_state.get(session_id, (None, None))
        observed_on = _observed_date(event.get("observed_at"))
        rate = _matching_rate(
            pricing_snapshot,
            provider=provider,
            model=model,
            observed_on=observed_on,
        )
        observations.append(
            _Observation(
                session=session_id,
                episode=episode_id,
                public_model=_model_route(model),
                priced_model=rate["model_sku"] if rate is not None else "UNKNOWN",
                phase=phase_state.get(session_id, "UNKNOWN"),
                token_count=sum(usage.values()),
                cost_micro_usd=_price_usage(rate, usage),
                rework=rework_state.get(session_id, False),
            )
        )

    tokens_by_model: Counter[str] = Counter()
    model_sessions: defaultdict[str, set[str]] = defaultdict(set)
    tokens_by_phase: Counter[str] = Counter()
    phase_sessions: defaultdict[str, set[str]] = defaultdict(set)
    cost_by_model: Counter[str] = Counter()
    cost_model_unknown: set[str] = set()
    cost_model_sessions: defaultdict[str, set[str]] = defaultdict(set)
    episode_costs: Counter[str] = Counter()
    unknown_cost_episodes: set[str] = set()
    episode_tokens: Counter[str] = Counter()
    session_tokens: Counter[str] = Counter()
    planning_tokens: Counter[str] = Counter()
    implementation_tokens: Counter[str] = Counter()
    rework_tokens = 0
    phase_tokens = 0

    for item in observations:
        tokens_by_model[item.public_model] += item.token_count
        model_sessions[item.public_model].add(item.session)
        tokens_by_phase[item.phase] += item.token_count
        phase_sessions[item.phase].add(item.session)
        cost_model_sessions[item.priced_model].add(item.session)
        episode_tokens[item.episode] += item.token_count
        session_tokens[item.session] += item.token_count
        if item.cost_micro_usd == "UNKNOWN":
            cost_model_unknown.add(item.priced_model)
            unknown_cost_episodes.add(item.episode)
        else:
            cost_by_model[item.priced_model] += item.cost_micro_usd
            episode_costs[item.episode] += item.cost_micro_usd
        if item.phase == "PLAN":
            planning_tokens[item.episode] += item.token_count
        if item.phase in _IMPLEMENTATION_PHASES:
            implementation_tokens[item.episode] += item.token_count
        if item.phase != "UNKNOWN":
            phase_tokens += item.token_count
            if item.rework:
                rework_tokens += item.token_count

    covered_sessions = {item.session for item in observations}
    ratio_episodes = {
        episode_id
        for episode_id in episode_outcomes
        if planning_tokens[episode_id] > 0 and implementation_tokens[episode_id] > 0
    }
    phase_episodes = {item.episode for item in observations if item.phase != "UNKNOWN"}
    classified_sessions = {
        session_id
        for session_id, episode_id in session_episodes.items()
        if episode_outcomes[episode_id] != "unknown" and session_tokens[session_id] > 0
    }
    classified_tokens = sum(session_tokens[session_id] for session_id in classified_sessions)
    abandoned_tokens = sum(
        session_tokens[session_id]
        for session_id in classified_sessions
        if episode_outcomes[session_episodes[session_id]] == "abandoned"
    )

    token_bands = _bands(entries[TOKENS_BY_MODEL_ID], "token_band")
    share_bands = _bands(entries[REWORK_TOKEN_SHARE_ID], "share_band")
    publishable: dict[str, dict] = {}
    model_cells = [
        {"model": model, "token_band": _token_band(tokens_by_model[model], token_bands)}
        for model in sorted(tokens_by_model)
        if len(model_sessions[model]) >= registry.min_support(TOKENS_BY_MODEL_ID)["sessions"]
    ]
    if model_cells:
        publishable[TOKENS_BY_MODEL_ID] = _claim(
            registry,
            entries[TOKENS_BY_MODEL_ID],
            {
                "cells": model_cells,
                "model_vocabulary_version": MODEL_VOCABULARY_VERSION,
                "token_accounting_policy_version": TOKEN_ACCOUNTING_POLICY_VERSION,
                "trust_tier": "ANCHORED",
                "caveats": _CAVEATS,
            },
        )

    phase_cells = [
        {"phase": phase, "token_band": _token_band(tokens_by_phase[phase], token_bands)}
        for phase in sorted(tokens_by_phase)
        if len(phase_sessions[phase]) >= registry.min_support(TOKENS_BY_PHASE_ID)["sessions"]
    ]
    if phase_cells:
        publishable[TOKENS_BY_PHASE_ID] = _claim(
            registry,
            entries[TOKENS_BY_PHASE_ID],
            {
                "cells": phase_cells,
                "classifier_version": WORKFLOW_PHASE_CLASSIFIER_VERSION,
                "token_accounting_policy_version": TOKEN_ACCOUNTING_POLICY_VERSION,
                "trust_tier": "ANCHORED",
                "caveats": _CAVEATS,
            },
        )

    if len(ratio_episodes) >= registry.min_support(PLANNING_RATIO_ID)["episodes"]:
        planning_total = sum(planning_tokens[item] for item in ratio_episodes)
        implementation_total = sum(implementation_tokens[item] for item in ratio_episodes)
        publishable[PLANNING_RATIO_ID] = _claim(
            registry,
            entries[PLANNING_RATIO_ID],
            {
                "ratio_band": _ratio_band(
                    planning_total,
                    implementation_total,
                    _bands(entries[PLANNING_RATIO_ID], "ratio_band"),
                ),
                "classifier_version": WORKFLOW_PHASE_CLASSIFIER_VERSION,
                "trust_tier": "ANCHORED",
                "caveats": _CAVEATS,
            },
        )
    if len(phase_episodes) >= registry.min_support(REWORK_TOKEN_SHARE_ID)["episodes"]:
        publishable[REWORK_TOKEN_SHARE_ID] = _claim(
            registry,
            entries[REWORK_TOKEN_SHARE_ID],
            {
                "share_band": _share_band(_basis_points(rework_tokens, phase_tokens), share_bands),
                "definition_version": REWORK_TOKEN_DEFINITION_VERSION,
                "trust_tier": "ANCHORED",
                "caveats": _CAVEATS,
            },
        )
    if len(classified_sessions) >= registry.min_support(ABANDONED_TOKEN_SHARE_ID)["sessions"]:
        publishable[ABANDONED_TOKEN_SHARE_ID] = _claim(
            registry,
            entries[ABANDONED_TOKEN_SHARE_ID],
            {
                "share_band": _share_band(
                    _basis_points(abandoned_tokens, classified_tokens), share_bands
                ),
                "definition_version": ABANDONED_TOKEN_DEFINITION_VERSION,
                "trust_tier": "ANCHORED",
                "caveats": _CAVEATS,
            },
        )

    local_costs: dict[str, dict] = {}
    cost_cells = [
        {
            "model": model,
            "cost_micro_usd": (
                "UNKNOWN" if model in cost_model_unknown else cost_by_model[model]
            ),
        }
        for model in sorted(cost_model_sessions)
        if len(cost_model_sessions[model]) >= registry.min_support(COST_BY_MODEL_ID)["sessions"]
    ]
    pricing_doc = pricing_snapshot.document()
    pricing_fields = {
        "estimate_label": pricing_doc["estimate_label"],
        "pricing_snapshot_version": pricing_snapshot.version,
        "pricing_snapshot_digest": pricing_snapshot.digest,
        "currency": pricing_snapshot.currency,
        "rounding_rule": pricing_doc["rounding_rule"],
        "trust_tier": "ANCHORED",
        "caveats": _CAVEATS,
    }
    if cost_cells:
        local_costs[COST_BY_MODEL_ID] = _claim(
            registry,
            entries[COST_BY_MODEL_ID],
            {"cells": cost_cells, **pricing_fields},
        )

    if len(episode_tokens) >= registry.min_support(COST_PER_EPISODE_ID)["episodes"]:
        cost_bands = _bands(entries[COST_PER_EPISODE_ID], "cost_band")
        histogram = Counter(
            _cost_band(cost, cost_bands)
            for episode_id, cost in episode_costs.items()
            if episode_id not in unknown_cost_episodes
        )
        local_costs[COST_PER_EPISODE_ID] = _claim(
            registry,
            entries[COST_PER_EPISODE_ID],
            {
                "cells": [
                    {"cost_band": band, "episode_count": histogram[band]}
                    for band in cost_bands
                    if histogram[band]
                ],
                "unknown_episode_count": len(unknown_cost_episodes),
                **pricing_fields,
            },
        )

    missing = len(session_episodes) - len(covered_sessions)
    ambiguities = {
        "missing-token-data": missing,
        "unknown-phase": sum(item.phase == "UNKNOWN" for item in observations),
        "missing-model": sum(item.public_model == "UNKNOWN" for item in observations),
    }
    coverage = build_coverage_contribution(
        "token-cost-profile",
        {"token-data": (len(covered_sessions), len(session_episodes))},
        missing_ambiguous=ambiguities,
    )
    section = {
        "schema_version": TOKEN_COST_SCHEMA_VERSION,
        "kind": "token-cost-profile",
        "scorer_version": TOKEN_COST_SCORER_VERSION,
        "pricing_snapshot": pricing_snapshot.reference(),
        "local": {
            "tokens_by_model": [
                {"model": model, "tokens": tokens_by_model[model]}
                for model in sorted(tokens_by_model)
            ],
            "tokens_by_phase": [
                {"phase": phase, "tokens": tokens_by_phase[phase]}
                for phase in sorted(tokens_by_phase)
            ],
            "planning_tokens": sum(planning_tokens.values()),
            "implementation_tokens": sum(implementation_tokens.values()),
            "rework_token_share_basis_points": _basis_points(rework_tokens, phase_tokens),
            "abandoned_session_token_share_basis_points": _basis_points(
                abandoned_tokens, classified_tokens
            ),
            "pricing_unknown_observations": sum(
                item.cost_micro_usd == "UNKNOWN" for item in observations
            ),
            "cost_claims": dict(sorted(local_costs.items())),
            "caveats": _CAVEATS,
        },
        "publishable": dict(sorted(publishable.items())),
        "coverage": coverage,
    }
    errors = sorted(load_validator("token_cost_profile.schema.json").iter_errors(section), key=str)
    if errors:
        raise TokenCostScoringError("token-cost section failed schema validation")
    return section


__all__ = [
    "ABANDONED_TOKEN_SHARE_ID",
    "COST_BY_MODEL_ID",
    "COST_PER_EPISODE_ID",
    "PLANNING_RATIO_ID",
    "REWORK_TOKEN_SHARE_ID",
    "TOKENS_BY_MODEL_ID",
    "TOKENS_BY_PHASE_ID",
    "TOKEN_COST_REGISTRY_IDS",
    "TOKEN_COST_SCHEMA_VERSION",
    "TOKEN_COST_SCORER_VERSION",
    "TokenCostScoringError",
    "score_token_cost_profile",
]
