"""Private orchestration/delegation distributions over normalized v5 structure.

The scorer consumes only the closed session-lineage markers and normalized
event timestamps already admitted to A8. Opaque session identities are used as
in-memory graph keys and never enter the result. The four outputs are exact,
local-report-only aggregates; this module does not implement the separately
gated public archetype gallery or any public topology projection.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping

from mybench.claims import canonical_bytes
from mybench.normalizer.contract import validate_corpus_artifact
from mybench.registry import Registry, RegistryError
from mybench.schemas import load_validator

DELEGATION_SCORER_VERSION = "1.0.0"
SPAWNING_SESSION_RATE_ID = "fingerprint.topology.spawning_session_rate"
DELEGATION_DEPTH_DISTRIBUTION_ID = "fingerprint.topology.delegation_depth_distribution"
FAN_OUT_DISTRIBUTION_ID = "fingerprint.topology.fan_out_distribution"
PEAK_PARALLEL_LANES_DISTRIBUTION_ID = "fingerprint.topology.peak_parallel_lanes.exact"
DELEGATION_REGISTRY_IDS = (
    DELEGATION_DEPTH_DISTRIBUTION_ID,
    FAN_OUT_DISTRIBUTION_ID,
    PEAK_PARALLEL_LANES_DISTRIBUTION_ID,
    SPAWNING_SESSION_RATE_ID,
)

_COMMON_CAVEATS = ["lineage-marker-coverage-dependent"]
_PEAK_CAVEATS = [
    "lineage-marker-coverage-dependent",
    "observed-activity-envelope-not-execution",
]


class DelegationScoringError(ValueError):
    """The normalized input or registry-owned metric contract is invalid."""


def _basis_points(numerator: int, denominator: int) -> int | str:
    if denominator == 0:
        return "UNKNOWN"
    return min(10000, (10000 * numerator + denominator // 2) // denominator)


def _schema_check(value: dict) -> None:
    try:
        errors = sorted(
            load_validator("orchestration_delegation.schema.json").iter_errors(value),
            key=str,
        )
    except Exception as exc:  # noqa: BLE001 - keep private inputs out of diagnostics
        raise DelegationScoringError("delegation output validation failed") from exc
    if errors:
        raise DelegationScoringError("delegation output violates its closed schema")


def _checked_corpus(corpus: object) -> dict:
    if not isinstance(corpus, dict):
        raise DelegationScoringError("normalized corpus must be an object")
    try:
        validate_corpus_artifact(canonical_bytes(corpus) + b"\n")
    except Exception as exc:  # noqa: BLE001 - normalizer errors are path/content-free here
        raise DelegationScoringError("normalized corpus validation failed") from exc
    return corpus


def _registry_contract(registry: Registry) -> dict[str, dict]:
    expected_support = {
        SPAWNING_SESSION_RATE_ID: {"sessions": 1},
        DELEGATION_DEPTH_DISTRIBUTION_ID: {"sessions": 1},
        FAN_OUT_DISTRIBUTION_ID: {"sessions": 1},
        PEAK_PARALLEL_LANES_DISTRIBUTION_ID: {"sessions": 5},
    }
    entries = {}
    for registry_id in DELEGATION_REGISTRY_IDS:
        try:
            entry = registry.entry(registry_id)
        except RegistryError as exc:
            raise DelegationScoringError("delegation registry contract is incomplete") from exc
        if (
            entry["status"] != "active"
            or entry["class"] != "measured"
            or entry["disclosure"] != "local-report-only"
            or entry.get("report_location") != "fingerprint.orchestration_topology"
            or entry["presets"]
            or registry.min_support(registry_id) != expected_support[registry_id]
        ):
            raise DelegationScoringError("delegation registry contract is invalid")
        properties = entry["output_schema"].get("properties", {})
        expected_caveats = (
            _PEAK_CAVEATS if registry_id == PEAK_PARALLEL_LANES_DISTRIBUTION_ID else _COMMON_CAVEATS
        )
        if properties.get("trust_tier") != {"const": "ANCHORED"} or properties.get("caveats") != {
            "const": expected_caveats
        }:
            raise DelegationScoringError("delegation trust/caveat contract is invalid")
        entries[registry_id] = entry
    return entries


def _lineage_forest(
    sessions: list[dict],
) -> tuple[dict[tuple[str, str], tuple[int, tuple[str, str]]], int]:
    """Resolve the observed Claude lineage forest.

    A root is a Claude session explicitly marked ``primary`` with no parent.
    A child is explicitly marked ``subagent`` and names one admitted Claude
    parent. Anything else, including a cycle, remains uncovered. Depth is the
    number of accepted parent edges from the root (root depth zero).
    """

    keys = [(session["source"], session["session_id"]) for session in sessions]
    by_key = dict(zip(keys, sessions, strict=True))
    resolved: dict[tuple[str, str], tuple[int, tuple[str, str]]] = {}
    resolving: set[tuple[str, str]] = set()

    def visit(key: tuple[str, str]) -> tuple[int, tuple[str, str]] | None:
        if key in resolved:
            return resolved[key]
        if key in resolving:
            return None
        session = by_key[key]
        if session["source"] != "claude-code":
            return None
        role = session.get("lane_role")
        parent_id = session.get("parent_session_id")
        if role == "primary" and parent_id is None:
            value = (0, key)
            resolved[key] = value
            return value
        if role != "subagent" or not isinstance(parent_id, str):
            return None
        parent = (session["source"], parent_id)
        if parent not in by_key:
            return None
        resolving.add(key)
        parent_value = visit(parent)
        resolving.remove(key)
        if parent_value is None:
            return None
        value = (parent_value[0] + 1, parent_value[1])
        resolved[key] = value
        return value

    for key in keys:
        visit(key)
    return resolved, len(sessions) - len(resolved)


def _activity_intervals(corpus: dict) -> dict[tuple[str, str], tuple[str, str]]:
    observed: dict[tuple[str, str], list[str]] = defaultdict(list)
    for event in corpus["events"]:
        timestamp = event.get("observed_at")
        if isinstance(timestamp, str):
            observed[(event["source"], event["session_id"])].append(timestamp)
    return {key: (min(values), max(values)) for key, values in observed.items() if values}


def _peak_overlap(intervals: list[tuple[str, str]]) -> int:
    """Count closed observed-activity envelopes at every observed boundary."""

    boundaries = sorted({point for interval in intervals for point in interval})
    return max(sum(start <= boundary <= end for start, end in intervals) for boundary in boundaries)


def _validate_registry_outputs(
    fields: dict[str, dict], entries: Mapping[str, dict], registry: Registry
) -> None:
    for registry_id, output in fields.items():
        try:
            registry.check_claim(
                {
                    "registry_id": registry_id,
                    "registry_version": entries[registry_id]["version"],
                    "derivation_class": entries[registry_id]["class"],
                    "output": output,
                }
            )
        except RegistryError as exc:
            raise DelegationScoringError("delegation output failed registry conformance") from exc


def score_orchestration_delegation(
    corpus: dict,
    *,
    registry: Registry | None = None,
) -> dict | None:
    """Return four identifier-free private distributions, or ``None`` unsupported.

    Fan-out is the accepted direct-child count for every lineage-eligible
    session. Delegation depth is accepted-parent-edge distance from a root.
    Peak parallel lanes is computed per root graph from closed intervals
    spanning each lane's first through last observed event timestamp. It is an
    observed-activity-envelope overlap, not proof of simultaneous execution.
    """

    corpus = _checked_corpus(corpus)
    sessions = corpus["manifest"]["sessions"]
    sessions_by_key = {(session["source"], session["session_id"]): session for session in sessions}
    forest, unknown_sessions = _lineage_forest(sessions)
    if not forest:
        return None

    registry = registry or Registry.load()
    entries = _registry_contract(registry)
    children: Counter[tuple[str, str]] = Counter()
    graphs: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    depths: Counter[int] = Counter()
    for key, (depth, root) in forest.items():
        graphs[root].append(key)
        depths[depth] += 1
        session = sessions_by_key[key]
        parent_id = session.get("parent_session_id")
        if depth and isinstance(parent_id, str):
            children[(session["source"], parent_id)] += 1

    fan_out: Counter[int] = Counter(children.get(key, 0) for key in forest)
    eligible_sessions = len(forest)
    lineage_coverage = _basis_points(eligible_sessions, len(sessions))
    spawning_sessions = sum(children.get(key, 0) > 0 for key in forest)

    intervals = _activity_intervals(corpus)
    peaks: Counter[int] = Counter()
    interval_unknown_graphs = 0
    interval_eligible_sessions = 0
    for nodes in graphs.values():
        if any(node not in intervals for node in nodes):
            interval_unknown_graphs += 1
            continue
        interval_eligible_sessions += len(nodes)
        peak = _peak_overlap([intervals[node] for node in nodes])
        peaks[peak] += 1
    interval_eligible_graphs = sum(peaks.values())
    interval_coverage = _basis_points(interval_eligible_graphs, len(graphs))

    fields = {
        DELEGATION_DEPTH_DISTRIBUTION_ID: {
            "lineage_coverage_basis_points": lineage_coverage,
            "eligible_sessions": eligible_sessions,
            "unknown_sessions": unknown_sessions,
            **{f"depth_{depth}_sessions": count for depth, count in sorted(depths.items())},
            "trust_tier": "ANCHORED",
            "caveats": _COMMON_CAVEATS,
        },
        FAN_OUT_DISTRIBUTION_ID: {
            "lineage_coverage_basis_points": lineage_coverage,
            "eligible_sessions": eligible_sessions,
            "unknown_sessions": unknown_sessions,
            **{
                f"fan_out_{child_count}_sessions": count
                for child_count, count in sorted(fan_out.items())
            },
            "trust_tier": "ANCHORED",
            "caveats": _COMMON_CAVEATS,
        },
        SPAWNING_SESSION_RATE_ID: {
            "lineage_coverage_basis_points": lineage_coverage,
            "eligible_sessions": eligible_sessions,
            "unknown_sessions": unknown_sessions,
            "spawning_sessions": spawning_sessions,
            "rate_basis_points": _basis_points(spawning_sessions, eligible_sessions),
            "trust_tier": "ANCHORED",
            "caveats": _COMMON_CAVEATS,
        },
    }
    if interval_eligible_sessions >= 5:
        fields[PEAK_PARALLEL_LANES_DISTRIBUTION_ID] = {
            "lineage_coverage_basis_points": lineage_coverage,
            "interval_coverage_basis_points": interval_coverage,
            "eligible_graphs": interval_eligible_graphs,
            "unknown_graphs": interval_unknown_graphs,
            **{f"peak_{peak}_graphs": count for peak, count in sorted(peaks.items())},
            "trust_tier": "ANCHORED",
            "caveats": _PEAK_CAVEATS,
        }
    fields = dict(sorted(fields.items()))
    _validate_registry_outputs(fields, entries, registry)
    result = {
        "schema_version": "1",
        "kind": "orchestration-delegation-distributions",
        "scorer_version": DELEGATION_SCORER_VERSION,
        "fields": fields,
    }
    _schema_check(result)
    return result


__all__ = [
    "DELEGATION_DEPTH_DISTRIBUTION_ID",
    "DELEGATION_REGISTRY_IDS",
    "DELEGATION_SCORER_VERSION",
    "DelegationScoringError",
    "FAN_OUT_DISTRIBUTION_ID",
    "PEAK_PARALLEL_LANES_DISTRIBUTION_ID",
    "SPAWNING_SESSION_RATE_ID",
    "score_orchestration_delegation",
]
