"""Deterministic evidence-coverage contract and aggregate (MYB-13.8).

The four content-adjacent Workflow Fingerprint section scorers emit one
closed contribution each. Contributions carry only rates, confidence/state
labels, and counts keyed by the pinned ambiguity taxonomy. Raw evidence,
identifiers, names, paths, timestamps, and ordered streams are not accepted.

The aggregate consumes the existing schema-v1 ``binding_coverage`` and
``evidence_provenance_split`` metrics as explicit inputs. This keeps the
PROVEN definitions owned by the shipped scorer instead of independently
reimplementing them here. The function has no clock, environment, network,
or filesystem dependency.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from mybench.schemas import load_validator

COVERAGE_CONTRACT_VERSION = "1.0.0"

AMBIGUITY_CATEGORIES = (
    "missing-marker",
    "missing-pointer-target",
    "conflicting-evidence",
    "unsupported-harness-version",
    "unlinked-session",
    "unknown-phase",
    "missing-model",
    "missing-effort",
    "missing-token-data",
)

INPUT_BASES = {
    "git-session-linkage": "binding-coverage-based-stand-in",
    "model": "recognized-model-or-other-per-eligible-event",
    "effort": "recognized-effort-per-eligible-event",
    "context-lifecycle": "reliable-lifecycle-marker-per-eligible-session",
    "token-data": "structurally-valid-token-metadata-per-eligible-session",
}

PRODUCER_INPUTS = {
    "workflow-map": (),
    "model-role-profile": ("model", "effort"),
    "context-management-profile": ("context-lifecycle",),
    "token-cost-profile": ("token-data",),
}

_INPUT_ORDER = tuple(INPUT_BASES)
_PROVENANCE_ORDER = ("IMPORTED", "LIVE")


class EvidenceCoverageError(ValueError):
    """A contribution, legacy metric, or coverage contract is invalid."""


def basis_points(covered: int, eligible: int) -> int | str:
    """Return the v2 pinned integer rate, or ``UNKNOWN`` without a denominator.

    Zero covered observations with a known denominator correctly produces
    zero *coverage*. It never supplies a zero activity value to a section
    scorer; the adjacent evidence state remains ``partial``.
    """

    if type(covered) is not int or type(eligible) is not int:
        raise EvidenceCoverageError("coverage counts must be integers")
    if covered < 0 or eligible < 0 or covered > eligible:
        raise EvidenceCoverageError("coverage counts are inconsistent")
    if eligible == 0:
        return "UNKNOWN"
    return min(10000, (10000 * covered + eligible // 2) // eligible)


def confidence(coverage_basis_points: int | str) -> str:
    """Return the v2 confidence label for one coverage rate."""

    if coverage_basis_points == "UNKNOWN":
        return "UNKNOWN"
    if type(coverage_basis_points) is not int or not 0 <= coverage_basis_points <= 10000:
        raise EvidenceCoverageError("coverage rate is invalid")
    if coverage_basis_points < 5000:
        return "LOW"
    if coverage_basis_points < 7500:
        return "MEDIUM"
    return "HIGH"


def _evidence_state(rate: int | str) -> str:
    if rate == "UNKNOWN":
        return "unknown"
    return "available" if rate == 10000 else "partial"


def _observation(input_class: str, counts: tuple[int, int] | None) -> dict:
    if input_class not in INPUT_BASES or input_class == "git-session-linkage":
        raise EvidenceCoverageError("coverage input class is invalid")
    if counts is None:
        rate: int | str = "UNKNOWN"
    elif (
        not isinstance(counts, tuple)
        or len(counts) != 2
        or any(type(value) is not int for value in counts)
    ):
        raise EvidenceCoverageError("coverage observation must be a covered/eligible pair")
    else:
        rate = basis_points(*counts)
    return {
        "input_class": input_class,
        "basis": INPUT_BASES[input_class],
        "coverage_basis_points": rate,
        "confidence": confidence(rate),
        "evidence_state": _evidence_state(rate),
    }


def _validate_contribution(contribution: dict) -> None:
    try:
        errors = sorted(
            load_validator("fingerprint_coverage_input.schema.json").iter_errors(contribution),
            key=str,
        )
    except Exception as exc:  # noqa: BLE001 - one path-free exception contract
        raise EvidenceCoverageError("coverage contribution validation failed") from exc
    if errors:
        raise EvidenceCoverageError("coverage contribution violates the closed schema")

    producer = contribution["producer"]
    observations = contribution["observations"]
    observed_classes = [item["input_class"] for item in observations]
    expected_classes = list(PRODUCER_INPUTS[producer])
    if observed_classes != expected_classes:
        raise EvidenceCoverageError("coverage contribution has the wrong producer inputs")
    for item in observations:
        rate = item["coverage_basis_points"]
        if item["basis"] != INPUT_BASES[item["input_class"]]:
            raise EvidenceCoverageError("coverage contribution changes an input basis")
        if item["confidence"] != confidence(rate) or item["evidence_state"] != _evidence_state(
            rate
        ):
            raise EvidenceCoverageError("coverage contribution has inconsistent honesty labels")

    categories = [item["category"] for item in contribution["missing_ambiguous"]]
    if categories != sorted(set(categories)):
        raise EvidenceCoverageError("ambiguity categories must be sorted and unique")


def build_coverage_contribution(
    producer: str,
    evidence_counts: Mapping[str, tuple[int, int] | None],
    *,
    missing_ambiguous: Mapping[str, int] | None = None,
) -> dict:
    """Build one deterministic, schema-valid section-scorer contribution.

    ``None`` is the explicit unsupported/unknown denominator state. A known
    marker-free denominator is expressed as ``(0, eligible)`` and yields 0%
    coverage plus ``evidence_state=partial``; downstream activity remains
    UNKNOWN rather than being zero-filled.
    """

    if producer not in PRODUCER_INPUTS:
        raise EvidenceCoverageError("coverage producer is invalid")
    if not isinstance(evidence_counts, Mapping):
        raise EvidenceCoverageError("coverage inputs must be an explicit mapping")
    expected = PRODUCER_INPUTS[producer]
    if set(evidence_counts) != set(expected):
        raise EvidenceCoverageError("coverage producer inputs are incomplete")

    ambiguities = []
    for category, count in sorted((missing_ambiguous or {}).items()):
        if category not in AMBIGUITY_CATEGORIES:
            raise EvidenceCoverageError("ambiguity category is not in the pinned taxonomy")
        if type(count) is not int or count < 0:
            raise EvidenceCoverageError("ambiguity counts must be non-negative integers")
        if count:
            ambiguities.append({"category": category, "count": count})

    contribution = {
        "schema_version": "1",
        "producer": producer,
        "observations": [_observation(name, evidence_counts[name]) for name in expected],
        "missing_ambiguous": ambiguities,
    }
    _validate_contribution(contribution)
    return contribution


def _legacy_metric(metrics: Sequence[dict], name: str) -> dict | None:
    matches = [
        metric for metric in metrics if isinstance(metric, dict) and metric.get("name") == name
    ]
    if len(matches) > 1:
        raise EvidenceCoverageError("legacy report contains a duplicate coverage metric")
    return matches[0] if matches else None


def _legacy_ratio(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceCoverageError("legacy coverage ratio is invalid")
    try:
        decimal = Decimal(str(value))
    except InvalidOperation:
        raise EvidenceCoverageError("legacy coverage ratio is invalid") from None
    if not decimal.is_finite() or not Decimal(0) <= decimal <= Decimal(1):
        raise EvidenceCoverageError("legacy coverage ratio is invalid")
    return int((decimal * 10000).to_integral_value(rounding=ROUND_HALF_UP))


def _binding_observation(metrics: Sequence[dict]) -> dict:
    metric = _legacy_metric(metrics, "binding_coverage")
    rate: int | str = "UNKNOWN"
    if metric is not None:
        if metric.get("trust_tier") != "PROVEN" or not isinstance(metric.get("value"), dict):
            raise EvidenceCoverageError("legacy binding coverage is invalid")
        rates = [_legacy_ratio(value) for value in metric["value"].values()]
        # v1 reports one exact value per explicitly public named repo but does
        # not preserve the per-repo denominators needed for a sound aggregate.
        # One value (or several identical values) is reusable verbatim. A
        # heterogeneous multi-repo set is UNKNOWN until MYB-10.10 supplies
        # session/commit linkage, rather than inventing a weighting rule.
        if rates and len(set(rates)) == 1:
            rate = rates[0]
    return {
        "input_class": "git-session-linkage",
        "basis": INPUT_BASES["git-session-linkage"],
        "coverage_basis_points": rate,
        "confidence": confidence(rate),
        "evidence_state": _evidence_state(rate),
        "trust_tier": "PROVEN",
    }


def _provenance_split(metrics: Sequence[dict]) -> list[dict]:
    metric = _legacy_metric(metrics, "evidence_provenance_split")
    rates: dict[str, int | str] = {name: "UNKNOWN" for name in _PROVENANCE_ORDER}
    if metric is not None:
        value = metric.get("value")
        if metric.get("trust_tier") != "PROVEN" or not isinstance(value, dict):
            raise EvidenceCoverageError("legacy provenance split is invalid")
        if set(value) != set(_PROVENANCE_ORDER):
            raise EvidenceCoverageError("legacy provenance split uses unknown classes")
        converted = {name: _legacy_ratio(value[name]) for name in _PROVENANCE_ORDER}
        total = sum(converted.values())
        if total == 10000:
            rates = converted
        elif total != 0:
            raise EvidenceCoverageError("legacy provenance split is inconsistent")
        # The v1 zero/zero result has no anchored denominator. Preserve it as
        # UNKNOWN rather than claiming zero imported and zero live work.

    return [
        {
            "provenance": name,
            "share_basis_points": rates[name],
            "trust_tier": "PROVEN",
            "basis": "anchor-coverage-derived-provenance-split",
        }
        for name in _PROVENANCE_ORDER
    ]


def score_evidence_coverage(
    contributions: Sequence[dict],
    *,
    legacy_metrics: Sequence[dict],
) -> dict:
    """Aggregate all section contributions with the two shipped PROVEN inputs.

    All four producer contracts are required, even when a scorer explicitly
    emits UNKNOWN observations. This is the integration brake that prevents
    an absent implementation from looking like complete evidence.
    """

    if isinstance(contributions, (str, bytes)) or not isinstance(contributions, Sequence):
        raise EvidenceCoverageError("coverage contributions must be an explicit sequence")
    if isinstance(legacy_metrics, (str, bytes)) or not isinstance(legacy_metrics, Sequence):
        raise EvidenceCoverageError("legacy metrics must be an explicit sequence")

    by_producer = {}
    for contribution in contributions:
        if not isinstance(contribution, dict):
            raise EvidenceCoverageError("coverage contribution must be an object")
        _validate_contribution(contribution)
        producer = contribution["producer"]
        if producer in by_producer:
            raise EvidenceCoverageError("coverage producer appears more than once")
        by_producer[producer] = contribution
    if set(by_producer) != set(PRODUCER_INPUTS):
        raise EvidenceCoverageError("every fingerprint coverage producer must participate")

    observations = {}
    ambiguities: Counter[str] = Counter()
    for producer in sorted(by_producer):
        contribution = by_producer[producer]
        for item in contribution["observations"]:
            input_class = item["input_class"]
            if input_class in observations:
                raise EvidenceCoverageError("coverage input class appears more than once")
            observations[input_class] = {**item, "trust_tier": "ANCHORED"}
        ambiguities.update(
            {item["category"]: item["count"] for item in contribution["missing_ambiguous"]}
        )

    coverage = [_binding_observation(legacy_metrics)]
    coverage.extend(observations[name] for name in _INPUT_ORDER if name != "git-session-linkage")
    aggregate = {
        "schema_version": "1",
        "kind": "evidence-coverage-aggregate",
        "coverage_contract_version": COVERAGE_CONTRACT_VERSION,
        "coverage": coverage,
        "provenance_split": _provenance_split(legacy_metrics),
        "missing_ambiguous": [
            {"category": category, "count": ambiguities[category]}
            for category in sorted(ambiguities)
            if ambiguities[category]
        ],
    }
    try:
        errors = sorted(
            load_validator("evidence_coverage_section.schema.json").iter_errors(aggregate),
            key=str,
        )
    except Exception as exc:  # noqa: BLE001 - one path-free exception contract
        raise EvidenceCoverageError("evidence coverage validation failed") from exc
    if errors:
        raise EvidenceCoverageError("evidence coverage violates the closed schema")
    return aggregate


__all__ = [
    "AMBIGUITY_CATEGORIES",
    "COVERAGE_CONTRACT_VERSION",
    "EvidenceCoverageError",
    "INPUT_BASES",
    "PRODUCER_INPUTS",
    "basis_points",
    "build_coverage_contribution",
    "confidence",
    "score_evidence_coverage",
]
