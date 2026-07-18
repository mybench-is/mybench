"""Deterministic workflow-phase classification over normalized events.

The classifier consumes only closed structural fields already present in A8.
It never resolves pointers or reads content, paths, filenames, identifiers,
timestamps, provider metadata, or ambient state.  The resulting ordered stream
is private A8-derived data; publication is deliberately outside this module.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from mybench.normalizer.claude import NormalizationError

WORKFLOW_PHASE_CLASSIFIER_VERSION = "1.0.0"
WORKFLOW_PHASE_SCHEMA_VERSION = "1"

WORKFLOW_PHASES = (
    "TASK",
    "PLAN",
    "BUILD",
    "TEST",
    "DEBUG",
    "REVIEW",
    "COMMIT",
    "UNKNOWN",
)
WORKFLOW_PHASE_CONFIDENCE = ("LOW", "MEDIUM", "HIGH", "UNKNOWN")

_PHASES = frozenset(WORKFLOW_PHASES)
_CONFIDENCE = frozenset(WORKFLOW_PHASE_CONFIDENCE)


@dataclass(frozen=True)
class WorkflowPhase:
    """One identifier-free classification in normalized event order."""

    ordinal: int
    phase: str
    confidence: str
    rule_id: str
    classifier_version: str = WORKFLOW_PHASE_CLASSIFIER_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.ordinal) is not int
            or self.ordinal < 0
            or self.phase not in _PHASES
            or self.confidence not in _CONFIDENCE
            or self.classifier_version != WORKFLOW_PHASE_CLASSIFIER_VERSION
            or not isinstance(self.rule_id, str)
            or not self.rule_id
        ):
            raise NormalizationError("workflow phase has an invalid structural state")
        if (self.phase == "UNKNOWN") != (self.confidence == "UNKNOWN"):
            raise NormalizationError("workflow phase has inconsistent confidence")

    def local_record(self) -> dict[str, object]:
        """Return the closed local-only record; no input identity is copied."""

        return {
            "classifier_version": self.classifier_version,
            "confidence": self.confidence,
            "ordinal": self.ordinal,
            "phase": self.phase,
            "rule_id": self.rule_id,
        }


def _unknown(ordinal: int) -> WorkflowPhase:
    return WorkflowPhase(
        ordinal=ordinal,
        phase="UNKNOWN",
        confidence="UNKNOWN",
        rule_id="no-structural-rule",
    )


def _classify_one(event: Mapping[str, object], ordinal: int) -> WorkflowPhase:
    """Apply v1's fixed precedence table using pinned structural fields only."""

    event_kind = event.get("event_kind")

    if event_kind == "turn" and event.get("authorship") == "human-turn":
        return WorkflowPhase(ordinal, "TASK", "MEDIUM", "human-turn-boundary")

    if event_kind == "reference":
        reference_kind = event.get("reference_kind")
        if reference_kind == "plan":
            return WorkflowPhase(ordinal, "PLAN", "HIGH", "plan-reference")
        if reference_kind == "instruction":
            return WorkflowPhase(ordinal, "PLAN", "MEDIUM", "instruction-reference")

    if event_kind == "tool-call":
        tool_family = event.get("tool_family")
        if tool_family == "write":
            return WorkflowPhase(ordinal, "BUILD", "HIGH", "write-tool")
        if tool_family == "edit":
            return WorkflowPhase(ordinal, "BUILD", "HIGH", "edit-tool")

    if event_kind == "test":
        return WorkflowPhase(ordinal, "TEST", "HIGH", "test-observation")

    if event_kind == "tool-result" and event.get("result_status") == "error":
        return WorkflowPhase(ordinal, "DEBUG", "MEDIUM", "error-observation")

    if event_kind == "forge-action" and event.get("forge_action_kind") in {
        "pr-comment",
        "pr-review-request",
    }:
        return WorkflowPhase(ordinal, "REVIEW", "MEDIUM", "review-boundary")

    # In particular, v1 does not coerce a push or merge attempt to COMMIT:
    # neither proves that a commit was created in this event stream.
    return _unknown(ordinal)


def classify_workflow_phases(
    events: Sequence[Mapping[str, object]],
) -> tuple[WorkflowPhase, ...]:
    """Return one deterministic phase record per normalized input event.

    The caller supplies events in normalized-corpus order.  That ordering is
    preserved exactly and replaced by local ordinals, so session identifiers
    and record coordinates never enter the output.  Unknown or newly added
    event shapes fail closed to ``UNKNOWN``.
    """

    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise NormalizationError("workflow phase input must be an explicit sequence")

    phases = []
    for ordinal, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise NormalizationError("workflow phase input has the wrong type")
        phases.append(_classify_one(event, ordinal))
    return tuple(phases)


def workflow_phase_artifact(events: Sequence[Mapping[str, object]]) -> bytes:
    """Return canonical, local-only bytes for a versioned phase stream."""

    phases = classify_workflow_phases(events)
    value = {
        "classifier_version": WORKFLOW_PHASE_CLASSIFIER_VERSION,
        "kind": "workflow-phase-stream",
        "phases": [phase.local_record() for phase in phases],
        "schema_version": WORKFLOW_PHASE_SCHEMA_VERSION,
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


__all__ = [
    "WORKFLOW_PHASE_CLASSIFIER_VERSION",
    "WORKFLOW_PHASE_CONFIDENCE",
    "WORKFLOW_PHASE_SCHEMA_VERSION",
    "WORKFLOW_PHASES",
    "WorkflowPhase",
    "classify_workflow_phases",
    "workflow_phase_artifact",
]
