"""mybench.scorer — deterministic activity metrics over the local ledger (see README)."""

from mybench.scorer.agent_hours import (
    AGENT_HOURS_REGISTRY_ID,
    AGENT_HOURS_SCORER_VERSION,
    AgentHoursScoringError,
    score_agent_hours,
)
from mybench.scorer.evidence_coverage import (
    AMBIGUITY_CATEGORIES,
    COVERAGE_CONTRACT_VERSION,
    EvidenceCoverageError,
    basis_points,
    build_coverage_contribution,
    confidence,
    score_evidence_coverage,
)
from mybench.scorer.topology import (
    TOPOLOGY_CATEGORIES,
    TOPOLOGY_REGISTRY_ID,
    TOPOLOGY_SCHEMA_VERSION,
    TopologyScanError,
    scan_orchestration_topology,
    store_local_topology,
)
from mybench.scorer.workflow_map import (
    AUTHORSHIP_SHARES_ID,
    CONTEXT_BOUNDARY_RATE_ID,
    MODEL_ROUTING_ID,
    RECURRING_SEQUENCES_ID,
    REWORK_LOOP_RATE_ID,
    TASK_EPISODE_TOTAL_ID,
    TRANSITION_SHARES_ID,
    UNKNOWN_PHASE_SHARE_ID,
    WORKFLOW_MAP_REGISTRY_IDS,
    WORKFLOW_MAP_SCHEMA_VERSION,
    WORKFLOW_MAP_SCORER_VERSION,
    WorkflowMapScoringError,
    score_workflow_map,
)

COMPONENT = "scorer"
RESPONSIBILITY = (
    "deterministically compute activity metrics over the local ledger, each tagged "
    "with a trust tier"
)

__all__ = [
    "AGENT_HOURS_REGISTRY_ID",
    "AGENT_HOURS_SCORER_VERSION",
    "AgentHoursScoringError",
    "score_agent_hours",
    "AMBIGUITY_CATEGORIES",
    "COVERAGE_CONTRACT_VERSION",
    "EvidenceCoverageError",
    "basis_points",
    "build_coverage_contribution",
    "confidence",
    "score_evidence_coverage",
    "TOPOLOGY_CATEGORIES",
    "TOPOLOGY_REGISTRY_ID",
    "TOPOLOGY_SCHEMA_VERSION",
    "TopologyScanError",
    "scan_orchestration_topology",
    "store_local_topology",
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
