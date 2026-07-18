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
from mybench.scorer.wave1 import (
    MCP_TAXONOMY_VERSION,
    SCORER_VERSION as WAVE1_SCORER_VERSION,
    Wave1ScorerError,
    build_harness_currency_snapshot,
    build_mcp_category_observations,
    build_mcp_recurrence_snapshot,
    score_autonomy_band,
    score_mcp_breadth,
    score_orchestrators,
    score_tool_mix,
    score_verification_ratio,
    score_wave1_claims,
    score_wellformed,
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
    "MCP_TAXONOMY_VERSION",
    "WAVE1_SCORER_VERSION",
    "Wave1ScorerError",
    "build_harness_currency_snapshot",
    "build_mcp_category_observations",
    "build_mcp_recurrence_snapshot",
    "score_autonomy_band",
    "score_mcp_breadth",
    "score_orchestrators",
    "score_tool_mix",
    "score_verification_ratio",
    "score_wave1_claims",
    "score_wellformed",
]
