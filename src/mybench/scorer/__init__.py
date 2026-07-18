"""mybench.scorer — deterministic activity metrics over the local ledger (see README)."""

from mybench.scorer.agent_hours import (
    AGENT_HOURS_REGISTRY_ID,
    AGENT_HOURS_SCORER_VERSION,
    AgentHoursScoringError,
    score_agent_hours,
)
from mybench.scorer.topology import (
    TOPOLOGY_CATEGORIES,
    TOPOLOGY_K,
    TOPOLOGY_SCHEMA_VERSION,
    TopologyScanError,
    scan_orchestration_topology,
    store_local_topology,
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
    "TOPOLOGY_CATEGORIES",
    "TOPOLOGY_K",
    "TOPOLOGY_SCHEMA_VERSION",
    "TopologyScanError",
    "scan_orchestration_topology",
    "store_local_topology",
]
