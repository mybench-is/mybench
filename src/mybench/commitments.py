"""ADR-0002 commitment API with deterministic primitives and nonce generation.

The deterministic implementation lives in :mod:`mybench.commitment_tree` so
compute-pipeline audits can traverse it without admitting ambient randomness.
This compatibility facade preserves the original public API for capture and
verification callers.  Fresh nonce generation remains a separate CSPRNG-only
boundary and no function here writes nonce material anywhere.
"""

from __future__ import annotations

from mybench.commitment_tree import (
    DOMAIN_DAY as DOMAIN_DAY,
    DOMAIN_LEAF as DOMAIN_LEAF,
    DOMAIN_NODE as DOMAIN_NODE,
    DOMAIN_SESSION as DOMAIN_SESSION,
    HASH_LEN as HASH_LEN,
    NONCE_LEN as NONCE_LEN,
    Proof as Proof,
    _check_hash as _check_hash,
    _fold as _fold,
    _sha256 as _sha256,
    _split as _split,
    day_root as day_root,
    inclusion_proof as inclusion_proof,
    leaf_commitment as leaf_commitment,
    merkle_root as merkle_root,
    node_hash as node_hash,
    session_root as session_root,
    verify_inclusion as verify_inclusion,
    verify_session_inclusion as verify_session_inclusion,
)
from mybench.nonce_generation import generate_nonce as generate_nonce

__all__ = [
    "DOMAIN_DAY",
    "DOMAIN_LEAF",
    "DOMAIN_NODE",
    "DOMAIN_SESSION",
    "HASH_LEN",
    "NONCE_LEN",
    "Proof",
    "day_root",
    "generate_nonce",
    "inclusion_proof",
    "leaf_commitment",
    "merkle_root",
    "node_hash",
    "session_root",
    "verify_inclusion",
    "verify_session_inclusion",
]
