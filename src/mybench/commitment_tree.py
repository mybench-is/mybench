"""Pure deterministic commitment and RFC-6962-shaped Merkle primitives.

This module deliberately has no nonce generation or ambient-state imports.  It
is the deterministic subset of ADR-0002 used by parsers, normalizers, scorers,
and verifiers.  ``mybench.commitments`` re-exports this public API for backward
compatibility with existing capture callers.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

DOMAIN_LEAF = b"mybench:v1:leaf"
DOMAIN_NODE = b"mybench:v1:node"
DOMAIN_SESSION = b"mybench:v1:session"
DOMAIN_DAY = b"mybench:v1:day"

NONCE_LEN = 32
HASH_LEN = 32
_LEN_BYTES = 8

# Inclusion proof: bottom-up list of (side, sibling_hash); side is which side
# the SIBLING sits on ("L" = sibling is the left child).
Proof = list[tuple[str, bytes]]


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_commitment(nonce: bytes, content: bytes) -> bytes:
    """Commitment to one item: H(leaf-domain || nonce || len || content)."""
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be exactly {NONCE_LEN} bytes, got {len(nonce)}")
    return _sha256(DOMAIN_LEAF + nonce + len(content).to_bytes(_LEN_BYTES, "big") + content)


def _check_hash(h: bytes) -> bytes:
    if len(h) != HASH_LEN:
        raise ValueError(f"expected a {HASH_LEN}-byte hash, got {len(h)} bytes")
    return h


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(DOMAIN_NODE + _check_hash(left) + _check_hash(right))


def _split(n: int) -> int:
    """Largest power of two strictly less than n (RFC-6962 split point)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(hashes: Sequence[bytes]) -> bytes:
    """RFC-6962-shaped tree root; one element is itself and empty is invalid."""
    if not hashes:
        raise ValueError("empty tree has no root (ADR-0002 §3: no items, no tree)")
    if len(hashes) == 1:
        return _check_hash(hashes[0])
    k = _split(len(hashes))
    return node_hash(merkle_root(hashes[:k]), merkle_root(hashes[k:]))


def session_root(leaves: Sequence[bytes]) -> bytes:
    """Finalized session root: H(session-domain || MTH(leaves))."""
    return _sha256(DOMAIN_SESSION + merkle_root(leaves))


def day_root(session_roots: Sequence[bytes]) -> bytes:
    """Finalized day root: H(day-domain || MTH(session roots))."""
    return _sha256(DOMAIN_DAY + merkle_root(session_roots))


def inclusion_proof(hashes: Sequence[bytes], index: int) -> Proof:
    """Audit path for ``hashes[index]`` up to the raw Merkle-tree root."""
    if not 0 <= index < len(hashes):
        raise IndexError(f"index {index} outside tree of {len(hashes)} leaves")
    if len(hashes) == 1:
        return []
    k = _split(len(hashes))
    if index < k:
        return inclusion_proof(hashes[:k], index) + [("R", merkle_root(hashes[k:]))]
    return inclusion_proof(hashes[k:], index - k) + [("L", merkle_root(hashes[:k]))]


def _fold(leaf: bytes, proof: Proof) -> bytes:
    h = _check_hash(leaf)
    for side, sibling in proof:
        if side == "R":
            h = node_hash(h, sibling)
        elif side == "L":
            h = node_hash(sibling, h)
        else:
            raise ValueError(f"proof side must be 'L' or 'R', got {side!r}")
    return h


def verify_inclusion(leaf: bytes, proof: Proof, root: bytes) -> bool:
    """Verify an audit path against a raw Merkle-tree root."""
    return _fold(leaf, proof) == root


def verify_session_inclusion(leaf: bytes, proof: Proof, session_root_value: bytes) -> bool:
    """Verify an audit path against a finalized (wrapped) session root."""
    return _sha256(DOMAIN_SESSION + _fold(leaf, proof)) == session_root_value


__all__ = [
    "DOMAIN_DAY",
    "DOMAIN_LEAF",
    "DOMAIN_NODE",
    "DOMAIN_SESSION",
    "HASH_LEN",
    "NONCE_LEN",
    "Proof",
    "day_root",
    "inclusion_proof",
    "leaf_commitment",
    "merkle_root",
    "node_hash",
    "session_root",
    "verify_inclusion",
    "verify_session_inclusion",
]
