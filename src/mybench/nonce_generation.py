"""Ambient-randomness boundary for ADR-0002 commitment nonces."""

from __future__ import annotations

import secrets

from mybench.commitment_tree import NONCE_LEN


def generate_nonce() -> bytes:
    """Return a fresh per-item nonce from the operating-system CSPRNG."""
    return secrets.token_bytes(NONCE_LEN)
