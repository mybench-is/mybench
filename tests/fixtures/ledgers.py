"""Shared canary-ledger builder for anchor/publisher tests (synthetic only)."""

from __future__ import annotations

from mybench import commitments as c
from mybench.ledger import Ledger
from tests.fixtures.synthetic import FixtureSet


def build_canary_ledger(fx: FixtureSet, repeats: int = 3) -> tuple[Ledger, list[bytes]]:
    """Ledger whose session roots commit canary-fixture content via canary nonces.

    Returns (ledger, all canaries incl. every nonce used) — the scan list any
    published artifact must be clean against.
    """
    led = Ledger()
    used: list[bytes] = []
    for i, s in enumerate(fx.sessions * repeats):
        items = s.read_bytes().splitlines()
        nonces = list(fx.nonce_canaries[: len(items)])
        nonces += [c.generate_nonce() for _ in items[len(nonces) :]]
        used.extend(nonces)
        leaves = [c.leaf_commitment(k, m) for k, m in zip(nonces, items)]
        led.append_session(
            session_id=f"synthetic-{i}",
            session_root=c.session_root(leaves),
            item_count=len(items),
            source="synthetic",
            ts=f"2026-01-01T00:00:{i:02d}Z",
        )
    return led, fx.all_canaries() + used
