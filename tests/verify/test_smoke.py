"""Smoke test for mybench.verify. Synthetic only — no real transcripts (invariant #3)."""

from mybench import verify


def test_component_metadata():
    assert verify.COMPONENT == "verify"
    assert verify.RESPONSIBILITY
