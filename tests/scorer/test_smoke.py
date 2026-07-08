"""Smoke test for mybench.scorer. Synthetic only — no real transcripts (invariant #3)."""

from mybench import scorer


def test_component_metadata():
    assert scorer.COMPONENT == "scorer"
    assert scorer.RESPONSIBILITY
