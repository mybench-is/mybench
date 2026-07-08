"""Smoke test for mybench.anchor. Synthetic only — no real transcripts (invariant #3)."""

from mybench import anchor


def test_component_metadata():
    assert anchor.COMPONENT == "anchor"
    assert anchor.RESPONSIBILITY
