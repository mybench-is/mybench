"""Smoke test for mybench.daemon. Synthetic only — no real transcripts (invariant #3)."""

from mybench import daemon


def test_component_metadata():
    assert daemon.COMPONENT == "daemon"
    assert daemon.RESPONSIBILITY
