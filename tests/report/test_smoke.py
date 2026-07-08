"""Smoke test for mybench.report. Synthetic only — no real transcripts (invariant #3)."""

from mybench import report


def test_component_metadata():
    assert report.COMPONENT == "report"
    assert report.RESPONSIBILITY
