"""Smoke test for mybench.hooks. Synthetic only — no real transcripts (invariant #3)."""

from mybench import hooks


def test_component_metadata():
    assert hooks.COMPONENT == "hooks"
    assert hooks.RESPONSIBILITY


def test_opt_in_marker_is_repo_relative():
    # Opt-in per repo via a marker file; never a global hook.
    assert hooks.MARKER_RELPATH == ".mybench/commit-binding-enabled"
