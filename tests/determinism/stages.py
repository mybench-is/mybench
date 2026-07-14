"""Synthetic, byte-producing pipeline stages covered by the CI gate.

Keep the inputs here (or in an existing synthetic test helper) fixed and
explicit.  A stage may read packaged, committed metadata such as a schema or
the descriptor registry, but it must never discover owner data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Stage:
    """One byte-producing pipeline stage and its ambient-state audit surface."""

    name: str
    module_names: tuple[str, ...]


# The current landed fingerprint pipeline has no transcript/git normalizers or
# publication-preview bundle yet.  Their owning stories add entries here.  The
# claim and registry-manifest stages are included because they are the already
# landed serialization/disclosure substrates those future stages consume.
STAGES = (
    Stage("activity-report-json", ("mybench.scorer.score",)),
    Stage(
        "signed-claim",
        ("mybench.claims.canonical", "mybench.claims.envelope"),
    ),
    Stage("registry-disclosure-manifest", ("mybench.registry",)),
    Stage("static-report-html", ("mybench.report.page",)),
)


def _activity_report_json() -> bytes:
    # Reuse MYB-4.2's fixed synthetic corpus rather than inventing a second
    # scorer fixture for this gate.
    from tests.scorer.test_score import fixed_report_bytes

    return fixed_report_bytes()


def _signed_claim() -> bytes:
    # Reuse MYB-10.1's fixed synthetic key and claim fixture.  No owner key is
    # loaded and no local data directory is touched.
    from mybench.claims import claim_file_bytes
    from tests.claims.test_envelope import make_signed

    return claim_file_bytes(make_signed())


def _registry_disclosure_manifest() -> bytes:
    from mybench.claims import canonical_bytes
    from mybench.registry import EMPLOYER_SAFE, Registry

    manifest = Registry.load().disclosure_manifest(EMPLOYER_SAFE)
    return canonical_bytes(manifest) + b"\n"


def _static_report_html() -> bytes:
    from mybench.report.page import render_page

    return render_page(
        json.loads(_activity_report_json()),
        anchors_url="https://github.com/synthetic/mybench-anchors",
        handle="synthetic-owner",
    )


_RUNNERS = {
    "activity-report-json": _activity_report_json,
    "signed-claim": _signed_claim,
    "registry-disclosure-manifest": _registry_disclosure_manifest,
    "static-report-html": _static_report_html,
}


def run_stage(name: str) -> bytes:
    """Run one named stage and require an exact byte artifact."""
    try:
        runner = _RUNNERS[name]
    except KeyError:
        raise ValueError(f"unknown determinism stage: {name}") from None
    output = runner()
    if not isinstance(output, bytes):
        raise TypeError(f"determinism stage {name!r} returned {type(output).__name__}, not bytes")
    return output
