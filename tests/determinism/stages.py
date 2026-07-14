"""Synthetic, byte-producing pipeline stages covered by the CI gate.

Keep the inputs here (or in an existing synthetic test helper) fixed and
explicit.  A stage may read packaged, committed metadata such as a schema or
the descriptor registry, but it must never discover owner data.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

Runner = Callable[[], bytes]


@dataclass(frozen=True)
class Stage:
    """One byte artifact plus its discovery and static-audit contracts.

    ``entry_module`` is set only for modules that discovery must match to an
    executable runner.  Substrate artifacts (claim serialization and registry
    manifest derivation) remain byte-gated but are not themselves scorer,
    parser, normalizer, report, or publication implementation modules.
    """

    name: str
    entry_module: str | None
    audit_roots: tuple[str, ...]


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


RUNNERS: dict[str, Runner] = {
    "activity-report-json": _activity_report_json,
    "signed-claim": _signed_claim,
    "registry-disclosure-manifest": _registry_disclosure_manifest,
    "static-report-html": _static_report_html,
}

# The current landed pipeline has no parser, normalizer, or publication-preview
# implementation yet.  Their owning stories add a Stage with entry_module set
# and a same-name callable in RUNNERS.  Claim/registry outputs are valuable
# deterministic substrates, so their byte runners remain even though discovery
# does not misclassify those mixed-boundary packages as pipeline stages.
STAGES = (
    Stage("activity-report-json", "mybench.scorer.score", ("mybench.scorer.score",)),
    Stage("signed-claim", None, ("mybench.claims.envelope",)),
    Stage("registry-disclosure-manifest", None, ("mybench.registry",)),
    Stage("static-report-html", "mybench.report.page", ("mybench.report.page",)),
)


def validate_registration(
    stages: Sequence[Stage] = STAGES,
    runners: Mapping[str, object] = RUNNERS,
) -> None:
    """Require an exact, executable one-to-one manifest/runner registration."""
    names = [stage.name for stage in stages]
    if len(names) != len(set(names)):
        raise ValueError("determinism stage names must be unique")
    stage_names = set(names)
    runner_names = set(runners)
    if stage_names != runner_names:
        missing = sorted(stage_names - runner_names)
        extra = sorted(runner_names - stage_names)
        raise ValueError(f"determinism stage/runner drift: missing={missing}, extra={extra}")
    noncallable = sorted(name for name, runner in runners.items() if not callable(runner))
    if noncallable:
        raise ValueError(f"determinism runners are not callable: {noncallable}")
    missing_audit_roots = sorted(stage.name for stage in stages if not stage.audit_roots)
    if missing_audit_roots:
        raise ValueError(f"determinism stages missing audit roots: {missing_audit_roots}")
    unaudited_entries = sorted(
        stage.name
        for stage in stages
        if stage.entry_module and stage.entry_module not in stage.audit_roots
    )
    if unaudited_entries:
        raise ValueError(f"pipeline entry modules absent from their audit roots: {unaudited_entries}")


def run_stage(name: str) -> bytes:
    """Run one named stage and require an exact byte artifact."""
    validate_registration()
    try:
        runner = RUNNERS[name]
    except KeyError:
        raise ValueError(f"unknown determinism stage: {name}") from None
    output = runner()
    if not isinstance(output, bytes):
        raise TypeError(f"determinism stage {name!r} returned {type(output).__name__}, not bytes")
    return output
