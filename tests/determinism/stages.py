"""Synthetic, byte-producing pipeline stages covered by the CI gate.

Keep the inputs here (or in an existing synthetic test helper) fixed and
explicit.  A stage may read packaged, committed metadata such as a schema or
the descriptor registry, but it must never discover owner data.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

EntryCallable = Callable[..., object]
Runner = Callable[[EntryCallable], bytes]


@dataclass(frozen=True)
class EntryPoint:
    """Importable production callable that a fixture runner must exercise."""

    module: str
    qualname: str

    def resolve(self) -> EntryCallable:
        value: object = importlib.import_module(self.module)
        for part in self.qualname.split("."):
            try:
                value = getattr(value, part)
            except AttributeError:
                raise ValueError(
                    f"determinism entry point does not exist: {self.module}:{self.qualname}"
                ) from None
        if not callable(value):
            raise ValueError(
                f"determinism entry point is not callable: {self.module}:{self.qualname}"
            )
        if getattr(value, "__module__", None) != self.module:
            raise ValueError(
                f"determinism entry point is not owned by {self.module}: {self.qualname}"
            )
        return value


@dataclass(frozen=True)
class Stage:
    """One byte artifact plus its discovery and static-audit contracts.

    Every runner receives the resolved production ``entrypoint`` and must call
    it. ``discovery_entry`` marks scorer/parser/normalizer/report/publication
    implementations that fail closed against package-root discovery. Substrate
    artifacts remain byte-gated without being misclassified as pipeline roots.
    """

    name: str
    entrypoint: EntryPoint
    discovery_entry: bool
    audit_roots: tuple[str, ...]


def _activity_report_json(entry: EntryCallable) -> bytes:
    # Reuse MYB-4.2's fixed synthetic corpus rather than inventing a second
    # scorer fixture for this gate.
    from tests.scorer.test_score import (
        FIXED_BATCHES,
        FIXED_ENROLLED,
        FIXED_ROWS,
    )

    return entry(
        FIXED_ROWS,
        FIXED_BATCHES,
        generated_at="2026-07-09T00:00:00Z",
        enrolled=FIXED_ENROLLED,
        allow_synthetic=True,
    )


def _signed_claim(entry: EntryCallable) -> bytes:
    # Reuse MYB-10.1's fixed synthetic key and claim fixture.  No owner key is
    # loaded and no local data directory is touched.
    from tests.claims.test_envelope import make_signed

    return entry(make_signed())


def _registry_disclosure_manifest(entry: EntryCallable) -> bytes:
    from mybench.claims import canonical_bytes
    from mybench.registry import EMPLOYER_SAFE, Registry

    manifest = entry(Registry.load(), EMPLOYER_SAFE)
    return canonical_bytes(manifest) + b"\n"


def _static_report_html(entry: EntryCallable) -> bytes:
    from tests.scorer.test_score import fixed_report_bytes

    return entry(
        json.loads(fixed_report_bytes()),
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
# implementation yet. Their owning stories add a Stage with discovery_entry
# set and a same-name bound runner. Claim/registry outputs are valuable
# deterministic substrates, but are not pipeline discovery roots themselves.
STAGES = (
    Stage(
        "activity-report-json",
        EntryPoint("mybench.scorer.score", "score"),
        True,
        ("mybench.scorer.score",),
    ),
    Stage(
        "signed-claim",
        EntryPoint("mybench.claims.envelope", "claim_file_bytes"),
        False,
        ("mybench.claims.envelope",),
    ),
    Stage(
        "registry-disclosure-manifest",
        EntryPoint("mybench.registry", "Registry.disclosure_manifest"),
        False,
        ("mybench.registry",),
    ),
    Stage(
        "static-report-html",
        EntryPoint("mybench.report.page", "render_page"),
        True,
        ("mybench.report.page",),
    ),
)


def validate_registration(
    stages: Sequence[Stage] = STAGES,
    runners: Mapping[str, object] = RUNNERS,
) -> dict[str, EntryCallable]:
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
        if stage.entrypoint.module not in stage.audit_roots
    )
    if unaudited_entries:
        raise ValueError(f"entry-point modules absent from their audit roots: {unaudited_entries}")
    return {stage.name: stage.entrypoint.resolve() for stage in stages}


class _BoundEntry:
    def __init__(self, target: EntryCallable):
        self.target = target
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        return self.target(*args, **kwargs)


def execute_stage(
    stage: Stage,
    runner: Runner,
    entry: EntryCallable | None = None,
) -> bytes:
    """Run a fixture through its owned entry point; constants cannot satisfy it."""
    target = stage.entrypoint.resolve() if entry is None else entry
    bound = _BoundEntry(target)
    output = runner(bound)
    if bound.calls == 0:
        raise ValueError(
            f"determinism runner {stage.name!r} did not invoke its bound entry point "
            f"{stage.entrypoint.module}:{stage.entrypoint.qualname}"
        )
    if not isinstance(output, bytes):
        raise TypeError(f"determinism stage {stage.name!r} returned {type(output).__name__}, not bytes")
    return output


def run_stage(name: str) -> bytes:
    """Run one named stage and require an exact byte artifact."""
    entries = validate_registration()
    try:
        stage = next(stage for stage in STAGES if stage.name == name)
        runner = RUNNERS[name]
    except (KeyError, StopIteration):
        raise ValueError(f"unknown determinism stage: {name}") from None
    return execute_stage(stage, runner, entries[name])
