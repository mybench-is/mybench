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
from enum import Enum

EntryCallable = Callable[..., object]


@dataclass(frozen=True)
class Invocation:
    """Synthetic arguments for one gate-owned production call."""

    args: tuple[object, ...]
    kwargs: Mapping[str, object]


InvocationFactory = Callable[[], Invocation]


class ResultEncoding(Enum):
    """Gate-owned conversion from a production result to artifact bytes."""

    BYTES = "bytes"
    CANONICAL_JSON_LINE = "canonical-json-line"


@dataclass(frozen=True)
class EntryPoint:
    """Importable production callable that the gate invokes directly."""

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

    The gate invokes the resolved production ``entrypoint`` with arguments from
    a same-name invocation factory, then applies only the declared built-in
    result encoding. ``discovery_entry`` marks scorer/parser/normalizer/report/
    publication implementations that fail closed against package-root
    discovery. Substrate artifacts remain byte-gated without being
    misclassified as pipeline roots.
    """

    name: str
    entrypoint: EntryPoint
    result_encoding: ResultEncoding
    discovery_entry: bool
    audit_roots: tuple[str, ...]


def _activity_report_json() -> Invocation:
    # Reuse MYB-4.2's fixed synthetic corpus rather than inventing a second
    # scorer fixture for this gate.
    from tests.scorer.test_score import (
        FIXED_BATCHES,
        FIXED_ENROLLED,
        FIXED_ROWS,
    )

    return Invocation(
        args=(FIXED_ROWS, FIXED_BATCHES),
        kwargs={
            "generated_at": "2026-07-09T00:00:00Z",
            "enrolled": FIXED_ENROLLED,
            "allow_synthetic": True,
        },
    )


def _signed_claim() -> Invocation:
    # Reuse MYB-10.1's fixed synthetic key and claim fixture.  No owner key is
    # loaded and no local data directory is touched.
    from tests.claims.test_envelope import make_signed

    return Invocation(args=(make_signed(),), kwargs={})


def _registry_disclosure_manifest() -> Invocation:
    from mybench.registry import EMPLOYER_SAFE, Registry

    return Invocation(args=(Registry.load(), EMPLOYER_SAFE), kwargs={})


def _static_report_html() -> Invocation:
    from tests.scorer.test_score import fixed_report_bytes

    return Invocation(
        args=(json.loads(fixed_report_bytes()),),
        kwargs={
            "anchors_url": "https://github.com/synthetic/mybench-anchors",
            "handle": "synthetic-owner",
        },
    )


def _claude_normalized_corpus() -> Invocation:
    # Fixed synthetic records and nonces only.  The production entry point
    # receives verified bytes explicitly and cannot discover owner data.
    from tests.normalizer.synthetic import synthetic_normalizer_input

    return Invocation(args=(synthetic_normalizer_input().sessions,), kwargs={})


def _codex_normalized_corpus() -> Invocation:
    # Fixed synthetic rollout records and nonces only. The Codex adapter is a
    # pure sibling stage and receives no ambient rollout-directory authority.
    from tests.normalizer.synthetic import synthetic_codex_normalizer_input

    return Invocation(args=(synthetic_codex_normalizer_input().sessions,), kwargs={})


def _session_timing_output() -> Invocation:
    # The exact timestamp-bearing artifact is private/local-only and uses the
    # fixed synthetic Codex canary corpus. The production output is already
    # closed and identifier-free.
    from tests.normalizer.synthetic import synthetic_codex_normalizer_input

    return Invocation(args=(synthetic_codex_normalizer_input().sessions,), kwargs={})


def _agent_hours_profile() -> Invocation:
    from tests.scorer.test_agent_hours import _timing

    return Invocation(
        args=([_timing() for _ in range(5)],),
        kwargs={"anchored_span_days": 20},
    )


def _git_normalized_corpus() -> Invocation:
    # Fixed, path-free subject-only repository records. The production stage
    # receives no Git, enrollment, filesystem, or author-identity authority.
    from tests.normalizer.repo_synthetic import synthetic_repo_evidence_input

    return Invocation(args=(synthetic_repo_evidence_input().snapshots,), kwargs={})


def _reference_target_join_corpus() -> Invocation:
    # Both normalized inputs and every candidate edge come from fixed synthetic
    # fixtures. The production join stage receives commitments only.
    from tests.normalizer.reference_synthetic import synthetic_reference_target_input

    synthetic = synthetic_reference_target_input()
    return Invocation(
        args=(synthetic.transcript_artifact, synthetic.repo_artifact, synthetic.joins),
        kwargs={},
    )


RUNNERS: dict[str, InvocationFactory] = {
    "agent-hours-profile": _agent_hours_profile,
    "activity-report-json": _activity_report_json,
    "claude-normalized-corpus": _claude_normalized_corpus,
    "codex-normalized-corpus": _codex_normalized_corpus,
    "git-normalized-corpus": _git_normalized_corpus,
    "reference-target-join-corpus": _reference_target_join_corpus,
    "session-timing-output": _session_timing_output,
    "signed-claim": _signed_claim,
    "registry-disclosure-manifest": _registry_disclosure_manifest,
    "static-report-html": _static_report_html,
}

# Parser/publication-preview implementations remain reserved fail-closed roots.
# Claim/registry outputs are valuable deterministic substrates, but are not
# pipeline discovery roots themselves.
STAGES = (
    Stage(
        "activity-report-json",
        EntryPoint("mybench.scorer.score", "score"),
        ResultEncoding.BYTES,
        True,
        ("mybench.scorer.score",),
    ),
    Stage(
        "agent-hours-profile",
        EntryPoint("mybench.scorer.agent_hours", "score_agent_hours"),
        ResultEncoding.CANONICAL_JSON_LINE,
        True,
        ("mybench.scorer.agent_hours",),
    ),
    Stage(
        "claude-normalized-corpus",
        EntryPoint("mybench.normalizer.claude", "normalize_claude"),
        ResultEncoding.BYTES,
        True,
        ("mybench.normalizer.claude",),
    ),
    Stage(
        "codex-normalized-corpus",
        EntryPoint("mybench.normalizer.codex", "normalize_codex"),
        ResultEncoding.BYTES,
        True,
        ("mybench.normalizer.codex",),
    ),
    Stage(
        "session-timing-output",
        EntryPoint(
            "mybench.normalizer.session_timing",
            "normalize_session_timing_bytes",
        ),
        ResultEncoding.BYTES,
        True,
        ("mybench.normalizer.session_timing",),
    ),
    Stage(
        "git-normalized-corpus",
        EntryPoint("mybench.normalizer.repo", "normalize_repo_evidence"),
        ResultEncoding.BYTES,
        True,
        ("mybench.normalizer.repo",),
    ),
    Stage(
        "reference-target-join-corpus",
        EntryPoint(
            "mybench.normalizer.reference_join",
            "normalize_reference_target_joins",
        ),
        ResultEncoding.BYTES,
        True,
        ("mybench.normalizer.reference_join",),
    ),
    Stage(
        "signed-claim",
        EntryPoint("mybench.claims.envelope", "claim_file_bytes"),
        ResultEncoding.BYTES,
        False,
        ("mybench.claims.envelope",),
    ),
    Stage(
        "registry-disclosure-manifest",
        EntryPoint("mybench.registry", "Registry.disclosure_manifest"),
        ResultEncoding.CANONICAL_JSON_LINE,
        False,
        ("mybench.registry",),
    ),
    Stage(
        "static-report-html",
        EntryPoint("mybench.report.page", "render_page"),
        ResultEncoding.BYTES,
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
        stage.name for stage in stages if stage.entrypoint.module not in stage.audit_roots
    )
    if unaudited_entries:
        raise ValueError(f"entry-point modules absent from their audit roots: {unaudited_entries}")
    return {stage.name: stage.entrypoint.resolve() for stage in stages}


def execute_stage(
    stage: Stage,
    invocation_factory: InvocationFactory,
    entry: EntryCallable | None = None,
) -> bytes:
    """Own the production invocation and derive bytes only from its result."""
    target = stage.entrypoint.resolve() if entry is None else entry
    invocation = invocation_factory()
    if type(invocation) is not Invocation:
        raise TypeError(
            f"determinism runner {stage.name!r} returned "
            f"{type(invocation).__name__}, not Invocation"
        )

    result = target(*invocation.args, **dict(invocation.kwargs))
    if stage.result_encoding is ResultEncoding.BYTES:
        if not isinstance(result, bytes):
            raise TypeError(
                f"determinism stage {stage.name!r} returned {type(result).__name__}, not bytes"
            )
        return result
    if stage.result_encoding is ResultEncoding.CANONICAL_JSON_LINE:
        if not isinstance(result, dict):
            raise TypeError(
                f"determinism stage {stage.name!r} returned {type(result).__name__}, not dict"
            )
        from mybench.claims import canonical_bytes

        return canonical_bytes(result) + b"\n"
    raise ValueError(
        f"determinism stage {stage.name!r} has unknown result encoding: {stage.result_encoding!r}"
    )


def run_stage(name: str) -> bytes:
    """Run one named stage and require an exact byte artifact."""
    entries = validate_registration()
    try:
        stage = next(stage for stage in STAGES if stage.name == name)
        runner = RUNNERS[name]
    except (KeyError, StopIteration):
        raise ValueError(f"unknown determinism stage: {name}") from None
    return execute_stage(stage, runner, entries[name])
