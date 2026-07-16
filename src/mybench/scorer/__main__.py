"""CLI wrapper for the pure scorer: gathers inputs, validates, writes.

    python -m mybench.scorer --generated-at 2026-07-09T00:00:00Z \
        [--enrolled-repo NAME=PATH --public NAME]... [--out report.json]

All impurity (ledger/anchor reads, git queries, clock-free by design —
generated_at is required) lives here; mybench/scorer/score.py stays pure.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from mybench import paths
from mybench.anchor.event import EventError, verify_event
from mybench.anchor.publish import EVENT_RE, staged_files
from mybench.ledger import Ledger, LedgerError
from mybench.schemas import load_validator
from mybench.scorer.score import ScoreError, score


def _repo_facts(path: Path) -> dict:
    def git(*args):
        return subprocess.run(
            ["git", "-C", str(path), *args], capture_output=True, text=True, check=True
        ).stdout.strip()

    marker_added = git(
        "log", "--diff-filter=A", "--format=%H", "--", ".mybench/commit-binding-enabled"
    ).splitlines()[-1]
    has_parent = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--verify", "-q", f"{marker_added}~1"],
        capture_output=True,
    ).returncode == 0
    # Commits since enrollment, INCLUDING the marker commit itself (it was bound).
    rev_range = f"{marker_added}~1..HEAD" if has_parent else "HEAD"
    commits = git("rev-list", rev_range).splitlines()
    return {"tip": git("rev-parse", "HEAD"), "commits": commits}


def _anchor_events() -> list[dict]:
    """Load date-only events from private staging plus the local published clone."""
    by_path: dict[str, bytes] = {}
    candidates = list(staged_files())
    clone = paths.data_dir() / "anchors-repo"
    if clone.is_dir():
        candidates.extend(
            (path, path.relative_to(clone).as_posix())
            for path in sorted((clone / "anchors").rglob("*.json"))
        )
    for path, relative in candidates:
        if not EVENT_RE.match(relative):
            continue
        encoded = path.read_bytes()
        if relative in by_path and by_path[relative] != encoded:
            raise ScoreError(f"conflicting staged/published anchor event: {relative}")
        by_path[relative] = encoded
    events = []
    for relative in sorted(by_path):
        try:
            event = json.loads(by_path[relative])
            verify_event(event)
        except (EventError, ValueError) as exc:
            raise ScoreError(f"invalid anchor event {relative}: {exc}") from exc
        expected = f"anchors/{event['identity_id']}/{event['date'].replace('-', '/')}.json"
        if relative != expected:
            raise ScoreError(f"anchor event path does not match identity/date: {relative}")
        events.append(event)
    return events


def build_report(
    *,
    generated_at: str,
    report_version: str = "v0",
    enrolled_specs: Sequence[str] = (),
    public_names: Sequence[str] = (),
) -> bytes:
    """Gather local scorer inputs and return one validated report artifact."""
    enrolled = {}
    for spec in enrolled_specs:
        name, _, path = spec.partition("=")
        if not name or not path or name in enrolled:
            raise ScoreError("--enrolled-repo entries must be unique NAME=PATH values")
        enrolled[name] = _repo_facts(Path(path))
    unknown = sorted(set(public_names) - set(enrolled))
    if unknown:
        raise ScoreError(f"--public names no --enrolled-repo entry: {', '.join(unknown)}")
    # MYB-6.11: the public+named assertion is typed per repo, never inferred —
    # an entry without it makes score() refuse the whole report (fail-closed).
    for name in public_names:
        enrolled[name]["public"] = True
    ledger = Ledger()
    ledger.verify_chain()
    rows = ledger.rows()
    anchors = _anchor_events()
    report_bytes = score(
        rows,
        anchors,
        generated_at=generated_at,
        report_version=report_version,
        enrolled=enrolled or None,
    )
    report = json.loads(report_bytes)
    errors = sorted(load_validator("report.schema.json").iter_errors(report), key=str)
    if errors:
        raise ScoreError(f"report failed schema validation: {errors[0].message}")
    return report_bytes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-scorer")
    parser.add_argument("--generated-at", required=True, help="UTC RFC3339; scorer has no clock")
    parser.add_argument("--report-version", default="v0")
    parser.add_argument(
        "--enrolled-repo",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="opted-in repo for binding_coverage; scores only when also asserted "
        "with --public NAME (MYB-6.11 fail-closed guard)",
    )
    parser.add_argument(
        "--public",
        action="append",
        default=[],
        metavar="NAME",
        help="assert this --enrolled-repo NAME is a PUBLIC, named repo: publishes "
        "its name and raw tip and emits PROVEN binding_coverage. One per repo — "
        "publicness is a per-repo human assertion, never implied by enrollment",
    )
    parser.add_argument("--out", help="write report here (default: stdout)")
    args = parser.parse_args(argv)

    try:
        report_bytes = build_report(
            generated_at=args.generated_at,
            report_version=args.report_version,
            enrolled_specs=args.enrolled_repo,
            public_names=args.public,
        )
    except (LedgerError, ScoreError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.out:
        Path(args.out).write_bytes(report_bytes)
    else:
        sys.stdout.buffer.write(report_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
