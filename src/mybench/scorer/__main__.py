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
from pathlib import Path

from mybench.anchor.publish import staged_files
from mybench.ledger import Ledger
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

    rows = Ledger().rows()
    batches = [
        json.loads(f.read_bytes()) for f in staged_files() if f.suffix == ".json"
    ]
    enrolled = {}
    for spec in args.enrolled_repo:
        name, _, path = spec.partition("=")
        enrolled[name] = _repo_facts(Path(path))
    unknown = sorted(set(args.public) - set(enrolled))
    if unknown:
        print(f"error: --public names no --enrolled-repo entry: {', '.join(unknown)}",
              file=sys.stderr)
        return 1
    # MYB-6.11: the public+named assertion is typed per repo, never inferred —
    # an entry without it makes score() refuse the whole report (fail-closed).
    for name in args.public:
        enrolled[name]["public"] = True
    try:
        report_bytes = score(
            rows,
            batches,
            generated_at=args.generated_at,
            report_version=args.report_version,
            enrolled=enrolled or None,
        )
    except ScoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    report = json.loads(report_bytes)
    errors = sorted(load_validator("report.schema.json").iter_errors(report), key=str)
    if errors:
        print(f"error: report failed schema validation: {errors[0].message}", file=sys.stderr)
        return 1
    if args.out:
        Path(args.out).write_bytes(report_bytes)
    else:
        sys.stdout.buffer.write(report_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
