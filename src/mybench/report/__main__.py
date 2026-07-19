"""CLI: render legacy HTML or assemble a signed private local report bundle.

Legacy renderer compatibility::

    python -m mybench.report --report report.json --out index.html

Bundle assembly captures the local scorer inputs itself so a supplied report
can never be paired with unrelated current evidence state.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from mybench.report.cli import (
    assemble_bundle,
    capture_report_inputs,
    derive_report_artifacts,
    open_report,
)
from mybench.report.page import PageError, render_page


def _generated_at(raw: str | None) -> str:
    if raw is None:
        return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.now(UTC).utcoffset():
        raise ValueError("generated-at must be UTC")
    return parsed.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _legacy_render(args: argparse.Namespace) -> int:
    try:
        page = render_page(
            json.loads(Path(args.report).read_bytes()),
            anchors_url=args.anchors_url,
            handle=args.handle,
            public=True,
        )
        Path(args.out).write_bytes(page)
    except (OSError, ValueError, PageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.out} ({len(page)} bytes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-report")
    parser.add_argument("--report", help="legacy renderer input report JSON (requires --out)")
    parser.add_argument("--out", help="legacy renderer output HTML (requires --report)")
    parser.add_argument(
        "--anchors-url",
        default="https://mybench.is/anchors",
        help="anchors location rendered into the page",
    )
    parser.add_argument("--handle", help="owner handle for page identity + canonical URL")
    parser.add_argument(
        "--generated-at",
        help="UTC RFC3339 scorer time (default: current UTC; provide for reproducible builds)",
    )
    parser.add_argument("--report-version", default="v0")
    parser.add_argument(
        "--enrolled-repo",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="public named repo scorer input (repeatable)",
    )
    parser.add_argument(
        "--public",
        action="append",
        default=[],
        metavar="NAME",
        help="assert that an enrolled named repo is public (repeatable)",
    )
    parser.add_argument("--open", action="store_true", help="open the private file URL")
    args = parser.parse_args(argv)

    if bool(args.report) != bool(args.out):
        parser.error("--report and --out must be used together")
    if args.report:
        if args.open or args.enrolled_repo or args.public or args.generated_at:
            parser.error("bundle assembly options cannot be combined with --report/--out")
        return _legacy_render(args)

    try:
        snapshot = capture_report_inputs(
            enrolled_specs=args.enrolled_repo,
            public_names=args.public,
        )
        report, manifest = derive_report_artifacts(
            snapshot,
            generated_at=_generated_at(args.generated_at),
            report_version=args.report_version,
        )
        directory = assemble_bundle(
            report,
            manifest,
            anchors_url=args.anchors_url,
            handle=args.handle,
        )
        opened = open_report(directory / "index.html") if args.open else None
    except Exception:  # noqa: BLE001 - local scorer paths and state stay out of CLI errors
        print("error: local report bundle failed", file=sys.stderr)
        return 1
    print(
        f"report ready: id={directory.name} (private, local only)"
        + ("; browser unavailable" if args.open and not opened else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
