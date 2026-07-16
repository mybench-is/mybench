"""CLI: cut anchor events, upgrade proofs, publish through the leak gate (layout v1).

    python -m mybench.anchor cut [--date YYYY-MM-DD] [--calendar URL ...]
    python -m mybench.anchor upgrade
    python -m mybench.anchor publish --remote URL [--push]

``publish`` is dry-run by default. Pending proofs never publish: ``cut``
stages event + pending proof; ``upgrade`` refreshes staged proofs;
``publish`` pushes events immediately and each proof only once confirmed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from mybench import paths
from mybench.anchor import ots
from mybench.anchor.batch import AnchorError, build_batch
from mybench.anchor.event import EventError, build_event, event_relpaths, stage_event
from mybench.anchor.publish import PublishError, publish, staged_files
from mybench.identity import local_identity_id
from mybench.ledger import Ledger, LedgerError


@dataclass(frozen=True)
class CutResult:
    event: dict
    event_path: Path
    proof_path: Path
    receipt: dict


def _append_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _known_row_end(identity_id: str, staging: Path, clone: Path) -> int:
    last = 0
    for base in (staging / "anchors" / identity_id, clone / "anchors" / identity_id):
        if base.is_dir():
            for p in base.rglob("*.json"):
                if p.suffix == ".json":
                    last = max(last, json.loads(p.read_bytes())["row_end"])
    return last


def cut(
    date: str,
    calendars: Sequence[str],
    *,
    ledger: Ledger | None = None,
    receipt_clock: Callable[[], datetime] | None = None,
    append_ts: str | None = None,
) -> CutResult:
    """Build, stamp, stage, then append one private receipt observation.

    The stage-before-append order is intentional.  If the process stops after
    staging, the absent receipt remains unknown; this function never recovers
    one from a filesystem, Git, event-date, or retry clock.
    """
    staging = paths.anchors_dir()
    clone = paths.data_dir() / "anchors-repo"
    identity_id = local_identity_id()
    rel_event, _ = event_relpaths(identity_id, date)
    if (staging / rel_event).exists() or (clone / rel_event).exists():
        raise EventError(f"{rel_event} exists — one event per identity per UTC day")

    last = _known_row_end(identity_id, staging, clone)
    ledger = ledger if ledger is not None else Ledger()
    batch = build_batch(ledger, previous={"row_end": last} if last else None)
    event = build_event(batch, ledger.rows(), date=date)
    stamp_kwargs = {"clock": receipt_clock} if receipt_clock is not None else {}
    stamped = ots.stamp_root_observed(
        bytes.fromhex(event["root"]), calendars=calendars, **stamp_kwargs
    )
    event_path, proof_path = stage_event(event, stamped.proof, staging)
    receipt = ledger.append_anchor_receipt(
        staged_event=event,
        receipt_ts=stamped.receipt_ts,
        ts=append_ts if append_ts is not None else _append_now(),
    )
    if receipt is None:  # pre-existing daily-event guard makes this defensive only
        raise LedgerError("anchor cut unexpectedly replayed an existing receipt")
    return CutResult(event, event_path, proof_path, receipt)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-anchor")
    sub = parser.add_subparsers(dest="command", required=True)
    p_cut = sub.add_parser("cut", help="build + OTS-stamp today's anchor event into staging")
    p_cut.add_argument("--date", help="UTC date (default: today)")
    p_cut.add_argument("--calendar", action="append", help="override calendar URL (repeatable)")
    sub.add_parser("upgrade", help="try to upgrade all staged proofs to Bitcoin attestations")
    p_pub = sub.add_parser("publish", help="gate + (with --push) publish the staged tree")
    p_pub.add_argument("--remote", required=True, help="anchors repo remote URL")
    p_pub.add_argument("--push", action="store_true", help="actually push (default: dry run)")
    args = parser.parse_args(argv)

    staging = paths.anchors_dir()
    try:
        if args.command == "cut":
            date = args.date or datetime.now(UTC).strftime("%Y-%m-%d")
            calendars = tuple(args.calendar) if args.calendar else ots.DEFAULT_CALENDARS
            result = cut(date, calendars)
            event = result.event
            print(
                f"cut rows [{event['row_start']}, {event['row_end']}) "
                f"sessions={event['session_count']} items={event['item_count']}\n"
                f"staged {result.event_path.relative_to(staging)} (+ pending proof); "
                "private receipt appended"
            )
        elif args.command == "upgrade":
            proofs = [p for p, rel in staged_files(staging) if rel.endswith(".json.ots")]
            confirmed = sum(ots.upgrade_batch_proof(p) for p in proofs)
            print(f"proofs: {len(proofs)} staged, {confirmed} bitcoin-confirmed")
        else:
            result = publish(args.remote, push=args.push)
            for f in result["files"]:
                print(f"{f['sha256']}  {f['bytes']:>7}  {f['path']}")
            if result["dry_run"]:
                print("dry run — nothing pushed (use --push to publish)")
            else:
                print(f"pushed {len(result['pushed'])} file(s) in "
                      f"{len(result['commits'])} signed commit(s)")
                for rel in result["pending"]:
                    print(f"withheld (pending Bitcoin confirmation): {rel}")
    except (AnchorError, EventError, LedgerError, ots.OtsError, PublishError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
