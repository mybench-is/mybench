"""CLI: cut anchor batches, upgrade proofs, publish through the leak gate.

    python -m mybench.anchor cut [--calendar URL ...]
    python -m mybench.anchor upgrade
    python -m mybench.anchor publish --remote URL [--push]

``publish`` is dry-run by default: it prints the exact files/bytes that
would be pushed; nothing leaves the machine without ``--push``.
"""

from __future__ import annotations

import argparse
import json
import sys

from mybench.anchor import ots
from mybench.anchor.batch import AnchorError, build_batch
from mybench.anchor.publish import PublishError, publish, staged_files


def _latest_staged_batch() -> dict | None:
    batches = [
        json.loads(f.read_bytes()) for f in staged_files() if f.suffix == ".json"
    ]
    return max(batches, key=lambda b: b["row_end"]) if batches else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-anchor")
    sub = parser.add_subparsers(dest="command", required=True)
    p_cut = sub.add_parser("cut", help="build + OTS-stamp the next batch into staging")
    p_cut.add_argument("--calendar", action="append", help="override calendar URL (repeatable)")
    sub.add_parser("upgrade", help="try to upgrade all staged proofs to Bitcoin attestations")
    p_pub = sub.add_parser("publish", help="gate + (with --push) publish the staged tree")
    p_pub.add_argument("--remote", required=True, help="anchors repo remote URL")
    p_pub.add_argument("--push", action="store_true", help="actually push (default: dry run)")
    args = parser.parse_args(argv)

    try:
        if args.command == "cut":
            batch = build_batch(previous=_latest_staged_batch())
            calendars = tuple(args.calendar) if args.calendar else ots.DEFAULT_CALENDARS
            artifact, proof = ots.stamp_batch(batch, calendars=calendars)
            print(
                f"cut rows [{batch['row_start']}, {batch['row_end']}) "
                f"sessions={batch['session_count']} root={batch['root']}\n"
                f"staged {artifact.name} + {proof.name}"
            )
        elif args.command == "upgrade":
            proofs = [f for f in staged_files() if f.name.endswith(".root.ots")]
            confirmed = sum(ots.upgrade_batch_proof(p) for p in proofs)
            print(f"proofs: {len(proofs)} staged, {confirmed} bitcoin-confirmed")
        else:
            result = publish(args.remote, push=args.push)
            for f in result["files"]:
                print(f"{f['sha256']}  {f['bytes']:>7}  {f['name']}")
            if result["dry_run"]:
                print("dry run — nothing pushed (use --push to publish)")
            elif result["commit"]:
                print(f"pushed {len(result['pushed'])} file(s) as {result['commit']}")
            else:
                print("remote already up to date")
    except (AnchorError, ots.OtsError, PublishError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
