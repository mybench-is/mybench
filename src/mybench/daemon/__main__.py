"""Run the capture daemon: ``python -m mybench.daemon --watch DIR:SOURCE …``.

Owner entry point and the subprocess target for the MYB-2.6 crash-recovery
harness. Watches come from explicit arguments or the consented private scan
config; there is no implicit home-directory discovery here.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from mybench.daemon.capture import Daemon, DaemonConfig, WatchSpec
from mybench.scan_config import load


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-daemon")
    parser.add_argument(
        "--watch",
        action="append",
        default=[],
        metavar="DIR:SOURCE",
        help="transcript dir and source kind (repeatable)",
    )
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--scans", type=int, default=None, help="stop after N scans")
    parser.add_argument("--once", action="store_true", help="single scan, then exit")
    parser.add_argument(
        "--archive",
        action="store_true",
        help=(
            "keep an exact private local copy of committed transcript records "
            "(default: disabled)"
        ),
    )
    args = parser.parse_args(argv)

    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    try:
        stored = load()
    except Exception:  # noqa: BLE001 - never echo a private config path/value
        parser.error("private scan config could not be loaded")
    watches = []
    for spec in args.watch:
        directory, separator, source = spec.rpartition(":")
        if not separator or not directory or not source:
            parser.error("invalid --watch; expected DIR:SOURCE")
        watches.append(WatchSpec(Path(directory), source))
    if not watches:
        if stored is None or not stored.watches:
            parser.error("no watches configured; pass --watch or accept discovery proposals")
        watches = list(stored.watches)
    daemon = Daemon(
        DaemonConfig(
            watches=tuple(watches),
            archive_enabled=args.archive,
            exclusions=stored.exclusions if stored is not None else (),
        )
    )
    if args.once:
        daemon.scan_once()
    else:
        daemon.run(interval=args.interval, max_scans=args.scans)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
