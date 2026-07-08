"""Run the capture daemon: ``python -m mybench.daemon --watch DIR:SOURCE …``.

Owner entry point and the subprocess target for the MYB-2.6 crash-recovery
harness. Watches are always explicit (see capture.default_config for the
owner's real-location shortcut, which is refused in test mode).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from mybench.daemon.capture import Daemon, DaemonConfig, WatchSpec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-daemon")
    parser.add_argument(
        "--watch",
        action="append",
        required=True,
        metavar="DIR:SOURCE",
        help="transcript dir and source kind (repeatable)",
    )
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--scans", type=int, default=None, help="stop after N scans")
    parser.add_argument("--once", action="store_true", help="single scan, then exit")
    args = parser.parse_args(argv)

    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    watches = []
    for spec in args.watch:
        directory, _, source = spec.rpartition(":")
        watches.append(WatchSpec(Path(directory), source))
    daemon = Daemon(DaemonConfig(watches=tuple(watches)))
    if args.once:
        daemon.scan_once()
    else:
        daemon.run(interval=args.interval, max_scans=args.scans)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
