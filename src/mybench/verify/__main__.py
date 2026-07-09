"""CLI: ``python -m mybench.verify <anchors dir or git URL>`` — see verify/cli.py."""

from __future__ import annotations

import argparse

from mybench.verify.cli import VerifyFailure, render, verify_anchors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-verify")
    parser.add_argument("source", help="path to an anchors clone, or a git/https URL")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip the Bitcoin header cross-check (report heights for independent checking)",
    )
    args = parser.parse_args(argv)
    try:
        result = verify_anchors(args.source, check_bitcoin=not args.offline)
    except VerifyFailure as exc:
        print(f"mybench verify: FAIL\n  {exc}")
        return 1
    print(render(result))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
