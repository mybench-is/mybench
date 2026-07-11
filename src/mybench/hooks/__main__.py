"""CLI: ``python -m mybench.hooks install|enroll <repo>`` / ``… run`` / ``… reconcile [repo]``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mybench.hooks.binding import HookError, enroll, install, reconcile, run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-hooks")
    sub = parser.add_subparsers(dest="command", required=True)
    p_install = sub.add_parser("install", help="install the opt-in post-commit hook into ONE repo")
    p_install.add_argument("repo", help="path to the repo worktree top level (never global)")
    p_enroll = sub.add_parser(
        "enroll", help="install + activate + stamp the enrollment point (HEAD at opt-in) for ONE repo"
    )
    p_enroll.add_argument("repo", help="path to the repo worktree top level (never global)")
    sub.add_parser("run", help="post-commit entry point (called by the installed hook)")
    p_reconcile = sub.add_parser(
        "reconcile", help="bind since-enrollment commits missed by post-commit (rebase/merge/squash)"
    )
    p_reconcile.add_argument(
        "repo", nargs="?", default=None, help="repo worktree (default: current directory)"
    )
    args = parser.parse_args(argv)

    if args.command == "run":
        return run()
    if args.command == "reconcile":
        reconcile(Path(args.repo) if args.repo else None)
        return 0
    if args.command == "enroll":
        try:
            record = enroll(args.repo)
        except HookError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(
            f"enrolled {args.repo}\n"
            f"  enrollment point: {record['enroll_commit'] or '(unborn HEAD — binds from first commit)'}"
        )
        return 0
    try:
        hook_path = install(args.repo)
    except HookError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"installed {hook_path}\n"
        f"NOT active yet: to opt this repo in, create the marker file\n"
        f"  {args.repo}/.mybench/commit-binding-enabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
