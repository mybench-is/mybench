"""CLI: ``python -m mybench.hooks install <repo>`` / ``… run`` (post-commit entry)."""

from __future__ import annotations

import argparse
import sys

from mybench.hooks.binding import HookError, install, run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-hooks")
    sub = parser.add_subparsers(dest="command", required=True)
    p_install = sub.add_parser("install", help="install the opt-in post-commit hook into ONE repo")
    p_install.add_argument("repo", help="path to the repo worktree top level (never global)")
    sub.add_parser("run", help="post-commit entry point (called by the installed hook)")
    args = parser.parse_args(argv)

    if args.command == "run":
        return run()
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
