"""CLI for opt-in git binding and machine-local Claude lifecycle hooks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mybench.hooks.binding import HookError, enroll, install, reconcile, run
from mybench.hooks import lifecycle
from mybench.paths import PathsError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-hooks")
    sub = parser.add_subparsers(dest="command", required=True)
    p_install = sub.add_parser("install", help="install the opt-in post-commit hook into ONE repo")
    p_install.add_argument("repo", help="path to the repo worktree top level (never global)")
    p_enroll = sub.add_parser(
        "enroll", help="install + activate + stamp the enrollment point (HEAD at opt-in) for ONE repo"
    )
    p_enroll.add_argument("repo", help="path to the repo worktree top level (never global)")
    p_enroll.add_argument(
        "--at",
        metavar="COMMIT",
        default=None,
        help="owner override: stamp the enrollment point at this revision (HEAD at the "
        "TRUE opt-in date) instead of deriving it — for repos enrolled before record-"
        "stamping existed; must be an ancestor of HEAD, refused if a record already "
        "exists with a different point",
    )
    sub.add_parser("run", help="post-commit entry point (called by the installed hook)")
    p_reconcile = sub.add_parser(
        "reconcile", help="bind since-enrollment commits missed by post-commit (rebase/merge/squash)"
    )
    p_reconcile.add_argument(
        "repo", nargs="?", default=None, help="repo worktree (default: current directory)"
    )
    p_lifecycle = sub.add_parser(
        "lifecycle", help="manage the opt-in Claude Code lifecycle adapter"
    )
    lifecycle_sub = p_lifecycle.add_subparsers(dest="lifecycle_command", required=True)
    lifecycle_sub.add_parser("run", help="hook entry point (reads Claude JSON from stdin)")
    lifecycle_sub.add_parser(
        "install", help="install async handlers in the machine-local user settings"
    )
    lifecycle_sub.add_parser(
        "uninstall", help="remove only the machine-local mybench lifecycle handlers"
    )
    args = parser.parse_args(argv)

    if args.command == "lifecycle":
        if args.lifecycle_command == "run":
            return lifecycle.run_from_stdin()
        settings_path = lifecycle.default_settings_path()
        try:
            changed = (
                lifecycle.install(settings_path)
                if args.lifecycle_command == "install"
                else lifecycle.uninstall(settings_path)
            )
        except lifecycle.LifecycleError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        action = "installed" if args.lifecycle_command == "install" else "uninstalled"
        if changed:
            print(f"{action} {', '.join(changed)} in {settings_path}")
        else:
            print(f"unchanged {settings_path}")
        return 0
    if args.command == "run":
        return run()
    if args.command == "reconcile":
        try:
            n = reconcile(Path(args.repo) if args.repo else None)
        except PathsError as exc:  # data-dir integrity: surfaced, not a traceback
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"bound {n} previously-missed commit(s)")
        return 0
    if args.command == "enroll":
        try:
            record = enroll(args.repo, at=args.at)
        except (HookError, PathsError) as exc:
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
