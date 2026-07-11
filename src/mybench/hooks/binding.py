"""Opt-in commit-binding hook (MYB-3.5, ADR-0001 §4).

Install (`python -m mybench.hooks install <repo>`) writes ONE file:
``<repo>/.git/hooks/post-commit``. Never global — no ``core.hooksPath``, no
template dirs, no other repo touched. The hook no-ops (in shell, before
Python even starts) unless ``.mybench/commit-binding-enabled`` exists in the
worktree: installation and activation are two separate explicit acts.

On an enabled commit, exactly one binding row is appended to the ledger:
commit hash, committer timestamp (UTC), and an opaque keyed-HMAC repo id.
The commit message, diff, filenames, and branch name have no code path into
the ledger (they are never even read). Hook failures never block or dirty a
commit: every error is swallowed to ``<data-dir>/hooks.log`` (exception
class only — messages can embed paths), or silently if the data dir itself
is unavailable.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from mybench import paths
from mybench.ledger import Ledger

MARKER_RELPATH = Path(".mybench") / "commit-binding-enabled"
HOOK_SENTINEL = "# installed by mybench hooks (commit-binding)"

HOOK_TEMPLATE = """#!/bin/sh
{sentinel}
# Opt-in per repo: hard no-op unless the worktree carries the marker file.
top="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
[ -f "$top/.mybench/commit-binding-enabled" ] || exit 0
{python} -m mybench.hooks run >/dev/null 2>&1 || true
exit 0
"""


class HookError(RuntimeError):
    pass


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


def install(repo: str) -> Path:
    """Install the post-commit hook into exactly this repo's .git/hooks."""
    if repo.startswith("-"):
        raise HookError(f"not a repo path: {repo!r} (global installs are refused by design)")
    top = Path(repo).resolve()
    git_dir = top / ".git"
    if not git_dir.is_dir():
        raise HookError(f"{top} is not the top level of a git worktree")
    hook_path = git_dir / "hooks" / "post-commit"
    if hook_path.exists() and HOOK_SENTINEL not in hook_path.read_text():
        raise HookError(f"{hook_path} exists and is not a mybench hook — refusing to overwrite")
    hook_path.parent.mkdir(exist_ok=True)
    hook_path.write_text(HOOK_TEMPLATE.format(sentinel=HOOK_SENTINEL, python=sys.executable))
    hook_path.chmod(0o755)
    return hook_path


def repo_identity(top: Path) -> str:
    """Opaque keyed repo id (OQ #9): HMAC over the realpath, never the path itself."""
    key = paths.ensure_session_scope_key()
    return hmac.new(key, b"repo:" + os.fsencode(top.resolve()), hashlib.sha256).hexdigest()[:16]


def _log_error(exc: Exception) -> None:
    try:
        paths.ensure_data_dir()
        line = (
            f"{datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"post-commit error type={type(exc).__name__}\n"
        )
        fd = os.open(paths.data_dir() / "hooks.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(line)
    except Exception:  # noqa: BLE001 — nowhere safe left to report; stay silent
        pass


def _committer_ts(repo: Path, commit_hash: str) -> str:
    committer_iso = _git(repo, "show", "-s", "--format=%cI", commit_hash)
    return datetime.fromisoformat(committer_iso).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cwd: Path | None = None) -> int:
    """Post-commit entry point. Always returns 0 — a hook must never block a commit."""
    try:
        cwd = cwd if cwd is not None else Path.cwd()
        top = Path(_git(cwd, "rev-parse", "--show-toplevel"))
        if not (top / MARKER_RELPATH).is_file():
            return 0  # belt-and-braces: the shell shim already checked
        commit_hash = _git(cwd, "rev-parse", "HEAD")
        Ledger().append_binding(
            commit_hash=commit_hash,
            commit_ts=_committer_ts(cwd, commit_hash),
            repo_id=repo_identity(top),
        )
    except Exception as exc:  # noqa: BLE001 — never block the commit
        _log_error(exc)
    return 0


def reconcile(cwd: Path | None = None) -> int:
    """Bind every HEAD-reachable commit in an enrolled repo that lacks a binding row (MYB-3.7).

    A catch-up sweep for the commit-creation paths the ``post-commit`` hook can
    never see: ``git rebase`` (post-rewrite), merge commits (post-merge),
    commits authored on another machine/clone, and — the practical case —
    GitHub's server-side squash/rebase-merge, where the mainline commit is a
    brand-new hash that was never local until it is pulled. ``post-commit`` is
    thus a prompt-binding optimization on top of a sweep that guarantees
    completeness. Meant to run from the capture scan; safe to call anywhere.

    Walks ``git rev-list HEAD`` and appends one binding row per commit not
    already bound, deduping against existing ``binding`` rows by
    ``(repo_id, commit_hash)``. Idempotent: a re-run finds everything already
    bound and appends nothing. Returns the number of rows appended.

    OWNER DECISION (flagged in the PR, not silently made here): the ledger
    records no "enrollment point", so this binds ALL of HEAD's history as
    backfill, not only commits authored after opt-in. That mirrors the repo's
    existing IMPORTED/backfill honesty, but "all history vs since enrollment"
    is a judgment call for review.

    Never raises for a repo it cannot process — empty/unborn HEAD, shallow,
    detached, or no marker all return 0 without touching the ledger. (A
    shallow clone binds only the commits it actually has, which is correct.)
    """
    try:
        cwd = cwd if cwd is not None else Path.cwd()
        top = Path(_git(cwd, "rev-parse", "--show-toplevel"))
    except Exception:  # noqa: BLE001 — not a git worktree (or git unavailable)
        return 0
    if not (top / MARKER_RELPATH).is_file():
        return 0  # strictly opt-in, exactly like the hook — no marker, no sweep
    try:
        rev_out = _git(top, "rev-list", "HEAD")
    except Exception:  # noqa: BLE001 — unborn/empty HEAD, or an otherwise unreadable repo
        return 0
    commits = rev_out.split()
    if not commits:
        return 0
    repo_id = repo_identity(top)
    ledger = Ledger()
    try:
        bound = {
            row["commit_hash"]
            for row in ledger.rows()
            if row["type"] == "binding" and row["repo_id"] == repo_id
        }
    except Exception as exc:  # noqa: BLE001 — an unreadable ledger is not ours to repair here
        _log_error(exc)
        return 0
    appended = 0
    for commit_hash in commits:
        if commit_hash in bound:
            continue
        ledger.append_binding(
            commit_hash=commit_hash,
            commit_ts=_committer_ts(top, commit_hash),
            repo_id=repo_id,
        )
        bound.add(commit_hash)  # guard against a hash appearing twice in rev-list output
        appended += 1
    return appended
