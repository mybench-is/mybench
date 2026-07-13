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

:func:`enroll` (MYB-3.7) stamps an *enrollment point* — HEAD at opt-in — in
the data dir (never the repo or the ledger; invariant #2), and :func:`reconcile`
sweeps the SINCE-ENROLLMENT (LIVE) window: it binds every commit after the
enrollment point that the ``post-commit`` hook missed (rebase, merge, or a
GitHub server-side squash-merge born as a new hash). Pre-enrollment history
is backfill/IMPORTED and is NOT swept.
"""

from __future__ import annotations

import hashlib
import hmac
import json
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


def _derive_enroll_commit(top: Path) -> str:
    """The real enrollment point anchoring reconcile's ``enroll_commit..HEAD`` window.

    Not simply "HEAD now": a repo whose marker was committed in the past (the
    dogfooded mybench repo, live for a while) genuinely enrolled back then, so
    stamping "now" would mislabel its live history as pre-enrollment and make
    :func:`reconcile` miss the merge/squash commits ``post-commit`` never caught.

    - Marker TRACKED in git → the true enrollment is the commit that FIRST
      added it (``git log --diff-filter=A``); anchor at that commit's parent so
      the window includes the marker commit and everything after, matching the
      scorer's ``marker_added~1..HEAD`` convention. Marker added in the root
      commit (no parent) → ``""`` (no pre-history; bind all of HEAD).
    - Marker UNTRACKED (local-only, e.g. ``.git/info/exclude``) → they really
      enrolled now, so ``enroll_commit = HEAD``.
    - Unborn HEAD (no commits) → ``""``.
    """
    try:
        head = _git(top, "rev-parse", "HEAD")
    except subprocess.CalledProcessError:
        return ""  # unborn HEAD: no commits yet
    marker = MARKER_RELPATH.as_posix()
    try:
        _git(top, "ls-files", "--error-unmatch", marker)
    except subprocess.CalledProcessError:
        return head  # untracked marker: enrolling now, all of HEAD is pre-enrollment
    adds = _git(top, "log", "--diff-filter=A", "--format=%H", "--", marker).splitlines()
    if not adds:
        return head  # staged but not yet committed — treat as enrolling now
    marker_add = adds[-1]  # git log is newest-first; the last line is the first add
    try:
        return _git(top, "rev-parse", f"{marker_add}~1")
    except subprocess.CalledProcessError:
        return ""  # marker added in the root commit: no pre-history, bind all


def enroll(repo: str | Path, at: str | None = None) -> dict:
    """Opt this repo into commit-binding and stamp its enrollment point (MYB-3.7).

    Installs the ``post-commit`` hook (reusing :func:`install`), ensures the
    ``.mybench/commit-binding-enabled`` marker exists, then records the
    enrollment point in the data dir (``enrollments/<repo_id>.json``, mode
    0600), NEVER in the repo or the ledger (invariant #2). The point is the
    repo's REAL enrollment, not "HEAD now" — see :func:`_derive_enroll_commit`:
    a tracked marker anchors at the marker-add commit's parent; an untracked
    (local-only) marker anchors at current HEAD; an unborn HEAD records ``""``.

    ``at`` (owner override) stamps the point at that revision instead of
    deriving it — for a repo whose true opt-in predates record-stamping (an
    untracked-marker repo enrolled before this code existed: derivation would
    say "now" and permanently exclude the already-missed squash/merge commits
    from the sweep window). The revision must resolve to a commit that is an
    ancestor of (or equal to) HEAD. The record is local-only state, so a
    backdated point fabricates nothing: binding rows still carry their real
    append timestamps.

    First enrollment wins: if a record already exists it is returned unchanged,
    so a re-run never moves the point (idempotent) — and a conflicting ``at``
    raises rather than being silently ignored. ``enroll_commit=""`` means
    :func:`reconcile` binds all of HEAD, since there is no pre-enrollment
    history to exclude.

    Returns the enrollment record dict.
    """
    top = Path(repo).resolve()
    install(str(top))  # validates the worktree top level; refuses foreign/global hooks
    marker = top / MARKER_RELPATH
    marker.parent.mkdir(exist_ok=True)
    marker.touch()
    at_commit = None
    if at is not None:
        try:
            at_commit = _git(top, "rev-parse", "--verify", f"{at}^{{commit}}")
        except subprocess.CalledProcessError as exc:
            raise HookError(f"--at {at!r} does not resolve to a commit in {top}") from exc
        try:
            _git(top, "merge-base", "--is-ancestor", at_commit, "HEAD")
        except subprocess.CalledProcessError as exc:
            raise HookError(
                f"--at {at!r} is not an ancestor of HEAD in {top} — the sweep window "
                "enroll_commit..HEAD would not contain the history it claims to cover"
            ) from exc
    repo_id = repo_identity(top)
    paths.ensure_data_dir()
    path = paths.enrollment_path(repo_id)
    if path.exists():
        record = json.loads(path.read_text())  # first enrollment wins — never re-stamp
        if at_commit is not None and record["enroll_commit"] != at_commit:
            raise HookError(
                "enrollment record already exists with a different point — first "
                "enrollment wins; refusing to move it (delete the record only if "
                "you are deliberately re-anchoring this repo)"
            )
        return record
    enroll_commit = at_commit if at_commit is not None else _derive_enroll_commit(top)
    record = {
        "repo_id": repo_id,
        "enroll_commit": enroll_commit,
        "enroll_ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)
    return record


def reconcile(cwd: Path | None = None) -> int:
    """Bind the SINCE-ENROLLMENT (LIVE) commits an enrolled repo has not bound (MYB-3.7).

    A catch-up sweep for the commit-creation paths the ``post-commit`` hook can
    never see: ``git rebase`` (post-rewrite), merge commits (post-merge),
    commits authored on another machine/clone, and — the practical case —
    GitHub's server-side squash/rebase-merge, where the mainline commit is a
    brand-new hash that was never local until it is pulled. ``post-commit`` is
    thus a prompt-binding optimization on top of a sweep that guarantees
    completeness for everything since enrollment. Meant to run from the capture
    scan; safe to call anywhere.

    Only commits AFTER the enrollment point are swept: with a non-empty
    ``enroll_commit`` the window is ``git rev-list <enroll_commit>..HEAD``; a
    repo enrolled at its very start (``enroll_commit=""``) has no pre-history,
    so the window is all of ``HEAD``. Pre-enrollment history is backfill/
    IMPORTED and is deliberately NOT swept (a future explicit IMPORTED-tagged
    backfill is out of scope). Appends one binding row per in-window commit not
    already bound, deduping against existing ``binding`` rows by
    ``(repo_id, commit_hash)``. Idempotent: a re-run appends nothing. Returns
    the number of rows appended.

    Never raises for a repo it cannot process. No enrollment record → no-op
    (enrollment must be stamped first; it does NOT backfill all-history as a
    fallback). Unborn/empty HEAD, shallow, no marker, or a non-repo all return
    0 without touching the ledger. A detached HEAD is swept normally (only the
    in-window commits reachable from it). If ``enroll_commit`` is no longer a
    valid ref (e.g. rebased away), the range errors — that is logged and
    returns 0 rather than falling back to binding everything.
    """
    try:
        cwd = cwd if cwd is not None else Path.cwd()
        top = Path(_git(cwd, "rev-parse", "--show-toplevel"))
    except Exception:  # noqa: BLE001 — not a git worktree (or git unavailable)
        return 0
    if not (top / MARKER_RELPATH).is_file():
        return 0  # strictly opt-in, exactly like the hook — no marker, no sweep
    repo_id = repo_identity(top)
    enroll_path = paths.enrollment_path(repo_id)
    if not enroll_path.exists():
        return 0  # not stamped: enrollment must be recorded before any sweep
    try:
        record = json.loads(enroll_path.read_text())
        enroll_commit = record.get("enroll_commit", "")
        rev_range = f"{enroll_commit}..HEAD" if enroll_commit else "HEAD"
        rev_out = _git(top, "rev-list", rev_range)
    except Exception as exc:  # noqa: BLE001 — unborn HEAD, rebased-away enroll point, bad record
        _log_error(exc)
        return 0
    commits = rev_out.split()
    if not commits:
        return 0
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
