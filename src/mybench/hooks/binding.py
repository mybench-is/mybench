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
GitHub server-side squash-merge born as a new hash). The explicit historical
mode reverses the former backfill exclusion under roadmap Stage 1 §3: it walks
only the pre-enrollment side and writes closed-shape IMPORTED rows.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
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


def _existing_enrollment_path(top: Path) -> Path | None:
    """Return a secure existing enrollment path using only existing key state."""
    from mybench.scan_health import load_scope_key

    scope_key = load_scope_key()
    if scope_key is None:
        return None
    repo_id = repo_identity_for_worktree(top, scope_key=scope_key)
    candidate = paths.enrollment_path(repo_id)
    if not os.path.lexists(candidate):
        return None
    info = candidate.lstat()
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise HookError("enrollment storage is insecure")
    return candidate


def preflight_enroll(repo: str | Path) -> Path:
    """Validate one enrollment target without writing it."""
    repo = os.fspath(repo)
    if repo.startswith("-"):
        raise HookError(f"not a repo path: {repo!r} (global installs are refused by design)")
    top = Path(repo).resolve()
    git_dir = top / ".git"
    if not git_dir.is_dir():
        raise HookError(f"{top} is not the top level of a git worktree")
    hooks_dir = git_dir / "hooks"
    if os.path.lexists(hooks_dir):
        info = hooks_dir.lstat()
        if hooks_dir.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise HookError("binding hooks directory is insecure")
    hook_path = hooks_dir / "post-commit"
    if os.path.lexists(hook_path):
        info = hook_path.lstat()
        if hook_path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise HookError("binding hook storage is insecure")
        if HOOK_SENTINEL not in hook_path.read_text():
            raise HookError("post-commit is not a mybench hook; refusing to overwrite")
    marker_parent = top / MARKER_RELPATH.parent
    if os.path.lexists(marker_parent):
        info = marker_parent.lstat()
        if marker_parent.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise HookError("binding marker directory is insecure")
    marker = top / MARKER_RELPATH
    if os.path.lexists(marker):
        info = marker.lstat()
        if marker.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise HookError("binding marker storage is insecure")
    _existing_enrollment_path(top)
    return top


def install(repo: str) -> Path:
    """Install the post-commit hook into exactly this repo's .git/hooks."""
    top = preflight_enroll(repo)
    hook_path = top / ".git" / "hooks" / "post-commit"
    expected = HOOK_TEMPLATE.format(sentinel=HOOK_SENTINEL, python=sys.executable)
    if hook_path.exists() and hook_path.read_text() == expected:
        return hook_path
    hook_path.parent.mkdir(exist_ok=True)
    hook_path.write_text(expected)
    hook_path.chmod(0o755)
    return hook_path


def repo_identity(top: Path, *, scope_key: bytes | None = None) -> str:
    """Opaque keyed repo id (OQ #9): HMAC over the realpath, never the path itself."""
    key = scope_key if scope_key is not None else paths.ensure_session_scope_key()
    return hmac.new(key, b"repo:" + os.fsencode(top.resolve()), hashlib.sha256).hexdigest()[:16]


def repo_identity_from_common_dir(
    common_dir: Path,
    *,
    scope_key: bytes | None = None,
) -> str:
    """Return one repo id across its main and linked worktrees.

    A normal/linked worktree's common dir is ``<canonical-top>/.git``.  Hashing
    its parent preserves every existing canonical-worktree id while making a
    linked worktree converge on that same id.  Repositories with an externally
    located common dir use that common dir itself as the stable identity base.
    """
    common_dir = common_dir.resolve()
    identity_base = common_dir.parent if common_dir.name == ".git" else common_dir
    return repo_identity(identity_base, scope_key=scope_key)


def repo_identity_for_worktree(
    top: Path,
    *,
    scope_key: bytes | None = None,
) -> str:
    """Resolve a worktree through Git's common-dir identity hierarchy."""
    common_dir = Path(_git(top, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    return repo_identity_from_common_dir(common_dir, scope_key=scope_key)


def worktree_identity(top: Path, *, scope_key: bytes | None = None) -> str:
    """Opaque keyed discriminator for one worktree of a shared repository."""
    key = scope_key if scope_key is not None else paths.ensure_session_scope_key()
    return hmac.new(
        key,
        b"worktree:" + os.fsencode(top.resolve()),
        hashlib.sha256,
    ).hexdigest()[:16]


def _log_error(exc: Exception, context: str = "post-commit") -> None:
    try:
        paths.ensure_data_dir()
        line = (
            f"{datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"{context} error type={type(exc).__name__}\n"
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
            repo_id=repo_identity_for_worktree(top),
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
    top = preflight_enroll(repo)
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
    repo_id = repo_identity_for_worktree(top)
    paths.ensure_data_dir()
    path = paths.enrollment_path(repo_id)
    if os.path.lexists(path):
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise HookError("enrollment storage is insecure")
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


def _unenroll_plan(repo: str | Path) -> tuple[Path, Path, bool, bool, Path | None]:
    """Validate one removal target and return its owned state without writing."""
    top = Path(repo).resolve()
    git_dir = top / ".git"
    if not git_dir.is_dir():
        raise HookError("capture disable requires a worktree root")
    hook_path = git_dir / "hooks" / "post-commit"
    marker_path = top / MARKER_RELPATH

    hook_exists = os.path.lexists(hook_path)
    if hook_exists:
        hook_info = hook_path.lstat()
        if (
            hook_path.is_symlink()
            or not stat.S_ISREG(hook_info.st_mode)
            or hook_info.st_nlink != 1
        ):
            raise HookError("binding hook storage is insecure")
        if HOOK_SENTINEL not in hook_path.read_text():
            raise HookError("refusing to remove a foreign post-commit hook")

    marker_exists = os.path.lexists(marker_path)
    if marker_exists:
        marker_info = marker_path.lstat()
        if (
            marker_path.is_symlink()
            or not stat.S_ISREG(marker_info.st_mode)
            or marker_info.st_nlink != 1
        ):
            raise HookError("binding marker storage is insecure")

    enrollment_path = _existing_enrollment_path(top)

    return hook_path, marker_path, hook_exists, marker_exists, enrollment_path


def preflight_unenroll(repo: str | Path) -> None:
    """Validate one removal target without unlinking any state."""
    _unenroll_plan(repo)


def unenroll(repo: str | Path) -> dict[str, bool]:
    """Remove only mybench-owned binding state for one worktree.

    Validation happens before any unlink: a foreign, symlinked, hardlinked, or
    non-regular hook/enrollment is refused rather than partially dismantled.
    Re-running after a clean removal is a no-op.
    """
    hook_path, marker_path, hook_exists, marker_exists, enrollment_path = (
        _unenroll_plan(repo)
    )
    if hook_exists:
        hook_path.unlink()
    if marker_exists:
        marker_path.unlink()
    if enrollment_path is not None:
        enrollment_path.unlink()
    try:
        marker_path.parent.rmdir()
    except OSError:
        pass
    return {
        "hook_removed": hook_exists,
        "marker_removed": marker_exists,
        "enrollment_removed": enrollment_path is not None,
    }


def reconcile(
    cwd: Path | None = None,
    *,
    historical: bool = False,
    dry_run: bool = False,
) -> int:
    """Bind missing commits on one side of an enrolled repo's enrollment floor.

    A catch-up sweep for the commit-creation paths the ``post-commit`` hook can
    never see: ``git rebase`` (post-rewrite), merge commits (post-merge),
    commits authored on another machine/clone, and — the practical case —
    GitHub's server-side squash/rebase-merge, where the mainline commit is a
    brand-new hash that was never local until it is pulled. ``post-commit`` is
    thus a prompt-binding optimization on top of a sweep that guarantees
    completeness for everything since enrollment. Meant to run from the capture
    scan; safe to call anywhere.

    Normally only commits AFTER the enrollment point are swept: with a non-empty
    ``enroll_commit`` the window is ``git rev-list <enroll_commit>..HEAD``; a
    repo enrolled at its very start (``enroll_commit=""``) has no pre-history,
    so the window is all of ``HEAD``. With ``historical=True`` the floor is
    reversed: ``git rev-list <enroll_commit>`` includes the enrollment commit
    and its ancestors as IMPORTED, while an empty enrollment point correctly
    has no pre-history. Appends one binding row per in-window commit not already
    bound, deduping against existing ``binding`` rows by
    ``(repo_id, commit_hash)``. Idempotent: a re-run appends nothing. Returns
    the number of rows appended, or the number planned when ``dry_run=True``.
    Dry-run is valid only for historical mode and never creates local state.

    REPO-level conditions never raise: no enrollment record → no-op (enrollment
    must be stamped first; it does NOT backfill all-history as a fallback);
    unborn/empty HEAD, no marker, a non-repo, or a shallow boundary that cuts
    off the window all return 0 without touching the ledger. A detached HEAD is
    swept normally (only the in-window commits reachable from it). If
    ``enroll_commit`` is no longer a valid ref (e.g. rebased away), the range
    errors — that is logged and returns 0 rather than falling back to binding
    everything. A mid-sweep failure logs and returns the partial count; the
    idempotent re-run resumes where it left off.

    Data-dir INTEGRITY failures are different and DO propagate
    (:class:`~mybench.paths.PathsError`: insecure permissions, data dir inside
    a repo): MYB-2.1 requires those to surface to the owner, not be masked as
    a quiet "0 bound". Contrast :func:`run`, which must never block a commit
    and swallows everything.
    """
    if dry_run and not historical:
        raise HookError("dry-run is available only for historical reconciliation")
    try:
        cwd = cwd if cwd is not None else Path.cwd()
        top = Path(_git(cwd, "rev-parse", "--show-toplevel"))
    except Exception:  # noqa: BLE001 — not a git worktree (or git unavailable)
        return 0
    if not (top / MARKER_RELPATH).is_file():
        return 0  # strictly opt-in, exactly like the hook — no marker, no sweep
    if dry_run:
        from mybench.scan_health import load_scope_key

        scope_key = load_scope_key()
        if scope_key is None:
            raise HookError("historical dry-run requires an initialized scope key")
        repo_id = repo_identity_for_worktree(top, scope_key=scope_key)
    else:
        repo_id = repo_identity_for_worktree(
            top
        )  # PathsError propagates: integrity failures must surface
    enroll_path = paths.enrollment_path(repo_id)
    if not enroll_path.exists():
        return 0  # not stamped: enrollment must be recorded before any sweep
    try:
        record = json.loads(enroll_path.read_text())
        enroll_commit = record.get("enroll_commit", "")
        if historical and not enroll_commit:
            return 0
        rev_range = (
            enroll_commit
            if historical
            else (f"{enroll_commit}..HEAD" if enroll_commit else "HEAD")
        )
        rev_out = _git(top, "rev-list", rev_range)
    except Exception as exc:  # noqa: BLE001 — unborn HEAD, rebased-away enroll point, bad record
        _log_error(exc, context="reconcile")
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
    except paths.PathsError:
        raise  # loose-perms ledger: surface it, never mask as "nothing to bind"
    except Exception as exc:  # noqa: BLE001 — an unreadable ledger is not ours to repair here
        _log_error(exc, context="reconcile")
        return 0
    appended = 0
    try:
        for commit_hash in commits:
            if commit_hash in bound:
                continue
            if dry_run:
                bound.add(commit_hash)
                appended += 1
                continue
            ledger.append_binding(
                commit_hash=commit_hash,
                commit_ts=_committer_ts(top, commit_hash),
                repo_id=repo_id,
                provenance="IMPORTED" if historical else None,
            )
            bound.add(commit_hash)  # guard against a hash appearing twice in rev-list output
            appended += 1
    except paths.PathsError:
        raise
    except Exception as exc:  # noqa: BLE001 — partial sweep; idempotent re-run resumes
        _log_error(exc, context="reconcile")
    return appended
