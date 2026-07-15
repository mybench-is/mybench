"""Bounded, privacy-safe Git context observation for lifecycle hooks.

The raw Claude ``cwd`` is memory-only.  Git returns a worktree top, common
directory, attached-HEAD status, and HEAD object id; those paths are reduced
immediately to keyed HMAC identifiers.  Only the two identifiers and the HEAD
sha can leave this module.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from mybench.hooks.binding import repo_identity_from_common_dir, worktree_identity

GIT_PROBE_TIMEOUT_SECONDS = 0.2

_HEAD_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
ABSENT_REASONS = {
    "invalid_cwd",
    "non_repo",
    "bare",
    "detached_head",
    "timeout",
    "unavailable",
    "error",
}


@dataclass(frozen=True)
class GitProbeResult:
    """Closed result: whitelisted fields or one metadata-only absence reason."""

    fields: dict[str, str]
    absent_reason: str | None = None


def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", os.fsdecode(cwd), *args],
        capture_output=True,
        check=False,
        timeout=GIT_PROBE_TIMEOUT_SECONDS,
    )


def _absent(reason: str) -> GitProbeResult:
    if reason not in ABSENT_REASONS:  # defensive closure for future callers
        reason = "error"
    return GitProbeResult({}, reason)


def probe_git_context(
    cwd_value: object,
    *,
    event_kind: str,
    scope_key: bytes,
) -> GitProbeResult:
    """Probe one start/end boundary without exposing repository strings.

    Non-repository, bare, detached, unavailable, malformed, and timed-out
    probes are honest absent observations.  They never guess a HEAD or partial
    identity.  ``compact_pre`` and future non-boundary events do not invoke Git.
    """
    if event_kind not in {"session_start", "session_end"}:
        return GitProbeResult({})
    if (
        not isinstance(cwd_value, str)
        or not cwd_value
        or "\x00" in cwd_value
        or not Path(cwd_value).is_absolute()
        or ".." in Path(cwd_value).parts
    ):
        return _absent("invalid_cwd")
    cwd = Path(cwd_value)

    try:
        bare = _run_git(cwd, "rev-parse", "--is-bare-repository")
        if bare.returncode != 0:
            return _absent("non_repo")
        if bare.stdout.strip() == b"true":
            return _absent("bare")
        if bare.stdout.strip() != b"false":
            return _absent("error")

        symbolic = _run_git(cwd, "symbolic-ref", "-q", "HEAD")
        if symbolic.returncode == 1:
            return _absent("detached_head")
        if symbolic.returncode != 0:
            return _absent("non_repo")

        facts = _run_git(
            cwd,
            "rev-parse",
            "--show-toplevel",
            "--path-format=absolute",
            "--git-common-dir",
            "HEAD",
        )
    except subprocess.TimeoutExpired:
        return _absent("timeout")
    except FileNotFoundError:
        return _absent("unavailable")
    except (OSError, ValueError):
        return _absent("error")

    if facts.returncode != 0:
        return _absent("error")
    lines = facts.stdout.splitlines()
    if len(lines) != 3:
        return _absent("error")
    top = Path(os.fsdecode(lines[0]))
    common_dir = Path(os.fsdecode(lines[1]))
    try:
        head = lines[2].decode("ascii")
    except UnicodeDecodeError:
        return _absent("error")
    if not top.is_absolute() or not common_dir.is_absolute() or not _HEAD_RE.fullmatch(head):
        return _absent("error")

    head_field = "head_before" if event_kind == "session_start" else "head_after"
    try:
        return GitProbeResult(
            {
                "repo_id": repo_identity_from_common_dir(common_dir, scope_key=scope_key),
                "worktree_id": worktree_identity(top, scope_key=scope_key),
                head_field: head,
            }
        )
    except Exception:  # noqa: BLE001 — identity reduction is a fail-safe probe boundary
        return _absent("error")
