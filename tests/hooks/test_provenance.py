"""MYB-12.6: synthetic Git repositories → lifecycle provenance observations."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from mybench import paths
from mybench.hooks import binding, lifecycle, provenance
from mybench.ledger import Ledger, LedgerError
from tests.fixtures import CanaryLeakError, assert_no_canaries

TS = "2026-07-15T22:00:00Z"
SCOPE_KEY = bytes.fromhex("22" * 32)
PROVENANCE_FIELDS = {"repo_id", "worktree_id", "head_before", "head_after"}


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=check,
    )


def init_repo(tmp_path: Path, name: str = "synthetic-repo") -> tuple[Path, str]:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "synthetic@example.invalid")
    git(repo, "config", "user.name", "Synthetic Committer")
    initial = repo / "synthetic-initial.txt"
    initial.write_bytes(b"synthetic initial content\n")
    git(repo, "add", initial.name)
    git(repo, "commit", "-q", "-m", "synthetic initial commit")
    return repo, git(repo, "rev-parse", "HEAD").stdout.strip()


def commit(repo: Path, name: str = "synthetic-next.txt") -> str:
    path = repo / name
    path.write_bytes(b"synthetic next content\n")
    git(repo, "add", path.name)
    git(repo, "commit", "-q", "-m", "synthetic next commit")
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def watch_and_transcript(tmp_path: Path) -> tuple[Path, Path]:
    watch = tmp_path / "synthetic-home" / ".claude" / "projects"
    transcript = watch / "synthetic-project" / "00000000-0000-4000-8000-000000000012.jsonl"
    transcript.parent.mkdir(parents=True)
    return watch, transcript


def payload(event: str, transcript: Path, cwd: Path, **fields: str) -> dict:
    return {
        "session_id": "raw-synthetic-harness-id",
        "transcript_path": str(transcript),
        "cwd": str(cwd),
        "hook_event_name": event,
        **fields,
    }


def event_rows() -> list[dict]:
    return [row for row in Ledger().rows() if row["type"] == "event"]


def test_session_boundaries_join_the_commit_binding_by_repo_and_row_range(tmp_path):
    paths.ensure_data_dir()
    repo, head_before = init_repo(tmp_path)
    marker = repo / binding.MARKER_RELPATH
    marker.parent.mkdir()
    marker.touch()
    watch, transcript = watch_and_transcript(tmp_path)
    scope_key = paths.ensure_session_scope_key()

    assert lifecycle.handle_payload(
        payload("SessionStart", transcript, repo, source="startup"),
        watch_root=watch,
        scope_key=scope_key,
        now=lambda: TS,
    ) == 0
    assert lifecycle.flush_queue() == 1

    bound_commit = commit(repo)
    assert binding.run(repo) == 0

    assert lifecycle.handle_payload(
        payload("SessionEnd", transcript, repo, reason="other"),
        watch_root=watch,
        scope_key=scope_key,
        now=lambda: "2026-07-15T22:05:00Z",
    ) == 0
    assert lifecycle.flush_queue() == 1

    rows = Ledger().rows()
    start = next(row for row in rows if row.get("event_kind") == "session_start")
    end = next(row for row in rows if row.get("event_kind") == "session_end")
    binding_row = next(row for row in rows if row["type"] == "binding")
    assert start["head_before"] == head_before
    assert end["head_after"] == bound_commit
    assert start["head_before"] != end["head_after"]
    assert start["repo_id"] == binding_row["repo_id"] == end["repo_id"]
    assert start["worktree_id"] == end["worktree_id"]
    assert start["i"] < binding_row["i"] < end["i"]
    assert binding_row["commit_hash"] == bound_commit
    assert git(repo, "merge-base", "--is-ancestor", head_before, bound_commit).returncode == 0
    assert Ledger().verify_chain() == 4


def test_main_and_linked_worktrees_share_repo_id_but_not_worktree_id(tmp_path):
    paths.ensure_data_dir()
    repo, _head = init_repo(tmp_path)
    marker = repo / binding.MARKER_RELPATH
    marker.parent.mkdir()
    marker.touch()
    git(repo, "add", marker.relative_to(repo).as_posix())
    git(repo, "commit", "-q", "-m", "synthetic enable binding")
    linked = tmp_path / "synthetic-linked"
    git(repo, "worktree", "add", "-q", "-b", "synthetic-linked", str(linked))
    scope_key = paths.ensure_session_scope_key()

    main = provenance.probe_git_context(
        str(repo), event_kind="session_start", scope_key=scope_key
    )
    other = provenance.probe_git_context(
        str(linked), event_kind="session_start", scope_key=scope_key
    )
    assert main.absent_reason is other.absent_reason is None
    assert main.fields["repo_id"] == other.fields["repo_id"]
    assert main.fields["worktree_id"] != other.fields["worktree_id"]
    assert main.fields["head_before"] == other.fields["head_before"]
    assert main.fields["repo_id"] == binding.repo_identity(repo, scope_key=scope_key)
    assert binding.repo_identity_for_worktree(
        repo, scope_key=scope_key
    ) == binding.repo_identity_for_worktree(linked, scope_key=scope_key)
    assert binding.run(linked) == 0
    binding_row = next(row for row in Ledger().rows() if row["type"] == "binding")
    assert binding_row["repo_id"] == main.fields["repo_id"]


def test_rebase_mid_session_is_observed_only_at_the_two_boundaries(tmp_path):
    paths.ensure_data_dir()
    repo, _head = init_repo(tmp_path)
    base_branch = git(repo, "symbolic-ref", "--short", "HEAD").stdout.strip()
    git(repo, "checkout", "-q", "-b", "synthetic-feature")
    feature_before = commit(repo, "synthetic-feature.txt")
    watch, transcript = watch_and_transcript(tmp_path)
    scope_key = paths.ensure_session_scope_key()

    lifecycle.handle_payload(
        payload("SessionStart", transcript, repo, source="startup"),
        watch_root=watch,
        scope_key=scope_key,
        now=lambda: TS,
    )
    assert lifecycle.flush_queue() == 1

    git(repo, "checkout", "-q", base_branch)
    main_head = commit(repo, "synthetic-main.txt")
    git(repo, "checkout", "-q", "synthetic-feature")
    git(repo, "rebase", "-q", base_branch)
    rebased_head = git(repo, "rev-parse", "HEAD").stdout.strip()

    lifecycle.handle_payload(
        payload("SessionEnd", transcript, repo, reason="other"),
        watch_root=watch,
        scope_key=scope_key,
        now=lambda: "2026-07-15T22:05:00Z",
    )
    assert lifecycle.flush_queue() == 1
    start, end = event_rows()
    assert start["head_before"] == feature_before
    assert end["head_after"] == rebased_head
    assert start["head_before"] != end["head_after"]
    assert start["repo_id"] == end["repo_id"]
    assert git(repo, "merge-base", "--is-ancestor", main_head, rebased_head).returncode == 0


@pytest.mark.parametrize(
    ("fixture_kind", "expected_reason"),
    [("non_repo", "non_repo"), ("detached", "detached_head"), ("bare", "bare")],
)
def test_unavailable_repo_states_append_boundary_without_provenance(
    tmp_path, fixture_kind, expected_reason
):
    paths.ensure_data_dir()
    if fixture_kind == "non_repo":
        cwd = tmp_path / "synthetic-non-repo"
        cwd.mkdir()
    elif fixture_kind == "detached":
        cwd, _head = init_repo(tmp_path)
        git(cwd, "checkout", "-q", "--detach")
    else:
        cwd = tmp_path / "synthetic-bare.git"
        cwd.mkdir()
        git(cwd, "init", "--bare", "-q")
    watch, transcript = watch_and_transcript(tmp_path)

    assert lifecycle.handle_payload(
        payload("SessionStart", transcript, cwd, source="startup"),
        watch_root=watch,
        scope_key=SCOPE_KEY,
        now=lambda: TS,
    ) == 0
    assert lifecycle.flush_queue() == 1
    row = event_rows()[0]
    assert not set(row) & PROVENANCE_FIELDS
    log = (paths.data_dir() / "hooks.log").read_text()
    assert f"reason={expected_reason} count=1" in log
    assert str(cwd) not in log
    assert Ledger().verify_chain() == 2


def test_probe_timeout_is_counted_but_does_not_lose_the_boundary(tmp_path, monkeypatch):
    paths.ensure_data_dir()
    repo, _head = init_repo(tmp_path)
    watch, transcript = watch_and_transcript(tmp_path)

    def time_out(_cwd, *_args):
        raise subprocess.TimeoutExpired(["git", "synthetic"], 0.2)

    monkeypatch.setattr(provenance, "_run_git", time_out)
    assert lifecycle.handle_payload(
        payload("SessionStart", transcript, repo, source="startup"),
        watch_root=watch,
        scope_key=SCOPE_KEY,
        now=lambda: TS,
    ) == 0
    assert lifecycle.flush_queue() == 1
    assert not set(event_rows()[0]) & PROVENANCE_FIELDS
    assert "reason=timeout count=1" in (paths.data_dir() / "hooks.log").read_text()


def test_every_git_subprocess_receives_the_bounded_timeout(tmp_path, monkeypatch):
    seen = []

    def fake_run(*_args, **kwargs):
        seen.append(kwargs.get("timeout"))
        return subprocess.CompletedProcess([], 128, b"", b"")

    monkeypatch.setattr(provenance.subprocess, "run", fake_run)
    result = provenance.probe_git_context(
        str(tmp_path), event_kind="session_start", scope_key=SCOPE_KEY
    )
    assert result.absent_reason == "non_repo"
    assert seen == [provenance.GIT_PROBE_TIMEOUT_SECONDS]


def test_missing_git_is_an_honest_absent_observation(tmp_path, monkeypatch):
    paths.ensure_data_dir()
    watch, transcript = watch_and_transcript(tmp_path)

    def unavailable(*_args, **_kwargs):
        raise FileNotFoundError("synthetic git absence")

    monkeypatch.setattr(provenance.subprocess, "run", unavailable)
    assert lifecycle.handle_payload(
        payload("SessionEnd", transcript, tmp_path, reason="other"),
        watch_root=watch,
        scope_key=SCOPE_KEY,
        now=lambda: TS,
    ) == 0
    assert lifecycle.flush_queue() == 1
    row = event_rows()[0]
    assert not set(row) & PROVENANCE_FIELDS
    assert "reason=unavailable count=1" in (paths.data_dir() / "hooks.log").read_text()


def test_queue_v1_boundary_without_provenance_remains_flushable():
    paths.ensure_data_dir()
    queue = paths.claude_lifecycle_queue_path()
    queue.write_text(
        '{"event_kind":"session_start","harness":"claude-code",'
        '"queue_version":"1","session_id":"synthetic-v1-queue",'
        '"trigger":"startup","ts":"2026-07-15T22:00:00Z"}\n'
    )
    queue.chmod(0o600)
    assert lifecycle.flush_queue() == 1
    assert not set(event_rows()[0]) & PROVENANCE_FIELDS


def test_malformed_queue_provenance_is_rejected_without_crashing_the_scan():
    paths.ensure_data_dir()
    queue = paths.claude_lifecycle_queue_path()
    record = {
        "queue_version": lifecycle.QUEUE_VERSION,
        "ts": TS,
        "event_kind": "session_start",
        "trigger": "startup",
        "session_id": "synthetic-invalid-provenance",
        "harness": "claude-code",
        "repo_id": 7,
        "worktree_id": "cd" * 8,
        "head_before": "1" * 40,
    }
    queue.write_text(json.dumps(record) + "\n")
    queue.chmod(0o600)
    assert lifecycle.flush_queue() == 0
    assert queue.stat().st_size == 0
    assert not Ledger().path.exists()


def test_schema_rejects_partial_misplaced_or_wrong_boundary_provenance():
    paths.ensure_data_dir()
    ledger = Ledger()
    common = {
        "session_id": "synthetic-schema-session",
        "context_gen": 0,
        "harness": "claude-code",
        "repo_id": "ab" * 8,
    }
    with pytest.raises(LedgerError):
        ledger.append_event(
            event_kind="session_start",
            trigger="startup",
            **common,
        )
    with pytest.raises(LedgerError):
        ledger.append_event(
            event_kind="session_start",
            trigger="startup",
            worktree_id="cd" * 8,
            head_after="1" * 40,
            **common,
        )
    with pytest.raises(LedgerError):
        ledger.append_event(
            event_kind="compact_pre",
            trigger="manual",
            worktree_id="cd" * 8,
            head_before="1" * 40,
            **common,
        )


def test_git_context_canaries_reach_no_queue_row_log_or_anchor_staging(tmp_path):
    paths.ensure_data_dir()
    canaries = [
        b"MYBENCH-CANARY-repo-0123abcd",
        b"MYBENCH-CANARY-branch-4567efab",
        b"MYBENCH-CANARY-remote-89abcdef",
        b"MYBENCH-CANARY-cwd-fedcba98",
    ]
    parent = tmp_path / canaries[3].decode()
    parent.mkdir()
    repo, _head = init_repo(parent, canaries[0].decode())
    git(repo, "checkout", "-q", "-b", canaries[1].decode())
    git(repo, "remote", "add", "origin", f"https://{canaries[2].decode()}.invalid/repo")
    watch, transcript = watch_and_transcript(tmp_path)

    lifecycle.handle_payload(
        payload("SessionStart", transcript, repo, source="startup"),
        watch_root=watch,
        scope_key=SCOPE_KEY,
        now=lambda: TS,
    )
    assert lifecycle.flush_queue() == 1
    row = event_rows()[0]
    assert set(row) >= {"repo_id", "worktree_id", "head_before"}
    assert re.fullmatch(r"[0-9a-f]{16}", row["repo_id"])
    assert re.fullmatch(r"[0-9a-f]{16}", row["worktree_id"])
    assert re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", row["head_before"])
    targets = [paths.claude_lifecycle_queue_path(), Ledger().path, paths.anchors_dir()]
    hook_log = paths.data_dir() / "hooks.log"
    if hook_log.exists():
        targets.append(hook_log)
    assert assert_no_canaries(targets, canaries) >= 2


def test_git_provenance_canary_scanner_companion_fires():
    paths.ensure_data_dir()
    marker = b"MYBENCH-CANARY-git-provenance-a1b2c3d4"
    planted = paths.anchors_dir() / "synthetic-git-provenance-canary"
    planted.write_bytes(marker)
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([paths.anchors_dir()], [marker])
