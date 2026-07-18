"""MYB-10.5 enrolled-Git extraction, privacy, and corpus binding."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import ValidationError

from mybench import paths
from mybench.hooks import binding
from mybench.normalizer.contract import corpus_commitment
from mybench.normalizer.repo import (
    FILE_CLASSES,
    NormalizationError,
    normalize_repo_evidence,
    validate_repo_corpus_artifact,
)
from mybench.normalizer.repo_loader import (
    RepoEvidenceLoaderError,
    _file_class,
    capture_enrolled_repo,
    resolve_repo_pointer,
)
from mybench.schemas import load_validator
from tests.fixtures import CanaryLeakError, assert_no_canaries
from tests.normalizer.repo_synthetic import (
    REPO_AUTHOR_CANARY,
    REPO_BRANCH_CANARY,
    REPO_CONTENT_CANARY,
    REPO_FILENAME_CANARY,
    REPO_NONCE_CANARY,
    REPO_PATH_CANARY,
    synthetic_repo_evidence_input,
)

SUBJECT_EMAIL = "declared-subject@example.invalid"
NON_SUBJECT_EMAIL = REPO_AUTHOR_CANARY
SCOPE_KEY = bytes.fromhex("8a" * 32)
COMMIT_DATE = "2026-01-01T00:00:00+00:00"


def git(repo: Path, *args: str, env: dict | None = None, check: bool = True):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        env=env,
        check=check,
    )


def identity_env(email: str, sequence: int) -> dict[str, str]:
    env = dict(os.environ)
    timestamp = f"2026-01-{sequence:02d}T00:00:00+00:00"
    env.update(
        {
            "GIT_AUTHOR_NAME": "Synthetic Author",
            "GIT_AUTHOR_EMAIL": email,
            "GIT_AUTHOR_DATE": timestamp,
            "GIT_COMMITTER_NAME": "Synthetic Committer",
            "GIT_COMMITTER_EMAIL": email,
            "GIT_COMMITTER_DATE": timestamp,
        }
    )
    return env


def commit_file(
    repo: Path,
    relative: str,
    content: str,
    *,
    email: str,
    sequence: int,
    message: str,
) -> str:
    target = repo / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    git(repo, "add", "--", relative)
    git(repo, "commit", "-q", "--no-gpg-sign", "-m", message, env=identity_env(email, sequence))
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def enroll_fixture(repo: Path, enroll_commit: str) -> str:
    marker = repo / binding.MARKER_RELPATH
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    repo_id = binding.repo_identity_for_worktree(repo, scope_key=SCOPE_KEY)
    paths.ensure_data_dir()
    enrollment = paths.enrollment_path(repo_id)
    enrollment.write_text(
        json.dumps(
            {
                "repo_id": repo_id,
                "enroll_commit": enroll_commit,
                "enroll_ts": "2026-01-01T00:00:00Z",
            }
        )
    )
    enrollment.chmod(0o600)
    return repo_id


@pytest.fixture
def enrolled_repo(tmp_path):
    repo = tmp_path / "private-path-canary" / "repo"
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Synthetic Default")
    git(repo, "config", "user.email", SUBJECT_EMAIL)
    root = commit_file(
        repo,
        f"{REPO_FILENAME_CANARY}/package.json",
        '{"private":"' + REPO_CONTENT_CANARY + '","nonce":"' + REPO_NONCE_CANARY + '"}\n',
        email=SUBJECT_EMAIL,
        sequence=1,
        message="subject root " + REPO_CONTENT_CANARY,
    )
    non_subject = commit_file(
        repo,
        f"{REPO_FILENAME_CANARY}/coauthor-secret.txt",
        "third party " + REPO_CONTENT_CANARY + "\n",
        email=NON_SUBJECT_EMAIL,
        sequence=2,
        message="non-subject " + REPO_CONTENT_CANARY,
    )
    live = commit_file(
        repo,
        f".github/workflows/{REPO_FILENAME_CANARY}.yml",
        "name: " + REPO_CONTENT_CANARY + "\n",
        email=SUBJECT_EMAIL,
        sequence=3,
        message="subject live " + REPO_CONTENT_CANARY,
    )
    git(repo, "branch", REPO_BRANCH_CANARY, live)
    repo_id = enroll_fixture(repo, root)
    return repo, repo_id, root, non_subject, live


def artifact_from(repo: Path) -> tuple[bytes, dict]:
    snapshot = capture_enrolled_repo(
        repo,
        subject_identities={SUBJECT_EMAIL},
        scope_key=SCOPE_KEY,
    )
    data = normalize_repo_evidence((snapshot,))
    return data, json.loads(data)


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        (b"README.md", "docs"),
        (b"docs/guide.rst", "docs"),
        (b"specs/protocol.md", "spec"),
        (b"decisions/ADR-0001-boundary.md", "spec"),
        (b".claude/plans/synthetic.md", "plan"),
        (b"docs/roadmaps/v1.md", "plan"),
        (b"AGENTS.md", "handoff"),
        (b"handoffs/release-context.md", "handoff"),
        (b"tests/spec/test_parser.py", "other"),
    ],
)
def test_file_classes_are_closed_and_document_specific(relative, expected):
    assert _file_class(relative) == expected


def test_synthetic_multi_file_commit_emits_every_file_class(tmp_path):
    repo = tmp_path / "synthetic-multi-file-repo"
    repo.mkdir()
    git(repo, "init", "-q")
    files = {
        "package.json": "{}\n",
        "package-lock.json": "{}\n",
        ".github/workflows/check.yml": "name: synthetic\n",
        "README.md": "synthetic documentation\n",
        "specs/protocol.md": "synthetic specification\n",
        ".claude/plans/next.md": "synthetic plan\n",
        "HANDOFF.md": "synthetic handoff\n",
        "src/example.py": "SYNTHETIC = True\n",
    }
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    git(repo, "add", "--all")
    git(
        repo,
        "commit",
        "-q",
        "--no-gpg-sign",
        "-m",
        "synthetic multi-file commit",
        env=identity_env(SUBJECT_EMAIL, 1),
    )
    root = git(repo, "rev-parse", "HEAD").stdout.strip()
    enroll_fixture(repo, root)

    snapshot = capture_enrolled_repo(
        repo, subject_identities={SUBJECT_EMAIL}, scope_key=SCOPE_KEY
    )
    commit = next(item for item in snapshot.commits if item.commit_id == root)
    assert dict(commit.file_class_counts) == {file_class: 1 for file_class in FILE_CLASSES}
    assert {target.file_class for target in commit.targets} == set(FILE_CLASSES)


def test_real_git_snapshot_is_deterministic_closed_and_subject_only(enrolled_repo):
    repo, repo_id, root, non_subject, live = enrolled_repo
    first_snapshot = capture_enrolled_repo(
        repo, subject_identities={SUBJECT_EMAIL}, scope_key=SCOPE_KEY
    )
    second_snapshot = capture_enrolled_repo(
        repo, subject_identities={SUBJECT_EMAIL}, scope_key=SCOPE_KEY
    )
    assert first_snapshot == second_snapshot
    data = normalize_repo_evidence((first_snapshot,))
    shuffled = replace(
        first_snapshot,
        commits=tuple(reversed(first_snapshot.commits)),
        branch_tips=tuple(reversed(first_snapshot.branch_tips)),
        reflog_targets=tuple(reversed(first_snapshot.reflog_targets)),
        worktrees=tuple(reversed(first_snapshot.worktrees)),
    )
    assert normalize_repo_evidence((shuffled,)) == data

    artifact = json.loads(data)
    load_validator("repo_evidence.schema.json").validate(artifact)
    assert validate_repo_corpus_artifact(data) == artifact["corpus_commitment"]
    assert (
        corpus_commitment(artifact["manifest"], artifact["events"]) == artifact["corpus_commitment"]
    )
    commits = [event for event in artifact["events"] if event["event_kind"] == "commit"]
    assert {event["pointer"]["object_id"] for event in commits} == {root, live}
    assert non_subject.encode() not in data
    assert {event["provenance"] for event in commits} == {"IMPORTED", "LIVE"}
    assert artifact["manifest"]["coverage"] == {
        "blob_targets_referenced": 2,
        "branch_tips_admitted": 1,
        "commits_admitted": 2,
        "commits_imported": 1,
        "commits_live": 1,
        "reflog_targets_admitted": 2,
        "repositories_admitted": 1,
        "structures_unknown": 0,
        "worktrees_admitted": 1,
    }
    assert artifact["manifest"]["repositories"][0]["repo_id"] == repo_id
    assert any(event["file_class_counts"]["manifest"] == 1 for event in commits)
    assert any(event["file_class_counts"]["ci"] == 1 for event in commits)


def test_non_subject_side_commit_has_no_effect_on_artifact(enrolled_repo):
    repo, _repo_id, _root, _non_subject, live = enrolled_repo
    before, _ = artifact_from(repo)
    tree = git(repo, "rev-parse", f"{live}^{{tree}}").stdout.strip()
    side = git(
        repo,
        "commit-tree",
        tree,
        "-p",
        live,
        "-m",
        "side " + REPO_CONTENT_CANARY,
        env=identity_env(NON_SUBJECT_EMAIL, 4),
    ).stdout.strip()
    git(repo, "update-ref", f"refs/heads/{REPO_BRANCH_CANARY}-side", side)
    after, _ = artifact_from(repo)
    assert before == after
    assert side.encode() not in after


def test_subject_merge_of_non_subject_branch_exposes_no_tree_structure(enrolled_repo):
    repo, _repo_id, _root, _non_subject, live = enrolled_repo
    git(repo, "checkout", "-q", "-b", REPO_BRANCH_CANARY + "-third-party", live)
    side = commit_file(
        repo,
        f"{REPO_FILENAME_CANARY}/merged-third-party.txt",
        "merged third party " + REPO_CONTENT_CANARY + "\n",
        email=NON_SUBJECT_EMAIL,
        sequence=5,
        message="third-party branch " + REPO_CONTENT_CANARY,
    )
    git(repo, "checkout", "-q", "master")
    git(
        repo,
        "merge",
        "-q",
        "--no-ff",
        "--no-gpg-sign",
        "-m",
        "subject merge " + REPO_CONTENT_CANARY,
        REPO_BRANCH_CANARY + "-third-party",
        env=identity_env(SUBJECT_EMAIL, 6),
    )
    merge_id = git(repo, "rev-parse", "HEAD").stdout.strip()
    data, artifact = artifact_from(repo)
    merge_event = next(
        event
        for event in artifact["events"]
        if event["event_kind"] == "commit" and event["pointer"]["object_id"] == merge_id
    )
    assert merge_event["structure_status"] == "unknown"
    assert "targets" not in merge_event and "change_counts" not in merge_event
    assert side.encode() not in data


def test_repo_pointer_resolves_live_and_missing_is_unknown(enrolled_repo):
    repo, _repo_id, _root, non_subject, _live = enrolled_repo
    _data, artifact = artifact_from(repo)
    commit = next(event for event in artifact["events"] if event["event_kind"] == "commit")
    pointer = commit["targets"][0]["pointer"]
    resolved = resolve_repo_pointer(
        pointer,
        repo,
        subject_identities={SUBJECT_EMAIL},
        scope_key=SCOPE_KEY,
    )
    assert resolved.status == "resolved" and isinstance(resolved.value, bytes)
    assert "value=" not in repr(resolved) and REPO_CONTENT_CANARY not in repr(resolved)

    missing = {
        **pointer,
        "object_id": "f" * 40,
        "target_commitment": {"algorithm": "git-sha1", "digest": "f" * 40},
    }
    unknown = resolve_repo_pointer(
        missing,
        repo,
        subject_identities={SUBJECT_EMAIL},
        scope_key=SCOPE_KEY,
    )
    assert unknown.status == "unknown" and unknown.reason == "target-missing"
    assert unknown.value is None

    mismatched = {
        **pointer,
        "target_commitment": {"algorithm": "git-sha1", "digest": "e" * 40},
    }
    with pytest.raises(RepoEvidenceLoaderError, match="pointer is invalid"):
        resolve_repo_pointer(
            mismatched,
            repo,
            subject_identities={SUBJECT_EMAIL},
            scope_key=SCOPE_KEY,
        )

    replayed = {**pointer, "subject_commit_id": non_subject}
    with pytest.raises(RepoEvidenceLoaderError, match="not subject-authored"):
        resolve_repo_pointer(
            replayed,
            repo,
            subject_identities={SUBJECT_EMAIL},
            scope_key=SCOPE_KEY,
        )


def test_extractor_refuses_unenrolled_repo_and_empty_subject_set(tmp_path):
    repo = tmp_path / "unenrolled"
    repo.mkdir()
    git(repo, "init", "-q")
    with pytest.raises(RepoEvidenceLoaderError, match="not enrolled"):
        capture_enrolled_repo(repo, subject_identities={SUBJECT_EMAIL}, scope_key=SCOPE_KEY)
    with pytest.raises(RepoEvidenceLoaderError, match="identity set is invalid"):
        capture_enrolled_repo(repo, subject_identities=set(), scope_key=SCOPE_KEY)


def test_artifact_and_loader_output_leak_scan_and_companion_fire(enrolled_repo, tmp_path, capsys):
    repo, _repo_id, _root, _non_subject, _live = enrolled_repo
    data, _artifact = artifact_from(repo)
    artifact_path = tmp_path / "repo-evidence.json"
    artifact_path.write_bytes(data)
    output = capsys.readouterr()
    log = tmp_path / "repo-evidence.log"
    log.write_text(output.out + output.err + "source=git status=ok\n")
    canaries = [
        value.encode()
        for value in (
            REPO_CONTENT_CANARY,
            REPO_FILENAME_CANARY,
            REPO_PATH_CANARY,
            REPO_AUTHOR_CANARY,
            REPO_BRANCH_CANARY,
            REPO_NONCE_CANARY,
            str(repo),
        )
    ]
    assert assert_no_canaries([artifact_path, log], canaries) == 2

    planted = tmp_path / "planted.json"
    planted.write_text(REPO_CONTENT_CANARY)
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], [REPO_CONTENT_CANARY.encode()])


@pytest.mark.parametrize("field", ["path", "filename", "content", "author", "branch"])
def test_closed_schema_and_core_validator_reject_smuggled_fields(field):
    synthetic = synthetic_repo_evidence_input()
    data = normalize_repo_evidence(synthetic.snapshots)
    artifact = json.loads(data)
    artifact["events"][0][field] = REPO_CONTENT_CANARY
    with pytest.raises(ValidationError):
        load_validator("repo_evidence.schema.json").validate(artifact)
    tampered = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(NormalizationError) as exc:
        validate_repo_corpus_artifact(tampered)
    assert REPO_CONTENT_CANARY not in str(exc.value)


def test_normalized_store_accepts_repo_artifact(tmp_path):
    from mybench.normalized_store import store_corpus_artifact

    data = normalize_repo_evidence(synthetic_repo_evidence_input().snapshots)
    commitment = validate_repo_corpus_artifact(data)
    stored = store_corpus_artifact(data)
    assert stored == paths.normalized_corpus_path(commitment)
    assert stored.read_bytes() == data


def test_fixed_repo_corpus_root_locks_shared_adr_0013_merkle_contract():
    data = normalize_repo_evidence(synthetic_repo_evidence_input().snapshots)
    artifact = json.loads(data)
    assert artifact["corpus_commitment"] == (
        "11e989ba39b84ecb8dfc9313893c78cc349e7bde822a1b0b3ae52554a31fa9f2"
    )
