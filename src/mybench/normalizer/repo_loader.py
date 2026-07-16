"""Trusted Git boundary for MYB-10.5 enrolled-repository evidence.

Raw paths, ref names, author identities, filenames, messages, and object bytes
exist only inside this boundary.  The returned snapshot contains subject-only
derived structure and opaque addresses; failures use fixed messages that cannot
relay Git stderr or a private path.
"""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from mybench import paths
from mybench.hooks import binding
from mybench.normalizer.repo import (
    CHANGE_KINDS,
    FILE_CLASSES,
    CommitEvidence,
    RefEvidence,
    RepoTarget,
    VerifiedRepoSnapshot,
    WorktreeEvidence,
)

_ZERO_OIDS = frozenset({"0" * 40, "0" * 64})
_MANIFEST_NAMES = frozenset(
    {
        b"cargo.toml",
        b"composer.json",
        b"gemfile",
        b"go.mod",
        b"mix.exs",
        b"package.json",
        b"pipfile",
        b"pom.xml",
        b"pyproject.toml",
        b"requirements.txt",
    }
)
_LOCKFILE_NAMES = frozenset(
    {
        b"cargo.lock",
        b"composer.lock",
        b"flake.lock",
        b"gemfile.lock",
        b"go.sum",
        b"mix.lock",
        b"package-lock.json",
        b"pipfile.lock",
        b"pnpm-lock.yaml",
        b"poetry.lock",
        b"uv.lock",
        b"yarn.lock",
    }
)
_CI_NAMES = frozenset({b".gitlab-ci.yml", b"azure-pipelines.yml", b"jenkinsfile"})


class RepoEvidenceLoaderError(RuntimeError):
    """Generic trusted-loader refusal; messages never contain private input."""


class _GitFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class RepoTargetResolution:
    """Resolution result whose repr deliberately hides target bytes."""

    status: str
    reason: str | None = None
    value: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        resolved = (
            self.status == "resolved" and self.reason is None and isinstance(self.value, bytes)
        )
        unknown = (
            self.status == "unknown" and self.reason == "target-missing" and self.value is None
        )
        if not (resolved or unknown):
            raise RepoEvidenceLoaderError("repository target resolution has invalid state")


def _run_git(
    repo: Path,
    *args: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            input=input_bytes,
            capture_output=True,
            check=False,
        )
    except (OSError, ValueError):
        raise _GitFailure from None
    if check and result.returncode != 0:
        raise _GitFailure
    return result


def _git_bytes(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    return _run_git(repo, *args, input_bytes=input_bytes).stdout


def _git_ascii(repo: Path, *args: str, input_bytes: bytes | None = None) -> str:
    try:
        return _git_bytes(repo, *args, input_bytes=input_bytes).strip().decode("ascii")
    except UnicodeDecodeError:
        raise _GitFailure from None


def _object_format(repo: Path) -> str:
    value = _git_ascii(repo, "rev-parse", "--show-object-format")
    if value not in {"sha1", "sha256"}:
        raise _GitFailure
    return value


def _valid_oid(value: object, object_format: str) -> bool:
    if not isinstance(value, str):
        return False
    length = 40 if object_format == "sha1" else 64
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


def _subject_set(subject_identities: Iterable[str]) -> frozenset[bytes]:
    if isinstance(subject_identities, (str, bytes)):
        raise RepoEvidenceLoaderError("declared subject identity set is invalid")
    try:
        values = frozenset(
            identity.strip().casefold().encode("utf-8") for identity in subject_identities
        )
    except (AttributeError, TypeError, UnicodeEncodeError):
        raise RepoEvidenceLoaderError("declared subject identity set is invalid") from None
    if not values or b"" in values:
        raise RepoEvidenceLoaderError("declared subject identity set is invalid")
    return values


def _worktree_records(repo: Path) -> list[tuple[Path, str]]:
    fields = _git_bytes(repo, "worktree", "list", "--porcelain", "-z").split(b"\0")
    records = []
    current_path = None
    current_head = None
    for field_value in fields:
        if not field_value:
            if current_path is not None and current_head is not None:
                records.append((current_path, current_head))
            current_path = None
            current_head = None
        elif field_value.startswith(b"worktree "):
            try:
                current_path = Path(
                    field_value[len(b"worktree ") :].decode("utf-8", errors="surrogateescape")
                )
            except UnicodeDecodeError:
                raise _GitFailure from None
        elif field_value.startswith(b"HEAD "):
            try:
                current_head = field_value[len(b"HEAD ") :].decode("ascii")
            except UnicodeDecodeError:
                raise _GitFailure from None
    return records


def _commit_metadata(repo: Path, object_id: str) -> tuple[tuple[str, ...], bytes]:
    raw = _git_bytes(repo, "show", "-s", "--format=%P%x00%ae", object_id).rstrip(b"\n")
    parts = raw.split(b"\0")
    if len(parts) != 2:
        raise _GitFailure
    try:
        parents = tuple(part.decode("ascii") for part in parts[0].split())
    except UnicodeDecodeError:
        raise _GitFailure from None
    return parents, parts[1].strip().lower()


def _provenance(repo: Path, object_id: str, enroll_commit: str) -> str:
    if not enroll_commit:
        return "LIVE"
    if object_id == enroll_commit:
        return "IMPORTED"
    result = _run_git(
        repo,
        "merge-base",
        "--is-ancestor",
        enroll_commit,
        object_id,
        check=False,
    )
    if result.returncode == 0:
        return "LIVE"
    if result.returncode == 1:
        return "IMPORTED"
    raise _GitFailure


def _file_class(raw_path: bytes) -> str:
    lowered = raw_path.lower()
    name = lowered.rsplit(b"/", 1)[-1]
    if (
        b"/.github/workflows/" in b"/" + lowered
        or name in _CI_NAMES
        or lowered.endswith(b"/.circleci/config.yml")
    ):
        return "ci"
    if name in _LOCKFILE_NAMES:
        return "lockfile"
    if name in _MANIFEST_NAMES:
        return "manifest"
    return "other"


def _root_changes(repo: Path, object_id: str) -> list[tuple[str, bytes, str | None]]:
    entries = []
    for raw_entry in _git_bytes(repo, "ls-tree", "-r", "-z", "--full-tree", object_id).split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        parts = metadata.split()
        if not separator or len(parts) != 3:
            raise _GitFailure
        try:
            object_type = parts[1].decode("ascii")
            target = parts[2].decode("ascii")
        except UnicodeDecodeError:
            raise _GitFailure from None
        entries.append(("A", raw_path, target if object_type == "blob" else None))
    return entries


def _diff_changes(
    repo: Path, parent_id: str, object_id: str
) -> list[tuple[str, bytes, str | None]] | None:
    if _run_git(repo, "cat-file", "-e", f"{parent_id}^{{commit}}", check=False).returncode != 0:
        return None
    raw = _git_bytes(
        repo,
        "diff-tree",
        "--no-commit-id",
        "--raw",
        "-r",
        "-z",
        "--no-renames",
        "--no-abbrev",
        parent_id,
        object_id,
    )
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) % 2:
        raise _GitFailure
    entries = []
    for index in range(0, len(parts), 2):
        header, raw_path = parts[index], parts[index + 1]
        fields = header.split()
        if len(fields) != 5 or not fields[0].startswith(b":"):
            raise _GitFailure
        try:
            status = fields[4][:1].decode("ascii")
            new_mode = fields[1].decode("ascii")
            new_id = fields[3].decode("ascii")
        except UnicodeDecodeError:
            raise _GitFailure from None
        target = (
            new_id
            if status != "D"
            and new_id not in _ZERO_OIDS
            and new_mode not in {"000000", "040000", "160000"}
            else None
        )
        entries.append((status, raw_path, target))
    return entries


def _structure(
    repo: Path,
    object_id: str,
    parents: tuple[str, ...],
    object_format: str,
) -> tuple[str, tuple[tuple[str, int], ...], tuple[tuple[str, int], ...], tuple[RepoTarget, ...]]:
    # A merge diff can import third-party branch content even when the merge
    # commit author is the subject. Keep the subject commit pointer, but emit
    # no derived tree structure or blob target for that ambiguous boundary.
    if len(parents) > 1:
        return "unknown", (), (), ()
    changes = (
        _root_changes(repo, object_id)
        if not parents
        else _diff_changes(repo, parents[0], object_id)
    )
    if changes is None:
        return "unknown", (), (), ()
    change_counts = Counter({key: 0 for key in CHANGE_KINDS})
    class_counts = Counter({key: 0 for key in FILE_CLASSES})
    targets = set()
    status_map = {"A": "added", "M": "modified", "D": "deleted", "T": "type_changed"}
    for status, raw_path, target_id in changes:
        change_counts[status_map.get(status, "other")] += 1
        file_class = _file_class(raw_path)
        class_counts[file_class] += 1
        if target_id is not None:
            if not _valid_oid(target_id, object_format):
                raise _GitFailure
            targets.add((file_class, target_id))
    return (
        "observed",
        tuple((key, change_counts[key]) for key in CHANGE_KINDS),
        tuple((key, class_counts[key]) for key in FILE_CLASSES),
        tuple(
            RepoTarget("blob", target_id, file_class) for file_class, target_id in sorted(targets)
        ),
    )


def _enrollment(repo_id: str) -> dict:
    enrollment_path = paths.enrollment_path(repo_id)
    if not enrollment_path.is_file():
        raise RepoEvidenceLoaderError("repository is not enrolled")
    try:
        record = json.loads(enrollment_path.read_bytes())
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        raise RepoEvidenceLoaderError("repository enrollment record is invalid") from None
    if (
        not isinstance(record, dict)
        or set(record) != {"repo_id", "enroll_commit", "enroll_ts"}
        or record.get("repo_id") != repo_id
        or not isinstance(record.get("enroll_commit"), str)
        or not isinstance(record.get("enroll_ts"), str)
    ):
        raise RepoEvidenceLoaderError("repository enrollment record is invalid")
    return record


def capture_enrolled_repo(
    repo: str | Path,
    *,
    subject_identities: Iterable[str],
    scope_key: bytes | None = None,
) -> VerifiedRepoSnapshot:
    """Capture one deterministic, subject-filtered snapshot from an enrolled repo."""
    subjects = _subject_set(subject_identities)
    try:
        requested = Path(repo)
        top = Path(
            _git_bytes(requested, "rev-parse", "--show-toplevel")
            .decode("utf-8", errors="surrogateescape")
            .strip()
        )
        if not (top / binding.MARKER_RELPATH).is_file():
            raise RepoEvidenceLoaderError("repository is not enrolled")
        repo_id = binding.repo_identity_for_worktree(top, scope_key=scope_key)
        enrollment = _enrollment(repo_id)
        object_format = _object_format(top)
        enroll_commit = enrollment["enroll_commit"]
        if enroll_commit and not _valid_oid(enroll_commit, object_format):
            raise RepoEvidenceLoaderError("repository enrollment record is invalid")
        if (
            enroll_commit
            and _run_git(
                top, "cat-file", "-e", f"{enroll_commit}^{{commit}}", check=False
            ).returncode
            != 0
        ):
            raise RepoEvidenceLoaderError("repository enrollment boundary is unavailable")

        branch_ids = {
            value.decode("ascii")
            for value in _git_bytes(
                top, "for-each-ref", "--format=%(objectname)", "refs/heads"
            ).splitlines()
            if value
        }
        reflog_result = _run_git(top, "reflog", "show", "--all", "--format=%H", check=False)
        if reflog_result.returncode not in {0, 1}:
            raise _GitFailure
        reflog_ids = {
            value.decode("ascii") for value in reflog_result.stdout.splitlines() if value
        } - _ZERO_OIDS
        worktree_records = _worktree_records(top)
        worktree_heads = {head for _path, head in worktree_records}
        candidates = (
            {
                value.decode("ascii")
                for value in _git_bytes(top, "rev-list", "--all", "--reflog").splitlines()
                if value
            }
            | branch_ids
            | reflog_ids
            | worktree_heads
        )
        if any(not _valid_oid(object_id, object_format) for object_id in candidates):
            raise _GitFailure

        metadata = {object_id: _commit_metadata(top, object_id) for object_id in sorted(candidates)}
        admitted = {
            object_id
            for object_id, (_parents, author_email) in metadata.items()
            if author_email in subjects
        }
        provenance = {
            object_id: _provenance(top, object_id, enroll_commit) for object_id in admitted
        }
        commits = []
        for object_id in sorted(admitted):
            parents = metadata[object_id][0]
            structure_status, change_counts, file_counts, targets = _structure(
                top, object_id, parents, object_format
            )
            commits.append(
                CommitEvidence(
                    commit_id=object_id,
                    provenance=provenance[object_id],
                    subject_parent_ids=tuple(sorted(set(parents) & admitted)),
                    structure_status=structure_status,
                    change_counts=change_counts,
                    file_class_counts=file_counts,
                    targets=targets,
                )
            )
        branch_tips = tuple(
            RefEvidence(object_id, provenance[object_id])
            for object_id in sorted(branch_ids & admitted)
        )
        reflog_targets = tuple(
            RefEvidence(object_id, provenance[object_id])
            for object_id in sorted(reflog_ids & admitted)
        )
        worktrees = tuple(
            sorted(
                (
                    WorktreeEvidence(
                        worktree_id=binding.worktree_identity(worktree_path, scope_key=scope_key),
                        commit_id=head,
                        provenance=provenance[head],
                    )
                    for worktree_path, head in worktree_records
                    if head in admitted
                ),
                key=lambda item: item.worktree_id,
            )
        )
        return VerifiedRepoSnapshot(
            repo_id=repo_id,
            object_format=object_format,
            commits=tuple(commits),
            branch_tips=branch_tips,
            reflog_targets=reflog_targets,
            worktrees=worktrees,
        )
    except RepoEvidenceLoaderError:
        raise
    except Exception:
        raise RepoEvidenceLoaderError("repository evidence extraction failed") from None


def resolve_repo_pointer(
    pointer: dict,
    repo: str | Path,
    *,
    subject_identities: Iterable[str],
    scope_key: bytes | None = None,
) -> RepoTargetResolution:
    """Resolve and verify a Git-object pointer, or return honest UNKNOWN if absent."""
    subjects = _subject_set(subject_identities)
    try:
        requested = Path(repo)
        top = Path(
            _git_bytes(requested, "rev-parse", "--show-toplevel")
            .decode("utf-8", errors="surrogateescape")
            .strip()
        )
        if not (top / binding.MARKER_RELPATH).is_file():
            raise RepoEvidenceLoaderError("repository is not enrolled")
        repo_id = binding.repo_identity_for_worktree(top, scope_key=scope_key)
        _enrollment(repo_id)
        object_format = _object_format(top)
        base_fields = {
            "repo_id",
            "object_type",
            "object_id",
            "target_commitment",
        }
        object_type = pointer.get("object_type") if isinstance(pointer, dict) else None
        expected_fields = base_fields | ({"subject_commit_id"} if object_type == "blob" else set())
        if (
            not isinstance(pointer, dict)
            or set(pointer) != expected_fields
            or pointer.get("repo_id") != repo_id
            or object_type not in {"blob", "commit"}
            or not _valid_oid(pointer.get("object_id", ""), object_format)
            or (
                object_type == "blob"
                and not _valid_oid(pointer.get("subject_commit_id", ""), object_format)
            )
            or pointer.get("target_commitment")
            != {
                "algorithm": f"git-{object_format}",
                "digest": pointer.get("object_id"),
            }
        ):
            raise RepoEvidenceLoaderError("repository target pointer is invalid")
        object_id = pointer["object_id"]
        origin_id = pointer.get("subject_commit_id", object_id)
        if _run_git(top, "cat-file", "-e", f"{origin_id}^{{commit}}", check=False).returncode != 0:
            return RepoTargetResolution("unknown", reason="target-missing")
        parents, author = _commit_metadata(top, origin_id)
        if author not in subjects:
            raise RepoEvidenceLoaderError("repository target pointer is not subject-authored")
        if _run_git(top, "cat-file", "-e", object_id, check=False).returncode != 0:
            return RepoTargetResolution("unknown", reason="target-missing")
        if object_type == "blob":
            structure_status, _changes, _classes, targets = _structure(
                top,
                origin_id,
                parents,
                object_format,
            )
            if structure_status != "observed":
                return RepoTargetResolution("unknown", reason="target-missing")
            if object_id not in {target.object_id for target in targets}:
                raise RepoEvidenceLoaderError("repository target pointer is not subject-derived")
        actual_type = _git_ascii(top, "cat-file", "-t", object_id)
        if actual_type != object_type:
            raise RepoEvidenceLoaderError("repository target commitment does not verify")
        raw = _git_bytes(top, "cat-file", actual_type, object_id)
        verified_id = _git_ascii(
            top,
            "hash-object",
            "-t",
            actual_type,
            "--stdin",
            input_bytes=raw,
        )
        if verified_id != object_id:
            raise RepoEvidenceLoaderError("repository target commitment does not verify")
        return RepoTargetResolution("resolved", value=raw)
    except RepoEvidenceLoaderError:
        raise
    except Exception:
        raise RepoEvidenceLoaderError("repository target resolution failed") from None
