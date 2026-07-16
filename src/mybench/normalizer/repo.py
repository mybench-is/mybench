"""Pure enrolled-repository evidence normalizer (MYB-10.5).

The trusted loader reduces Git state to the frozen dataclasses in this module.
This stage receives no path, Git executable, author identity, clock, or local
configuration authority.  It serializes subject-authored structure plus opaque
Git-object pointers under the exact ADR-0013 normalized-corpus Merkle contract.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from mybench.claims.canonical import CanonicalError, canonical_bytes
from mybench.normalizer.contract import (
    AUTHORSHIP_POLICY_VERSION,
    NoEvidence,
    NormalizationError,
    corpus_commitment,
)

SCHEMA_VERSION = "1"
REPO_NORMALIZER_VERSION = "1.0.0"
GIT_ADAPTER_VERSION = "1.0.0"

_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_OBJECT_FORMATS = frozenset({"sha1", "sha256"})
_OBJECT_TYPES = frozenset({"blob", "commit"})
_PROVENANCE = frozenset({"IMPORTED", "LIVE"})
_STRUCTURE_STATUS = frozenset({"observed", "unknown"})
CHANGE_KINDS = ("added", "modified", "deleted", "type_changed", "other")
FILE_CLASSES = ("manifest", "lockfile", "ci", "other")
_EVENT_KINDS = frozenset({"commit", "branch-tip", "reflog", "worktree"})
_COVERAGE_KEYS = (
    "repositories_admitted",
    "commits_admitted",
    "commits_imported",
    "commits_live",
    "branch_tips_admitted",
    "reflog_targets_admitted",
    "worktrees_admitted",
    "blob_targets_referenced",
    "structures_unknown",
)


@dataclass(frozen=True)
class RepoTarget:
    """One Git object address; bytes remain in the enrolled repository."""

    object_type: str
    object_id: str
    file_class: str | None = None


@dataclass(frozen=True)
class CommitEvidence:
    """Structure derived only from one declared-subject-authored commit."""

    commit_id: str
    provenance: str
    subject_parent_ids: tuple[str, ...]
    structure_status: str
    change_counts: tuple[tuple[str, int], ...] = ()
    file_class_counts: tuple[tuple[str, int], ...] = ()
    targets: tuple[RepoTarget, ...] = ()


@dataclass(frozen=True)
class RefEvidence:
    """A content-free branch-tip or reflog observation."""

    commit_id: str
    provenance: str


@dataclass(frozen=True)
class WorktreeEvidence:
    """One opaque worktree whose HEAD is subject-authored."""

    worktree_id: str
    commit_id: str
    provenance: str


@dataclass(frozen=True)
class VerifiedRepoSnapshot:
    """Path-free, authorship-filtered input supplied by the trusted Git loader."""

    repo_id: str
    object_format: str
    commits: tuple[CommitEvidence, ...]
    branch_tips: tuple[RefEvidence, ...]
    reflog_targets: tuple[RefEvidence, ...]
    worktrees: tuple[WorktreeEvidence, ...]


def _safe_error(message: str) -> NormalizationError:
    return NormalizationError(message)


def _is_uint(value: object) -> bool:
    return type(value) is int and value >= 0


def _is_hex16(value: object) -> bool:
    return isinstance(value, str) and _HEX16.fullmatch(value) is not None


def _valid_oid(value: object, object_format: str) -> bool:
    if not isinstance(value, str):
        return False
    pattern = _HEX40 if object_format == "sha1" else _HEX64
    return pattern.fullmatch(value) is not None


def _counts(value: tuple[tuple[str, int], ...], keys: tuple[str, ...]) -> dict[str, int]:
    if not isinstance(value, tuple) or any(
        not isinstance(item, tuple) or len(item) != 2 for item in value
    ):
        raise _safe_error("repo evidence contains invalid structural counts")
    result = dict(value)
    if tuple(name for name, _count in value) != keys or set(result) != set(keys):
        raise _safe_error("repo evidence contains invalid structural counts")
    if any(not _is_uint(count) for count in result.values()):
        raise _safe_error("repo evidence contains invalid structural counts")
    return result


def _pointer(
    repo_id: str,
    object_format: str,
    target: RepoTarget,
    *,
    subject_commit_id: str | None = None,
) -> dict:
    if type(target) is not RepoTarget:
        raise _safe_error("repo evidence contains an invalid target")
    if target.object_type not in _OBJECT_TYPES or not _valid_oid(target.object_id, object_format):
        raise _safe_error("repo evidence contains an invalid target")
    if target.file_class is not None and (
        target.object_type != "blob" or target.file_class not in FILE_CLASSES
    ):
        raise _safe_error("repo evidence contains an invalid target classification")
    if target.object_type == "blob":
        if not _valid_oid(subject_commit_id, object_format):
            raise _safe_error("repo evidence blob target has no subject origin")
    elif subject_commit_id is not None:
        raise _safe_error("repo evidence commit target has an invalid origin")
    pointer = {
        "repo_id": repo_id,
        "object_type": target.object_type,
        "object_id": target.object_id,
        "target_commitment": {
            "algorithm": f"git-{object_format}",
            "digest": target.object_id,
        },
    }
    if subject_commit_id is not None:
        pointer["subject_commit_id"] = subject_commit_id
    return pointer


def _event_base(repo_id: str, record_index: int, event_kind: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "normalized-repo-event",
        "source": "git",
        "session_id": repo_id,
        "record_index": record_index,
        "subevent_index": 0,
        "event_kind": event_kind,
    }


def _checked_snapshot(snapshot: VerifiedRepoSnapshot) -> VerifiedRepoSnapshot:
    if type(snapshot) is not VerifiedRepoSnapshot:
        raise _safe_error("repo normalizer requires verified snapshots")
    if not _is_hex16(snapshot.repo_id) or snapshot.object_format not in _OBJECT_FORMATS:
        raise _safe_error("repo snapshot has an invalid opaque identity")
    if any(
        not isinstance(values, tuple)
        for values in (
            snapshot.commits,
            snapshot.branch_tips,
            snapshot.reflog_targets,
            snapshot.worktrees,
        )
    ):
        raise _safe_error("repo snapshot collections must be immutable tuples")

    commit_ids = []
    for commit in snapshot.commits:
        if type(commit) is not CommitEvidence:
            raise _safe_error("repo snapshot contains invalid commit evidence")
        if not _valid_oid(commit.commit_id, snapshot.object_format):
            raise _safe_error("repo snapshot contains an invalid commit target")
        if commit.provenance not in _PROVENANCE:
            raise _safe_error("repo snapshot contains invalid provenance")
        if commit.structure_status not in _STRUCTURE_STATUS:
            raise _safe_error("repo snapshot contains invalid structure status")
        if not isinstance(commit.subject_parent_ids, tuple) or any(
            not _valid_oid(parent, snapshot.object_format) for parent in commit.subject_parent_ids
        ):
            raise _safe_error("repo snapshot contains invalid subject-parent evidence")
        if len(commit.subject_parent_ids) != len(set(commit.subject_parent_ids)):
            raise _safe_error("repo snapshot contains duplicate subject-parent evidence")
        if commit.structure_status == "observed":
            change_counts = _counts(commit.change_counts, CHANGE_KINDS)
            file_class_counts = _counts(commit.file_class_counts, FILE_CLASSES)
            if sum(change_counts.values()) != sum(file_class_counts.values()):
                raise _safe_error("repo snapshot structural counts disagree")
            if not isinstance(commit.targets, tuple):
                raise _safe_error("repo snapshot targets must be an immutable tuple")
            target_keys = []
            for target in commit.targets:
                _pointer(
                    snapshot.repo_id,
                    snapshot.object_format,
                    target,
                    subject_commit_id=commit.commit_id,
                )
                if target.object_type != "blob" or target.file_class is None:
                    raise _safe_error("commit evidence target must classify a blob")
                target_keys.append((target.file_class, target.object_id))
            if target_keys != sorted(target_keys) or len(target_keys) != len(set(target_keys)):
                raise _safe_error("repo snapshot targets are not sorted and unique")
            target_class_counts = {
                file_class: sum(
                    1 for target_class, _object_id in target_keys if target_class == file_class
                )
                for file_class in FILE_CLASSES
            }
            if any(
                target_class_counts[file_class] > file_class_counts[file_class]
                for file_class in FILE_CLASSES
            ):
                raise _safe_error("repo snapshot blob targets exceed structural counts")
        elif commit.change_counts or commit.file_class_counts or commit.targets:
            raise _safe_error("unknown repo structure cannot carry observed values")
        commit_ids.append(commit.commit_id)
    if len(commit_ids) != len(set(commit_ids)):
        raise _safe_error("repo snapshot contains duplicate commit evidence")
    admitted = set(commit_ids)
    for commit in snapshot.commits:
        if not set(commit.subject_parent_ids) <= admitted:
            raise _safe_error("repo snapshot points to an unadmitted parent")

    for refs in (snapshot.branch_tips, snapshot.reflog_targets):
        keys = []
        for ref in refs:
            if type(ref) is not RefEvidence or ref.commit_id not in admitted:
                raise _safe_error("repo snapshot reference is not subject-authored")
            if ref.provenance not in _PROVENANCE:
                raise _safe_error("repo snapshot contains invalid provenance")
            keys.append(ref.commit_id)
        if len(keys) != len(set(keys)):
            raise _safe_error("repo snapshot contains duplicate reference evidence")
    worktree_keys = []
    for worktree in snapshot.worktrees:
        if type(worktree) is not WorktreeEvidence or not _is_hex16(worktree.worktree_id):
            raise _safe_error("repo snapshot contains invalid worktree evidence")
        if worktree.commit_id not in admitted or worktree.provenance not in _PROVENANCE:
            raise _safe_error("repo snapshot worktree is not subject-authored")
        worktree_keys.append(worktree.worktree_id)
    if len(worktree_keys) != len(set(worktree_keys)):
        raise _safe_error("repo snapshot contains duplicate worktree evidence")
    return snapshot


def normalize_repo_evidence(snapshots: Sequence[VerifiedRepoSnapshot]) -> bytes:
    """Return one canonical A8 artifact from explicit enrolled-repo snapshots."""
    if isinstance(snapshots, (str, bytes)) or not isinstance(snapshots, Sequence):
        raise _safe_error("repo normalizer input must be a snapshot sequence")
    if not snapshots:
        raise NoEvidence("no verified repository input exists")
    checked = sorted(
        (_checked_snapshot(snapshot) for snapshot in snapshots), key=lambda s: s.repo_id
    )
    if len({snapshot.repo_id for snapshot in checked}) != len(checked):
        raise _safe_error("repo normalizer received duplicate repository identities")

    events = []
    repositories = []
    coverage = {key: 0 for key in _COVERAGE_KEYS}
    coverage["repositories_admitted"] = len(checked)
    for snapshot in checked:
        repo_events = []
        commits = sorted(snapshot.commits, key=lambda item: item.commit_id)
        for commit in commits:
            event = _event_base(snapshot.repo_id, len(repo_events), "commit")
            event.update(
                {
                    "provenance": commit.provenance,
                    "pointer": _pointer(
                        snapshot.repo_id,
                        snapshot.object_format,
                        RepoTarget("commit", commit.commit_id),
                    ),
                    "subject_parents": [
                        _pointer(
                            snapshot.repo_id,
                            snapshot.object_format,
                            RepoTarget("commit", parent),
                        )
                        for parent in sorted(commit.subject_parent_ids)
                    ],
                    "structure_status": commit.structure_status,
                }
            )
            if commit.structure_status == "observed":
                event["change_counts"] = _counts(commit.change_counts, CHANGE_KINDS)
                event["file_class_counts"] = _counts(commit.file_class_counts, FILE_CLASSES)
                event["targets"] = [
                    {
                        "file_class": target.file_class,
                        "pointer": _pointer(
                            snapshot.repo_id,
                            snapshot.object_format,
                            target,
                            subject_commit_id=commit.commit_id,
                        ),
                    }
                    for target in commit.targets
                ]
                coverage["blob_targets_referenced"] += len(commit.targets)
            else:
                coverage["structures_unknown"] += 1
            coverage["commits_admitted"] += 1
            coverage["commits_imported" if commit.provenance == "IMPORTED" else "commits_live"] += 1
            repo_events.append(event)

        for kind, refs, coverage_key in (
            ("branch-tip", snapshot.branch_tips, "branch_tips_admitted"),
            ("reflog", snapshot.reflog_targets, "reflog_targets_admitted"),
        ):
            for ref in sorted(refs, key=lambda item: item.commit_id):
                event = _event_base(snapshot.repo_id, len(repo_events), kind)
                event.update(
                    {
                        "provenance": ref.provenance,
                        "pointer": _pointer(
                            snapshot.repo_id,
                            snapshot.object_format,
                            RepoTarget("commit", ref.commit_id),
                        ),
                    }
                )
                repo_events.append(event)
                coverage[coverage_key] += 1

        for worktree in sorted(snapshot.worktrees, key=lambda item: item.worktree_id):
            event = _event_base(snapshot.repo_id, len(repo_events), "worktree")
            event.update(
                {
                    "worktree_id": worktree.worktree_id,
                    "provenance": worktree.provenance,
                    "pointer": _pointer(
                        snapshot.repo_id,
                        snapshot.object_format,
                        RepoTarget("commit", worktree.commit_id),
                    ),
                }
            )
            repo_events.append(event)
            coverage["worktrees_admitted"] += 1

        repositories.append(
            {
                "repo_id": snapshot.repo_id,
                "object_format": snapshot.object_format,
                "admitted_commit_count": len(commits),
                "event_count": len(repo_events),
            }
        )
        events.extend(repo_events)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "normalized-repo-corpus-manifest",
        "normalizer": {
            "name": "mybench.normalizer.repo",
            "version": REPO_NORMALIZER_VERSION,
            "authorship_policy_version": AUTHORSHIP_POLICY_VERSION,
        },
        "adapters": [{"source": "git", "version": GIT_ADAPTER_VERSION}],
        "repositories": repositories,
        "coverage": coverage,
        "event_count": len(events),
    }
    root = corpus_commitment(manifest, events)
    artifact = {
        "schema_version": SCHEMA_VERSION,
        "kind": "normalized-repo-corpus-artifact",
        "corpus_commitment": root,
        "manifest": manifest,
        "events": events,
    }
    return canonical_bytes(artifact) + b"\n"


def _exact_keys(value: object, required: set[str], optional: set[str] = set()) -> bool:
    return isinstance(value, dict) and required <= set(value) <= required | optional


def _validate_pointer(pointer: object, object_format: str, repo_id: str) -> None:
    if not _exact_keys(
        pointer,
        {"repo_id", "object_type", "object_id", "target_commitment"},
        {"subject_commit_id"},
    ):
        raise _safe_error("normalized repo pointer has invalid fields")
    assert isinstance(pointer, dict)
    if pointer["repo_id"] != repo_id or pointer["object_type"] not in _OBJECT_TYPES:
        raise _safe_error("normalized repo pointer has an invalid address")
    if not _valid_oid(pointer["object_id"], object_format):
        raise _safe_error("normalized repo pointer has an invalid object id")
    if pointer["object_type"] == "blob":
        if not _valid_oid(pointer.get("subject_commit_id"), object_format):
            raise _safe_error("normalized repo blob pointer has no subject origin")
    elif "subject_commit_id" in pointer:
        raise _safe_error("normalized repo commit pointer has an invalid origin")
    commitment = pointer["target_commitment"]
    if not _exact_keys(commitment, {"algorithm", "digest"}) or commitment != {
        "algorithm": f"git-{object_format}",
        "digest": pointer["object_id"],
    }:
        raise _safe_error("normalized repo pointer has an invalid target commitment")


def _event_order_key(event: Mapping) -> tuple:
    try:
        return (
            event["source"].encode(),
            event["session_id"].encode(),
            event["record_index"],
            event["subevent_index"],
        )
    except (AttributeError, KeyError, TypeError):
        raise _safe_error("normalized repo event has an invalid order key") from None


def _validate_artifact_semantics(artifact: dict) -> None:
    manifest = artifact["manifest"]
    required_manifest = {
        "schema_version",
        "kind",
        "normalizer",
        "adapters",
        "repositories",
        "coverage",
        "event_count",
    }
    if not _exact_keys(manifest, required_manifest):
        raise _safe_error("normalized repo manifest has invalid fields")
    if (
        manifest["schema_version"] != SCHEMA_VERSION
        or manifest["kind"] != "normalized-repo-corpus-manifest"
    ):
        raise _safe_error("normalized repo manifest has an invalid version or kind")
    if manifest["normalizer"] != {
        "name": "mybench.normalizer.repo",
        "version": REPO_NORMALIZER_VERSION,
        "authorship_policy_version": AUTHORSHIP_POLICY_VERSION,
    } or manifest["adapters"] != [{"source": "git", "version": GIT_ADAPTER_VERSION}]:
        raise _safe_error("normalized repo manifest has an unsupported normalizer")
    repositories = manifest["repositories"]
    if not isinstance(repositories, list) or not repositories:
        raise _safe_error("normalized repo manifest has no repository inventory")
    repo_formats = {}
    repo_event_counts = {}
    for repository in repositories:
        if not _exact_keys(
            repository,
            {"repo_id", "object_format", "admitted_commit_count", "event_count"},
        ):
            raise _safe_error("normalized repo manifest repository has invalid fields")
        repo_id = repository["repo_id"]
        if not _is_hex16(repo_id) or repository["object_format"] not in _OBJECT_FORMATS:
            raise _safe_error("normalized repo manifest repository has invalid identity")
        if not _is_uint(repository["admitted_commit_count"]) or not _is_uint(
            repository["event_count"]
        ):
            raise _safe_error("normalized repo manifest repository has invalid counts")
        repo_formats[repo_id] = repository["object_format"]
        repo_event_counts[repo_id] = repository["event_count"]
    if list(repo_formats) != sorted(repo_formats) or len(repo_formats) != len(repositories):
        raise _safe_error("normalized repo inventory is not sorted and unique")
    coverage = manifest["coverage"]
    if not _exact_keys(coverage, set(_COVERAGE_KEYS)) or any(
        not _is_uint(value) for value in coverage.values()
    ):
        raise _safe_error("normalized repo manifest has invalid coverage")

    events = artifact["events"]
    if manifest["event_count"] != len(events) or sum(repo_event_counts.values()) != len(events):
        raise _safe_error("normalized repo manifest event count is inconsistent")
    observed = {key: 0 for key in _COVERAGE_KEYS}
    observed["repositories_admitted"] = len(repositories)
    indexes = {repo_id: [] for repo_id in repo_formats}
    admitted_commits = {repo_id: set() for repo_id in repo_formats}
    commit_provenance = {repo_id: {} for repo_id in repo_formats}
    reference_targets = {
        repo_id: {"branch-tip": set(), "reflog": set()} for repo_id in repo_formats
    }
    worktree_ids = {repo_id: set() for repo_id in repo_formats}
    deferred_parent_checks = []
    deferred_reference_checks = []
    for event in events:
        common = {
            "schema_version",
            "kind",
            "source",
            "session_id",
            "record_index",
            "subevent_index",
            "event_kind",
            "provenance",
            "pointer",
        }
        if not isinstance(event, dict) or not common <= set(event):
            raise _safe_error("normalized repo event has invalid fields")
        repo_id = event["session_id"]
        if (
            repo_id not in repo_formats
            or event["schema_version"] != SCHEMA_VERSION
            or event["kind"] != "normalized-repo-event"
            or event["source"] != "git"
            or not _is_uint(event["record_index"])
            or event["subevent_index"] != 0
            or event["event_kind"] not in _EVENT_KINDS
            or event["provenance"] not in _PROVENANCE
        ):
            raise _safe_error("normalized repo event has invalid common fields")
        indexes[repo_id].append(event["record_index"])
        _validate_pointer(event["pointer"], repo_formats[repo_id], repo_id)
        if event["pointer"]["object_type"] != "commit":
            raise _safe_error("normalized repo event must point to a commit")
        kind = event["event_kind"]
        if kind == "commit":
            allowed = common | {
                "subject_parents",
                "structure_status",
                "change_counts",
                "file_class_counts",
                "targets",
            }
            required = common | {"subject_parents", "structure_status"}
            if not required <= set(event) <= allowed:
                raise _safe_error("normalized repo commit event has invalid fields")
            commit_id = event["pointer"]["object_id"]
            if commit_id in admitted_commits[repo_id]:
                raise _safe_error("normalized repo contains duplicate commit evidence")
            admitted_commits[repo_id].add(commit_id)
            commit_provenance[repo_id][commit_id] = event["provenance"]
            observed["commits_admitted"] += 1
            observed[
                "commits_imported" if event["provenance"] == "IMPORTED" else "commits_live"
            ] += 1
            if event["structure_status"] not in _STRUCTURE_STATUS or not isinstance(
                event["subject_parents"], list
            ):
                raise _safe_error("normalized repo commit has invalid structure state")
            parent_ids = []
            for parent in event["subject_parents"]:
                _validate_pointer(parent, repo_formats[repo_id], repo_id)
                if parent["object_type"] != "commit":
                    raise _safe_error("normalized repo parent is not a commit")
                parent_ids.append(parent["object_id"])
            if parent_ids != sorted(set(parent_ids)):
                raise _safe_error("normalized repo parents are not sorted and unique")
            deferred_parent_checks.append((repo_id, set(parent_ids)))
            if event["structure_status"] == "unknown":
                if set(event) != required:
                    raise _safe_error("unknown repo structure carries observed values")
                observed["structures_unknown"] += 1
            else:
                if set(event) != allowed:
                    raise _safe_error("observed repo structure is incomplete")
                if set(event["change_counts"]) != set(CHANGE_KINDS) or set(
                    event["file_class_counts"]
                ) != set(FILE_CLASSES):
                    raise _safe_error("normalized repo structure has invalid count fields")
                if any(
                    not _is_uint(value)
                    for value in (
                        *event["change_counts"].values(),
                        *event["file_class_counts"].values(),
                    )
                ) or not isinstance(event["targets"], list):
                    raise _safe_error("normalized repo structure has invalid counts")
                if sum(event["change_counts"].values()) != sum(event["file_class_counts"].values()):
                    raise _safe_error("normalized repo structure counts disagree")
                target_keys = []
                for target in event["targets"]:
                    if (
                        not _exact_keys(target, {"file_class", "pointer"})
                        or target["file_class"] not in FILE_CLASSES
                    ):
                        raise _safe_error("normalized repo blob target has invalid fields")
                    _validate_pointer(target["pointer"], repo_formats[repo_id], repo_id)
                    if target["pointer"]["object_type"] != "blob":
                        raise _safe_error("normalized repo structure target is not a blob")
                    if target["pointer"]["subject_commit_id"] != commit_id:
                        raise _safe_error(
                            "normalized repo blob target has the wrong subject origin"
                        )
                    target_keys.append((target["file_class"], target["pointer"]["object_id"]))
                if target_keys != sorted(set(target_keys)):
                    raise _safe_error("normalized repo blob targets are not sorted and unique")
                target_classes = {}
                for file_class, _object_id in target_keys:
                    target_classes[file_class] = target_classes.get(file_class, 0) + 1
                if any(
                    count > event["file_class_counts"][file_class]
                    for file_class, count in target_classes.items()
                ):
                    raise _safe_error("normalized repo blob targets exceed structural counts")
                observed["blob_targets_referenced"] += len(target_keys)
        elif kind in {"branch-tip", "reflog"}:
            if set(event) != common:
                raise _safe_error("normalized repo reference event has invalid fields")
            target_id = event["pointer"]["object_id"]
            if target_id in reference_targets[repo_id][kind]:
                raise _safe_error("normalized repo contains duplicate reference evidence")
            reference_targets[repo_id][kind].add(target_id)
            deferred_reference_checks.append((repo_id, target_id, event["provenance"]))
            observed[
                "branch_tips_admitted" if kind == "branch-tip" else "reflog_targets_admitted"
            ] += 1
        else:
            if set(event) != common | {"worktree_id"} or not _is_hex16(event["worktree_id"]):
                raise _safe_error("normalized repo worktree event has invalid fields")
            if event["worktree_id"] in worktree_ids[repo_id]:
                raise _safe_error("normalized repo contains duplicate worktree evidence")
            worktree_ids[repo_id].add(event["worktree_id"])
            deferred_reference_checks.append(
                (repo_id, event["pointer"]["object_id"], event["provenance"])
            )
            observed["worktrees_admitted"] += 1
    for repo_id, parents in deferred_parent_checks:
        if not parents <= admitted_commits[repo_id]:
            raise _safe_error("normalized repo event points to an unadmitted parent")
    for repo_id, target_id, provenance in deferred_reference_checks:
        if commit_provenance[repo_id].get(target_id) != provenance:
            raise _safe_error("normalized repo reference is not subject-authored")
    for repository in repositories:
        repo_id = repository["repo_id"]
        if repository["admitted_commit_count"] != len(admitted_commits[repo_id]):
            raise _safe_error("normalized repo admitted commit count is inconsistent")
        if indexes[repo_id] != list(range(repository["event_count"])):
            raise _safe_error("normalized repo event indexes are not contiguous")
    if coverage != observed:
        raise _safe_error("normalized repo coverage is inconsistent")


def validate_repo_corpus_artifact(data: bytes) -> str:
    """Validate canonical repo artifact shape and Merkle binding."""
    if type(data) is not bytes or not data.endswith(b"\n"):
        raise _safe_error("normalized repo corpus must be one canonical JSON line")
    try:
        artifact = json.loads(data[:-1].decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _safe_error("normalized repo corpus is not valid JSON") from None
    if not isinstance(artifact, dict):
        raise _safe_error("normalized repo corpus artifact must be an object")
    try:
        if canonical_bytes(artifact) + b"\n" != data:
            raise _safe_error("normalized repo corpus is not canonically serialized")
    except (CanonicalError, ValueError, RecursionError):
        raise _safe_error("normalized repo corpus contains a non-canonical value") from None
    if (
        set(artifact)
        != {
            "schema_version",
            "kind",
            "corpus_commitment",
            "manifest",
            "events",
        }
        or artifact.get("schema_version") != SCHEMA_VERSION
        or artifact.get("kind") != "normalized-repo-corpus-artifact"
    ):
        raise _safe_error("normalized repo corpus artifact has invalid fields")
    if not isinstance(artifact["events"], list):
        raise _safe_error("normalized repo corpus events must be an array")
    _validate_artifact_semantics(artifact)
    keys = [_event_order_key(event) for event in artifact["events"]]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise _safe_error("normalized repo events are not sorted and unique")
    expected = corpus_commitment(artifact["manifest"], artifact["events"])
    if artifact["corpus_commitment"] != expected:
        raise _safe_error("normalized repo corpus commitment does not match its records")
    return expected
