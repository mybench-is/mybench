"""Fixed path-free repository evidence for determinism and privacy tests."""

from __future__ import annotations

from dataclasses import dataclass

from mybench.normalizer.repo import (
    CHANGE_KINDS,
    FILE_CLASSES,
    CommitEvidence,
    RefEvidence,
    RepoTarget,
    VerifiedRepoSnapshot,
    WorktreeEvidence,
)

REPO_CONTENT_CANARY = "MYBENCH-REPO-CONTENT-CANARY-7f31"
REPO_FILENAME_CANARY = "mybench-private-repo-filename-canary-92a4.toml"
REPO_PATH_CANARY = "/synthetic/private/repo/mybench-private-repo-filename-canary-92a4.toml"
REPO_AUTHOR_CANARY = "private-author-canary@example.invalid"
REPO_BRANCH_CANARY = "private-branch-canary-5db8"
REPO_NONCE_CANARY = "9f81c23a4d5e60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef"


@dataclass(frozen=True)
class SyntheticRepoInput:
    snapshots: tuple[VerifiedRepoSnapshot, ...]
    canaries: tuple[bytes, ...]


def _counts(keys: tuple[str, ...], **values: int) -> tuple[tuple[str, int], ...]:
    return tuple((key, values.get(key, 0)) for key in keys)


def synthetic_repo_evidence_input() -> SyntheticRepoInput:
    imported = "11" * 20
    live = "22" * 20
    snapshot = VerifiedRepoSnapshot(
        repo_id="a1" * 8,
        object_format="sha1",
        commits=(
            CommitEvidence(
                commit_id=imported,
                provenance="IMPORTED",
                subject_parent_ids=(),
                structure_status="observed",
                change_counts=_counts(CHANGE_KINDS, added=6),
                file_class_counts=_counts(
                    FILE_CLASSES,
                    manifest=1,
                    docs=1,
                    spec=1,
                    plan=1,
                    handoff=1,
                    other=1,
                ),
                targets=(
                    RepoTarget("blob", "66" * 20, "docs"),
                    RepoTarget("blob", "77" * 20, "handoff"),
                    RepoTarget("blob", "33" * 20, "manifest"),
                    RepoTarget("blob", "88" * 20, "plan"),
                    RepoTarget("blob", "99" * 20, "spec"),
                ),
            ),
            CommitEvidence(
                commit_id=live,
                provenance="LIVE",
                subject_parent_ids=(imported,),
                structure_status="observed",
                change_counts=_counts(CHANGE_KINDS, added=1, modified=1),
                file_class_counts=_counts(FILE_CLASSES, lockfile=1, ci=1),
                targets=(
                    RepoTarget("blob", "44" * 20, "ci"),
                    RepoTarget("blob", "55" * 20, "lockfile"),
                ),
            ),
        ),
        branch_tips=(RefEvidence(live, "LIVE"),),
        reflog_targets=(RefEvidence(imported, "IMPORTED"), RefEvidence(live, "LIVE")),
        worktrees=(WorktreeEvidence("b2" * 8, live, "LIVE"),),
    )
    return SyntheticRepoInput(
        snapshots=(snapshot,),
        canaries=tuple(
            value.encode()
            for value in (
                REPO_CONTENT_CANARY,
                REPO_FILENAME_CANARY,
                REPO_PATH_CANARY,
                REPO_AUTHOR_CANARY,
                REPO_BRANCH_CANARY,
                REPO_NONCE_CANARY,
            )
        ),
    )
