"""Fixed commitment-only cross-stream join input for determinism tests."""

from __future__ import annotations

import json
from dataclasses import dataclass

from mybench.normalizer.claude import normalize_claude
from mybench.normalizer.reference_join import ReferenceTargetJoin
from mybench.normalizer.repo import normalize_repo_evidence
from tests.normalizer.repo_synthetic import synthetic_repo_evidence_input
from tests.normalizer.synthetic import synthetic_normalizer_input


@dataclass(frozen=True)
class SyntheticReferenceTargetInput:
    transcript_artifact: bytes
    repo_artifact: bytes
    joins: tuple[ReferenceTargetJoin, ...]
    canaries: tuple[bytes, ...]


def synthetic_reference_target_input() -> SyntheticReferenceTargetInput:
    transcript_source = synthetic_normalizer_input()
    repo_source = synthetic_repo_evidence_input()
    transcript_artifact = normalize_claude(transcript_source.sessions)
    repo_artifact = normalize_repo_evidence(repo_source.snapshots)
    transcript = json.loads(transcript_artifact)
    reference = next(
        event for event in transcript["events"] if event["event_kind"] == "reference"
    )
    return SyntheticReferenceTargetInput(
        transcript_artifact=transcript_artifact,
        repo_artifact=repo_artifact,
        joins=(
            ReferenceTargetJoin(
                reference_record_commitment=reference["pointer"]["record_commitment"],
                reference_block_index=reference["pointer"]["block_index"],
                target_algorithm="git-sha1",
                target_digest="66" * 20,
            ),
        ),
        canaries=tuple(dict.fromkeys((*transcript_source.canaries, *repo_source.canaries))),
    )
