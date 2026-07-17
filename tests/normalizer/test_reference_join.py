"""MYB-19.2 commitment-only transcript-reference to repo-target joins."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from jsonschema import ValidationError

from mybench import paths
from mybench.claims.canonical import canonical_bytes
from mybench.normalized_store import store_corpus_artifact
from mybench.normalizer import NormalizationError
from mybench.normalizer.reference_join import (
    normalize_reference_target_joins,
    validate_reference_target_corpus_artifact,
)
from mybench.schemas import load_validator
from tests.normalizer.reference_synthetic import synthetic_reference_target_input


def test_join_is_canonical_closed_commitment_only_and_storable():
    synthetic = synthetic_reference_target_input()
    data = normalize_reference_target_joins(
        synthetic.transcript_artifact,
        synthetic.repo_artifact,
        synthetic.joins,
    )
    artifact = json.loads(data)
    load_validator("reference_target_join.schema.json").validate(artifact)
    commitment = validate_reference_target_corpus_artifact(data)
    assert commitment == artifact["corpus_commitment"]
    assert artifact["manifest"]["inputs"] == {
        "repo_corpus_commitment": json.loads(synthetic.repo_artifact)["corpus_commitment"],
        "transcript_corpus_commitment": json.loads(synthetic.transcript_artifact)[
            "corpus_commitment"
        ],
    }
    assert artifact["events"] == [
        {
            "schema_version": "1",
            "kind": "normalized-reference-target-event",
            "source": "cross-stream",
            "session_id": json.loads(synthetic.transcript_artifact)["corpus_commitment"],
            "record_index": 0,
            "subevent_index": 0,
            "reference_pointer": {
                "field": "tool-input",
                "block_index": synthetic.joins[0].reference_block_index,
                "record_commitment": synthetic.joins[0].reference_record_commitment,
            },
            "target_commitment": {
                "algorithm": "git-sha1",
                "digest": "66" * 20,
            },
        }
    ]
    assert all(
        forbidden.encode() not in data
        for forbidden in ("filename", "file_path", "path", "content", "publication")
    )
    assert not any(canary in data for canary in synthetic.canaries)
    stored = store_corpus_artifact(data)
    assert stored == paths.normalized_corpus_path(commitment)
    assert stored.read_bytes() == data


def test_join_rejects_unadmitted_reference_and_target_commitments():
    synthetic = synthetic_reference_target_input()
    with pytest.raises(NormalizationError, match="no admitted reference"):
        normalize_reference_target_joins(
            synthetic.transcript_artifact,
            synthetic.repo_artifact,
            (replace(synthetic.joins[0], reference_record_commitment="aa" * 32),),
        )
    with pytest.raises(NormalizationError, match="no admitted repo target"):
        normalize_reference_target_joins(
            synthetic.transcript_artifact,
            synthetic.repo_artifact,
            (replace(synthetic.joins[0], target_digest="aa" * 20),),
        )


@pytest.mark.parametrize("field", ["filename", "path", "content", "publication"])
def test_join_schema_rejects_smuggled_fields(field):
    synthetic = synthetic_reference_target_input()
    artifact = json.loads(
        normalize_reference_target_joins(
            synthetic.transcript_artifact,
            synthetic.repo_artifact,
            synthetic.joins,
        )
    )
    artifact["events"][0][field] = "synthetic-forbidden-value"
    with pytest.raises(ValidationError):
        load_validator("reference_target_join.schema.json").validate(artifact)
    tampered = canonical_bytes(artifact) + b"\n"
    with pytest.raises(NormalizationError) as exc:
        validate_reference_target_corpus_artifact(tampered)
    assert "synthetic-forbidden-value" not in str(exc.value)


def test_fixed_reference_target_root_locks_shared_merkle_contract():
    synthetic = synthetic_reference_target_input()
    artifact = json.loads(
        normalize_reference_target_joins(
            synthetic.transcript_artifact,
            synthetic.repo_artifact,
            synthetic.joins,
        )
    )
    assert artifact["corpus_commitment"] == (
        "333a16a25c0bba6d83a2ead2e982c2de05b71eae86165e0d4704bd626ac3b3e2"
    )
