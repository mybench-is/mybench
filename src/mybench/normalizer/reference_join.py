"""Pure commitment-only transcript-reference to repository-target joins.

The trusted integration boundary may inspect a referenced filename long enough
to resolve it to an admitted Git blob.  This module receives only the resulting
transcript pointer coordinates and Git object commitment.  It verifies both
against normalized A8 inputs and emits a third, local-only A8 artifact; no path,
filename, transcript bytes, or repository bytes enter the join corpus.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from mybench.claims.canonical import CanonicalError, canonical_bytes
from mybench.normalizer.contract import (
    NoEvidence,
    NormalizationError,
    corpus_commitment,
    validate_corpus_artifact,
)
from mybench.normalizer.repo import validate_repo_corpus_artifact

SCHEMA_VERSION = "1"
REFERENCE_JOIN_NORMALIZER_VERSION = "1.0.0"

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TARGET_ALGORITHMS = frozenset({"git-sha1", "git-sha256"})


@dataclass(frozen=True)
class ReferenceTargetJoin:
    """One filename-free edge from a transcript invocation to a Git blob."""

    reference_record_commitment: str
    reference_block_index: int
    target_algorithm: str
    target_digest: str


def _safe_error(message: str) -> NormalizationError:
    return NormalizationError(message)


def _is_uint(value: object) -> bool:
    return type(value) is int and value >= 0


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _valid_target(algorithm: object, digest: object) -> bool:
    if algorithm not in _TARGET_ALGORITHMS or not isinstance(digest, str):
        return False
    pattern = _HEX40 if algorithm == "git-sha1" else _HEX64
    return pattern.fullmatch(digest) is not None


def _reference_key(pointer: Mapping) -> tuple[str, int] | None:
    if (
        set(pointer) != {"field", "block_index", "record_commitment"}
        or pointer.get("field") != "tool-input"
        or not _is_uint(pointer.get("block_index"))
        or not _is_hex64(pointer.get("record_commitment"))
    ):
        return None
    return pointer["record_commitment"], pointer["block_index"]


def _target_key(commitment: Mapping) -> tuple[str, str] | None:
    if set(commitment) != {"algorithm", "digest"} or not _valid_target(
        commitment.get("algorithm"), commitment.get("digest")
    ):
        return None
    return commitment["algorithm"], commitment["digest"]


def _source_indexes(
    transcript_artifact: bytes, repo_artifact: bytes
) -> tuple[str, str, set[tuple[str, int]], dict[tuple[str, str], set[str]]]:
    transcript_root = validate_corpus_artifact(transcript_artifact)
    repo_root = validate_repo_corpus_artifact(repo_artifact)
    transcript = json.loads(transcript_artifact)
    repo = json.loads(repo_artifact)
    references = {
        key
        for event in transcript["events"]
        if event["event_kind"] == "reference"
        and (key := _reference_key(event["pointer"])) is not None
    }
    targets: dict[tuple[str, str], set[str]] = {}
    for event in repo["events"]:
        if event["event_kind"] != "commit" or event["structure_status"] != "observed":
            continue
        for target in event["targets"]:
            key = _target_key(target["pointer"]["target_commitment"])
            if key is not None:
                targets.setdefault(key, set()).add(target["file_class"])
    return transcript_root, repo_root, references, targets


def normalize_reference_target_joins(
    transcript_artifact: bytes,
    repo_artifact: bytes,
    joins: Sequence[ReferenceTargetJoin],
) -> bytes:
    """Return canonical local A8 joins between two normalized corpora.

    ``joins`` is deliberately incapable of carrying a filename.  A caller at
    the trusted filesystem boundary resolves names transiently, then supplies
    only the committed invocation coordinates and verified Git blob digest.
    """
    if isinstance(joins, (str, bytes)) or not isinstance(joins, Sequence):
        raise _safe_error("reference-target joins must be a sequence")
    if not joins:
        raise NoEvidence("no verified reference-target joins exist")
    transcript_root, repo_root, references, targets = _source_indexes(
        transcript_artifact, repo_artifact
    )
    checked = []
    for join in joins:
        if type(join) is not ReferenceTargetJoin:
            raise _safe_error("reference-target join input is invalid")
        reference_key = (
            join.reference_record_commitment,
            join.reference_block_index,
        )
        target_key = (join.target_algorithm, join.target_digest)
        if (
            not _is_hex64(join.reference_record_commitment)
            or not _is_uint(join.reference_block_index)
            or not _valid_target(*target_key)
        ):
            raise _safe_error("reference-target join input is invalid")
        if reference_key not in references:
            raise _safe_error("reference-target join has no admitted reference")
        target_classes = targets.get(target_key)
        if target_classes is None:
            raise _safe_error("reference-target join has no admitted repo target")
        if len(target_classes) != 1:
            raise _safe_error("reference-target join has an ambiguous repo target")
        checked.append((reference_key, target_key))
    checked.sort()
    if len(checked) != len(set(checked)) or len({reference for reference, _ in checked}) != len(
        checked
    ):
        raise _safe_error("reference-target joins are duplicate or ambiguous")

    events = [
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "normalized-reference-target-event",
            "source": "cross-stream",
            "session_id": transcript_root,
            "record_index": record_index,
            "subevent_index": 0,
            "reference_pointer": {
                "field": "tool-input",
                "block_index": reference[1],
                "record_commitment": reference[0],
            },
            "target_commitment": {
                "algorithm": target[0],
                "digest": target[1],
            },
        }
        for record_index, (reference, target) in enumerate(checked)
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "normalized-reference-target-manifest",
        "normalizer": {
            "name": "mybench.normalizer.reference_join",
            "version": REFERENCE_JOIN_NORMALIZER_VERSION,
        },
        "inputs": {
            "transcript_corpus_commitment": transcript_root,
            "repo_corpus_commitment": repo_root,
        },
        "event_count": len(events),
    }
    root = corpus_commitment(manifest, events)
    artifact = {
        "schema_version": SCHEMA_VERSION,
        "kind": "normalized-reference-target-corpus-artifact",
        "corpus_commitment": root,
        "manifest": manifest,
        "events": events,
    }
    return canonical_bytes(artifact) + b"\n"


def _exact_keys(value: object, required: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == required


def _event_key(event: Mapping) -> tuple[str, int, str, str]:
    pointer = event["reference_pointer"]
    target = event["target_commitment"]
    return (
        pointer["record_commitment"],
        pointer["block_index"],
        target["algorithm"],
        target["digest"],
    )


def _validate_artifact_semantics(artifact: dict) -> None:
    manifest = artifact["manifest"]
    if not _exact_keys(
        manifest,
        {"schema_version", "kind", "normalizer", "inputs", "event_count"},
    ):
        raise _safe_error("normalized reference-target manifest has invalid fields")
    if (
        manifest["schema_version"] != SCHEMA_VERSION
        or manifest["kind"] != "normalized-reference-target-manifest"
        or manifest["normalizer"]
        != {
            "name": "mybench.normalizer.reference_join",
            "version": REFERENCE_JOIN_NORMALIZER_VERSION,
        }
        or not _exact_keys(
            manifest["inputs"],
            {"transcript_corpus_commitment", "repo_corpus_commitment"},
        )
        or not all(_is_hex64(value) for value in manifest["inputs"].values())
        or not _is_uint(manifest["event_count"])
    ):
        raise _safe_error("normalized reference-target manifest is invalid")
    events = artifact["events"]
    if manifest["event_count"] != len(events) or not events:
        raise _safe_error("normalized reference-target event count is invalid")
    keys = []
    references = set()
    for event in events:
        if not _exact_keys(
            event,
            {
                "schema_version",
                "kind",
                "source",
                "session_id",
                "record_index",
                "subevent_index",
                "reference_pointer",
                "target_commitment",
            },
        ) or (
            event["schema_version"] != SCHEMA_VERSION
            or event["kind"] != "normalized-reference-target-event"
            or event["source"] != "cross-stream"
            or event["session_id"]
            != manifest["inputs"]["transcript_corpus_commitment"]
            or event["record_index"] != len(keys)
            or event["subevent_index"] != 0
        ):
            raise _safe_error("normalized reference-target event has invalid fields")
        if not isinstance(event["reference_pointer"], dict) or not isinstance(
            event["target_commitment"], dict
        ):
            raise _safe_error("normalized reference-target event is invalid")
        reference = _reference_key(event["reference_pointer"])
        target = _target_key(event["target_commitment"])
        if reference is None or target is None or reference in references:
            raise _safe_error("normalized reference-target event is invalid")
        references.add(reference)
        keys.append(_event_key(event))
    if keys != sorted(set(keys)):
        raise _safe_error("normalized reference-target events are not sorted and unique")


def validate_reference_target_corpus_artifact(data: bytes) -> str:
    """Validate canonical join shape and Merkle binding; return its address."""
    if type(data) is not bytes or not data.endswith(b"\n"):
        raise _safe_error("normalized reference-target corpus must be canonical JSON")
    try:
        artifact = json.loads(data[:-1].decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _safe_error("normalized reference-target corpus is invalid JSON") from None
    if not isinstance(artifact, dict):
        raise _safe_error("normalized reference-target corpus must be an object")
    try:
        if canonical_bytes(artifact) + b"\n" != data:
            raise _safe_error("normalized reference-target corpus is not canonical")
    except (CanonicalError, ValueError, RecursionError):
        raise _safe_error("normalized reference-target corpus is not canonical") from None
    if not _exact_keys(
        artifact,
        {"schema_version", "kind", "corpus_commitment", "manifest", "events"},
    ) or (
        artifact.get("schema_version") != SCHEMA_VERSION
        or artifact.get("kind") != "normalized-reference-target-corpus-artifact"
        or not _is_hex64(artifact.get("corpus_commitment"))
        or not isinstance(artifact.get("events"), list)
    ):
        raise _safe_error("normalized reference-target corpus has invalid fields")
    _validate_artifact_semantics(artifact)
    expected = corpus_commitment(artifact["manifest"], artifact["events"])
    if artifact["corpus_commitment"] != expected:
        raise _safe_error("normalized reference-target corpus commitment is invalid")
    return expected
