"""Owner-approved normalized-corpus Merkle domains and golden vector."""

from __future__ import annotations

import hashlib
import json

import pytest

from mybench.commitment_tree import leaf_commitment, merkle_root, session_root
from mybench.normalizer.claude import VerifiedRecord, VerifiedSession, normalize_claude
from mybench.normalizer.contract import (
    DOMAIN_NORMALIZED_CORPUS,
    NormalizationError,
    corpus_commitment,
    event_leaf_hash,
    manifest_leaf_hash,
    validate_corpus_artifact,
)
from mybench.schemas import load_validator


def vector_records():
    episode_id = "ep-" + "22" * 16
    manifest = {
        "adapters": [{"source": "claude-code", "version": "1.0.0"}],
        "coverage": {
            "records_malformed": 0,
            "records_parsed": 2,
            "records_seen": 2,
            "records_unsupported": 0,
        },
        "event_count": 2,
        "kind": "normalized-corpus",
        "normalizer": {
            "authorship_policy_version": "1.0.0",
            "episode_stitcher_version": "1.0.0",
            "name": "mybench.normalizer",
            "version": "1.0.0",
        },
        "schema_version": "1",
        "sessions": [
            {
                "item_count": 2,
                "session_id": "synthetic-session-0001",
                "session_root": "11" * 32,
                "source": "claude-code",
                "task_episode_id": episode_id,
            }
        ],
    }
    event_1 = {
        "authorship": "human-turn",
        "event_kind": "turn",
        "kind": "normalized-event",
        "pointer": {
            "end": 5,
            "field": "message-text",
            "record_commitment": "33" * 32,
            "start": 0,
            "unit": "unicode-scalar",
        },
        "record_index": 0,
        "schema_version": "1",
        "session_id": "synthetic-session-0001",
        "source": "claude-code",
        "subevent_index": 0,
        "task_episode_id": episode_id,
    }
    event_2 = {
        "authorship": "agent-turn",
        "event_kind": "turn",
        "kind": "normalized-event",
        "pointer": {
            "block_index": 0,
            "end": 7,
            "field": "content-block-text",
            "record_commitment": "44" * 32,
            "start": 0,
            "unit": "unicode-scalar",
        },
        "record_index": 1,
        "schema_version": "1",
        "session_id": "synthetic-session-0001",
        "source": "claude-code",
        "subevent_index": 0,
        "task_episode_id": episode_id,
    }
    return manifest, event_1, event_2


def test_fixed_three_leaf_vector_locks_domains_framing_and_odd_tree_rule():
    manifest, event_1, event_2 = vector_records()
    leaves = [manifest_leaf_hash(manifest), event_leaf_hash(event_1), event_leaf_hash(event_2)]
    assert [leaf.hex() for leaf in leaves] == [
        "f8394b691d9fd434574aec8b09855fcdfe55f978f88246d5cb3baf9da7dc00c3",
        "1a15c5eadc28433f383e334ad8e3b56296a78bb64678c5126741bee61fa54257",
        "6485d2dbfd65fe23803c9112fe00491dc15253038cb846a438db22d01d7ab5b4",
    ]
    tree_root = merkle_root(leaves)
    assert tree_root.hex() == "0854ccba296f7c305220c42a2d0fde7c770a0df8e7660864dd2b7a7c927a213d"
    assert hashlib.sha256(DOMAIN_NORMALIZED_CORPUS + tree_root).hexdigest() == (
        "6177ce6ac5043aa5627a2f274930d38a4c28e4d471c4189807a221dc2509c15d"
    )
    assert corpus_commitment(manifest, [event_2, event_1]) == (
        "6177ce6ac5043aa5627a2f274930d38a4c28e4d471c4189807a221dc2509c15d"
    )


def test_duplicate_event_order_key_is_rejected_not_deduplicated():
    manifest, event, _ = vector_records()
    duplicate = dict(event)
    duplicate["authorship"] = "agent-turn"
    with pytest.raises(NormalizationError, match="duplicate normalized event"):
        corpus_commitment(manifest, [event, duplicate])


def test_fixed_production_artifact_locks_schema_and_root_together():
    raw = (
        b'{"isSidechain":false,"message":{"content":"synthetic production golden",'
        b'"role":"user"},"parentUuid":null,"type":"user",'
        b'"uuid":"synthetic-golden-record"}'
    )
    nonce = bytes.fromhex("6a" * 32)
    commitment = leaf_commitment(nonce, raw)
    session = VerifiedSession(
        source="claude-code",
        session_id="synthetic-golden-session",
        session_root=session_root([commitment]).hex(),
        records=(VerifiedRecord(0, raw, commitment.hex(), "subject"),),
        subject_owned=True,
    )
    data = normalize_claude((session,))
    artifact = json.loads(data)
    assert artifact["corpus_commitment"] == (
        "067bfb0baaf02044c28bde0171d96606a13fdb25cd0f92dd66ccdd8053cf2853"
    )
    load_validator("normalized_corpus.schema.json").validate(artifact)
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]
