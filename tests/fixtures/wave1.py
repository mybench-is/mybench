"""Synthetic-by-construction 20-session corpus for Wave-1 scorer tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from mybench.commitments import leaf_commitment, session_root
from mybench.normalizer.claude import (
    VerifiedRecord,
    VerifiedSession,
    normalize_claude,
)
from mybench.normalizer.contract import event_leaf_hash
from mybench.scorer.wave1 import (
    build_harness_currency_snapshot,
    build_mcp_category_observations,
    build_mcp_recurrence_snapshot,
)

WAVE1_CONTENT_CANARY = "MYBENCH-WAVE1-CONTENT-CANARY-79f1"
WAVE1_PATH_CANARY = "/synthetic/private/WAVE1-FILENAME-CANARY-843a.py"
WAVE1_RESULT_CANARY = "MYBENCH-WAVE1-RESULT-CANARY-61dd"
WAVE1_TOOL_ID_CANARY = "MYBENCH-WAVE1-TOOL-ID-CANARY-9c2e"
WAVE1_RAW_SESSION_CANARY = "MYBENCH-WAVE1-RAW-SESSION-CANARY-52b7"
WAVE1_CANARIES = tuple(
    value.encode()
    for value in (
        WAVE1_CONTENT_CANARY,
        WAVE1_PATH_CANARY,
        WAVE1_RESULT_CANARY,
        WAVE1_TOOL_ID_CANARY,
        WAVE1_RAW_SESSION_CANARY,
    )
)


@dataclass(frozen=True)
class Wave1SyntheticInput:
    corpus: dict
    currency_snapshot: dict
    mcp_observations: dict
    mcp_snapshot: dict
    canaries: tuple[bytes, ...]


def _raw(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _session(index: int) -> VerifiedSession:
    raw_session = f"{WAVE1_RAW_SESSION_CANARY}-{index:02d}"
    uuids = [f"synthetic-wave1-uuid-{index:02d}-{record}" for record in range(5)]
    tool_specs = [
        ("Read", {"file_path": WAVE1_PATH_CANARY}),
        (
            "Edit",
            {
                "file_path": WAVE1_PATH_CANARY,
                "old_string": WAVE1_CONTENT_CANARY,
                "new_string": "synthetic replacement",
            },
        ),
        ("Bash", {"command": f"pytest -q {WAVE1_PATH_CANARY}"}),
        ("WebSearch", {"query": WAVE1_CONTENT_CANARY}),
        ("mcp__synthetic_vcs", {"value": WAVE1_CONTENT_CANARY}),
        ("mcp__synthetic_database", {"value": WAVE1_CONTENT_CANARY}),
        ("mcp__synthetic_browser", {"value": WAVE1_CONTENT_CANARY}),
    ]
    if index == 0:
        tool_specs.append(("mcp__synthetic_one_off", {"value": WAVE1_CONTENT_CANARY}))
    tool_ids = [f"{WAVE1_TOOL_ID_CANARY}-{index:02d}-{number}" for number in range(len(tool_specs))]
    assistant_blocks = [{"type": "text", "text": WAVE1_CONTENT_CANARY}]
    assistant_blocks.extend(
        {
            "type": "tool_use",
            "id": tool_id,
            "name": name,
            "input": tool_input,
        }
        for tool_id, (name, tool_input) in zip(tool_ids, tool_specs)
    )
    result_blocks = [
        {
            "type": "tool_result",
            "tool_use_id": tool_id,
            "content": f"{WAVE1_RESULT_CANARY}-{number}",
            "is_error": False,
        }
        for number, tool_id in enumerate(tool_ids)
    ]
    values = [
        {
            "type": "user",
            "isSidechain": False,
            "sessionId": raw_session,
            "uuid": uuids[0],
            "parentUuid": None,
            "timestamp": f"2026-01-01T00:{index:02d}:00.000Z",
            "message": {"role": "user", "content": WAVE1_CONTENT_CANARY},
        },
        {
            "type": "assistant",
            "isSidechain": False,
            "sessionId": raw_session,
            "uuid": uuids[1],
            "parentUuid": uuids[0],
            "timestamp": f"2026-01-01T00:{index:02d}:01.000Z",
            "message": {"role": "assistant", "content": assistant_blocks},
        },
        {
            "type": "user",
            "isSidechain": False,
            "sessionId": raw_session,
            "uuid": uuids[2],
            "parentUuid": uuids[1],
            "timestamp": f"2026-01-01T00:{index:02d}:02.000Z",
            "message": {"role": "user", "content": result_blocks},
        },
        {
            "type": "user",
            "isSidechain": False,
            "sessionId": raw_session,
            "uuid": uuids[3],
            "parentUuid": uuids[2],
            "timestamp": f"2026-01-01T00:{index:02d}:03.000Z",
            "message": {"role": "user", "content": "synthetic follow-up"},
        },
        {
            "type": "assistant",
            "isSidechain": False,
            "sessionId": raw_session,
            "uuid": uuids[4],
            "parentUuid": uuids[3],
            "timestamp": f"2026-01-01T00:{index:02d}:04.000Z",
            "message": {"role": "assistant", "content": "synthetic done"},
        },
    ]
    raws = [_raw(value) for value in values]
    nonces = [
        hashlib.sha256(f"wave1-fixture:{index}:{record}".encode()).digest()
        for record in range(len(raws))
    ]
    commitments = [leaf_commitment(nonce, raw) for nonce, raw in zip(nonces, raws)]
    records = tuple(
        VerifiedRecord(record, raw, commitment.hex(), "subject")
        for record, (raw, commitment) in enumerate(zip(raws, commitments))
    )
    return VerifiedSession(
        source="claude-code",
        session_id=f"synthetic-wave1-session-{index:02d}",
        session_root=session_root(commitments).hex(),
        records=records,
        subject_owned=True,
    )


def wave1_synthetic_input(*, session_count: int = 20) -> Wave1SyntheticInput:
    sessions = tuple(_session(index) for index in range(session_count))
    corpus = json.loads(normalize_claude(sessions))
    currency = build_harness_currency_snapshot(
        {"claude-code": "5.1.0"}, snapshot_version="2026.7.0"
    )
    observation_rows = []
    by_session = {}
    for event in corpus["events"]:
        if event["event_kind"] == "tool-call" and event["tool_family"] == "mcp":
            by_session.setdefault((event["source"], event["session_id"]), []).append(event)
    for session_key, events in sorted(by_session.items()):
        categories = ["vcs", "database", "browser"]
        if session_key[1] == "synthetic-wave1-session-00":
            categories.append("other")
        assert len(events) == len(categories)
        observation_rows.extend(
            {"event_commitment": event_leaf_hash(event).hex(), "category": category}
            for event, category in zip(events, categories)
        )
    mcp_observations = build_mcp_category_observations(
        corpus["corpus_commitment"],
        observation_rows,
    )
    mcp_snapshot = build_mcp_recurrence_snapshot(corpus, mcp_observations)
    return Wave1SyntheticInput(corpus, currency, mcp_observations, mcp_snapshot, WAVE1_CANARIES)


__all__ = ["WAVE1_CANARIES", "Wave1SyntheticInput", "wave1_synthetic_input"]
