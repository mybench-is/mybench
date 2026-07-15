"""Fixed synthetic Claude records for normalizer and determinism tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from mybench.commitments import leaf_commitment, session_root
from mybench.normalizer.claude import VerifiedRecord, VerifiedSession

CONTENT_CANARY = "MYBENCH-NORMALIZER-CONTENT-CANARY-7d2b"
AGENT_CANARY = "MYBENCH-NORMALIZER-AGENT-CANARY-f104"
RESULT_CANARY = "MYBENCH-NORMALIZER-RESULT-CANARY-a191"
PASTE_CANARY = "MYBENCH-NORMALIZER-PASTE-CANARY-c055"
NON_SUBJECT_CANARY = "MYBENCH-NORMALIZER-NON-SUBJECT-CANARY-08ee"
UNKNOWN_CANARY = "MYBENCH-NORMALIZER-UNKNOWN-CANARY-d276"
FILENAME_CANARY = "synthetic_private_plan_31ef.py"
PATH_CANARY = "/synthetic/private/project/synthetic_private_plan_31ef.py"
RAW_SESSION_CANARY = "raw-session-identifier-canary-a"
SIDECHAIN_RAW_SESSION_CANARY = "raw-session-identifier-canary-b"
NON_SUBJECT_RAW_SESSION_CANARY = "raw-session-identifier-canary-c"
TOOL_ID_CANARY = "tool-use-identifier-canary-77cc"
UUID_CANARIES = tuple(f"raw-uuid-canary-{index:02d}" for index in range(12))


@dataclass(frozen=True)
class SyntheticNormalizedInput:
    sessions: tuple[VerifiedSession, ...]
    canaries: tuple[bytes, ...]
    nonces: tuple[bytes, ...]


def _raw(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _nonce(session_index: int, record_index: int) -> bytes:
    return hashlib.sha256(
        f"synthetic-normalizer-nonce:{session_index}:{record_index}".encode()
    ).digest()


def _session(
    *,
    session_index: int,
    session_id: str,
    values: list[dict | bytes],
    attributions: list[str],
    subject_owned: bool,
    parent_session_id: str | None = None,
    generations: dict[int, int] | None = None,
) -> tuple[VerifiedSession, list[bytes]]:
    generations = generations or {}
    raws = [value if isinstance(value, bytes) else _raw(value) for value in values]
    nonces = [_nonce(session_index, index) for index in range(len(raws))]
    commitments = [leaf_commitment(nonce, raw) for nonce, raw in zip(nonces, raws)]
    records = tuple(
        VerifiedRecord(
            index=index,
            raw_bytes=raw,
            record_commitment=commitments[index].hex(),
            attribution=attributions[index],
            context_generation_id=generations.get(index),
        )
        for index, raw in enumerate(raws)
    )
    return (
        VerifiedSession(
            source="claude-code",
            session_id=session_id,
            session_root=session_root(commitments).hex(),
            records=records,
            subject_owned=subject_owned,
            parent_session_id=parent_session_id,
        ),
        nonces,
    )


def synthetic_normalizer_input() -> SyntheticNormalizedInput:
    """Return a fixed corpus containing only conspicuously synthetic bytes."""
    main_values: list[dict | bytes] = [
        {
            "cwd": PATH_CANARY,
            "isSidechain": False,
            "message": {"role": "user", "content": CONTENT_CANARY},
            "parentUuid": None,
            "sessionId": RAW_SESSION_CANARY,
            "timestamp": "2026-01-01T00:00:00.000Z",
            "type": "user",
            "uuid": UUID_CANARIES[0],
        },
        {
            "cwd": PATH_CANARY,
            "isSidechain": False,
            "message": {
                "role": "assistant",
                "model": "synthetic-model-v1",
                "provider": "synthetic",
                "effort": "high",
                "usage": {"input_tokens": 0, "output_tokens": 7},
                "content": [
                    {"type": "text", "text": AGENT_CANARY},
                    {
                        "type": "tool_use",
                        "id": TOOL_ID_CANARY,
                        "name": "Read",
                        "input": {"file_path": PATH_CANARY, "content": CONTENT_CANARY},
                    },
                ],
            },
            "parentUuid": UUID_CANARIES[0],
            "sessionId": RAW_SESSION_CANARY,
            "timestamp": "2026-01-01T00:00:01.000Z",
            "type": "assistant",
            "uuid": UUID_CANARIES[1],
        },
        {
            "cwd": PATH_CANARY,
            "isSidechain": False,
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": TOOL_ID_CANARY,
                        "content": RESULT_CANARY + " " + PATH_CANARY,
                        "is_error": False,
                    },
                    {"type": "text", "text": "synthetic follow-up " + CONTENT_CANARY},
                ],
            },
            "parentUuid": UUID_CANARIES[1],
            "sessionId": RAW_SESSION_CANARY,
            "timestamp": "2026-01-01T00:00:02.000Z",
            "type": "user",
            "uuid": UUID_CANARIES[2],
        },
        {
            "cwd": PATH_CANARY,
            "isSidechain": False,
            "message": {
                "role": "user",
                "content": f"```synthetic\n{PASTE_CANARY}\n{FILENAME_CANARY}\n```",
            },
            "parentUuid": UUID_CANARIES[2],
            "sessionId": RAW_SESSION_CANARY,
            "timestamp": "2026-01-01T00:00:03.000Z",
            "type": "user",
            "uuid": UUID_CANARIES[3],
        },
        {
            "cwd": PATH_CANARY,
            "isSidechain": False,
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "final " + AGENT_CANARY}],
            },
            "parentUuid": UUID_CANARIES[3],
            "sessionId": RAW_SESSION_CANARY,
            "timestamp": "2026-01-01T00:00:04.000Z",
            "type": "assistant",
            "uuid": UUID_CANARIES[4],
        },
        {
            "cwd": PATH_CANARY,
            "parentUuid": UUID_CANARIES[4],
            "sessionId": RAW_SESSION_CANARY,
            "subtype": "compact_boundary",
            "timestamp": "2026-01-01T00:00:05.000Z",
            "type": "system",
            "uuid": UUID_CANARIES[5],
        },
        {
            "message": {"role": "user", "content": NON_SUBJECT_CANARY},
            "sessionId": "raw-non-subject-record-canary",
            "type": "user",
        },
        {
            "message": {"role": "user", "content": UNKNOWN_CANARY},
            "sessionId": "raw-unknown-record-canary",
            "type": "user",
        },
        b'{"synthetic-malformed":',
        {
            "payload": CONTENT_CANARY,
            "sessionId": RAW_SESSION_CANARY,
            "type": "future_record_shape",
        },
    ]
    main, main_nonces = _session(
        session_index=0,
        session_id="opaque-main-session",
        values=main_values,
        attributions=[
            "subject",
            "subject",
            "subject",
            "subject",
            "subject",
            "subject",
            "non-subject",
            "unknown",
            "subject",
            "subject",
        ],
        subject_owned=True,
        generations={5: 1},
    )

    side_values = [
        {
            "cwd": PATH_CANARY,
            "isSidechain": True,
            "message": {"role": "user", "content": "delegated " + CONTENT_CANARY},
            "parentUuid": None,
            "sessionId": SIDECHAIN_RAW_SESSION_CANARY,
            "timestamp": "2026-01-01T00:01:00.000Z",
            "type": "user",
            "uuid": UUID_CANARIES[6],
        },
        {
            "cwd": PATH_CANARY,
            "isSidechain": True,
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "delegated " + AGENT_CANARY}],
            },
            "parentUuid": UUID_CANARIES[6],
            "sessionId": SIDECHAIN_RAW_SESSION_CANARY,
            "timestamp": "2026-01-01T00:01:01.000Z",
            "type": "assistant",
            "uuid": UUID_CANARIES[7],
        },
    ]
    sidechain, side_nonces = _session(
        session_index=1,
        session_id="opaque-sidechain-session",
        values=side_values,
        attributions=["subject", "subject"],
        subject_owned=True,
        parent_session_id="opaque-main-session",
    )

    non_subject_values = [
        {
            "cwd": PATH_CANARY,
            "isSidechain": False,
            "message": {"role": "user", "content": NON_SUBJECT_CANARY},
            "parentUuid": None,
            "sessionId": NON_SUBJECT_RAW_SESSION_CANARY,
            "timestamp": "2026-01-01T00:02:00.000Z",
            "type": "user",
            "uuid": UUID_CANARIES[8],
        }
    ]
    non_subject, non_subject_nonces = _session(
        session_index=2,
        session_id="opaque-non-subject-session",
        values=non_subject_values,
        attributions=["non-subject"],
        subject_owned=False,
    )

    nonces = tuple(main_nonces + side_nonces + non_subject_nonces)
    string_canaries = (
        CONTENT_CANARY,
        AGENT_CANARY,
        RESULT_CANARY,
        PASTE_CANARY,
        NON_SUBJECT_CANARY,
        UNKNOWN_CANARY,
        FILENAME_CANARY,
        PATH_CANARY,
        RAW_SESSION_CANARY,
        SIDECHAIN_RAW_SESSION_CANARY,
        NON_SUBJECT_RAW_SESSION_CANARY,
        TOOL_ID_CANARY,
        *UUID_CANARIES,
    )
    return SyntheticNormalizedInput(
        sessions=(main, sidechain, non_subject),
        canaries=tuple(value.encode() for value in string_canaries) + nonces,
        nonces=nonces,
    )
