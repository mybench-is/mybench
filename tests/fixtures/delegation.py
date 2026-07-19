"""Deterministic nested-subagent corpus for MYB-6.8 scorer tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from mybench.commitments import leaf_commitment, session_root
from mybench.normalizer.claude import VerifiedRecord, VerifiedSession, normalize_claude

DELEGATION_CONTENT_CANARY = "MYBENCH-DELEGATION-CONTENT-CANARY-6e8a"
DELEGATION_FILENAME_CANARY = "synthetic_private_delegation_plan_6e8a.md"
DELEGATION_PATH_CANARY = "/synthetic/private/delegation/synthetic_private_plan_6e8a.md"


@dataclass(frozen=True)
class SyntheticDelegationInput:
    corpus: dict
    canaries: tuple[bytes, ...]


def _raw(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _session(
    session_id: str,
    *,
    start: str | None,
    end: str | None,
    parent_session_id: str | None = None,
    subagent: bool = False,
    contradictory_lane: bool = False,
) -> tuple[VerifiedSession, tuple[bytes, ...], tuple[bytes, ...]]:
    raw_id = f"raw-{session_id}-canary"
    lane_markers = (subagent, not subagent) if contradictory_lane else (subagent, subagent)
    values = [
        {
            "cwd": DELEGATION_PATH_CANARY,
            "isSidechain": lane_markers[0],
            "message": {
                "role": "user",
                "content": f"synthetic nested request {DELEGATION_CONTENT_CANARY}",
            },
            "parentUuid": None,
            "sessionId": raw_id,
            "type": "user",
            "uuid": f"uuid-{session_id}-0",
            **({"timestamp": start} if start is not None else {}),
        },
        {
            "cwd": DELEGATION_PATH_CANARY,
            "isSidechain": lane_markers[1],
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"synthetic nested response {DELEGATION_CONTENT_CANARY} "
                            f"{DELEGATION_FILENAME_CANARY}"
                        ),
                    }
                ],
            },
            "parentUuid": f"uuid-{session_id}-0",
            "sessionId": raw_id,
            "type": "assistant",
            "uuid": f"uuid-{session_id}-1",
            **({"timestamp": end} if end is not None else {}),
        },
    ]
    raw_bytes = tuple(_raw(value) for value in values)
    nonces = tuple(
        hashlib.sha256(f"synthetic-delegation-nonce:{session_id}:{index}".encode()).digest()
        for index in range(2)
    )
    commitments = tuple(
        leaf_commitment(nonce, raw) for nonce, raw in zip(nonces, raw_bytes, strict=True)
    )
    records = tuple(
        VerifiedRecord(
            index=index,
            raw_bytes=raw,
            record_commitment=commitments[index].hex(),
            attribution="subject",
        )
        for index, raw in enumerate(raw_bytes)
    )
    session = VerifiedSession(
        source="claude-code",
        session_id=session_id,
        session_root=session_root(commitments).hex(),
        records=records,
        subject_owned=True,
        parent_session_id=parent_session_id,
        started_at=(start.replace(".000Z", ".000000Z") if start is not None else None),
    )
    identifiers = (session_id.encode(), raw_id.encode())
    return session, nonces, identifiers


def synthetic_delegation_input(
    *,
    include_unknown_lane: bool = False,
    include_untimed_root: bool = False,
    below_peak_support: bool = False,
) -> SyntheticDelegationInput:
    """Build three rooted graphs, including nested and overlapping subagents."""

    specs = [
        ("synthetic-root-a", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:10.000Z", None, False),
        (
            "synthetic-child-a1",
            "2026-01-01T00:00:01.000Z",
            "2026-01-01T00:00:08.000Z",
            "synthetic-root-a",
            True,
        ),
        (
            "synthetic-child-a2",
            "2026-01-01T00:00:02.000Z",
            "2026-01-01T00:00:09.000Z",
            "synthetic-root-a",
            True,
        ),
        (
            "synthetic-grandchild-a",
            "2026-01-01T00:00:03.000Z",
            "2026-01-01T00:00:07.000Z",
            "synthetic-child-a1",
            True,
        ),
        ("synthetic-root-b", "2026-01-01T01:00:00.000Z", "2026-01-01T01:00:10.000Z", None, False),
        (
            "synthetic-child-b1",
            "2026-01-01T01:00:01.000Z",
            "2026-01-01T01:00:05.000Z",
            "synthetic-root-b",
            True,
        ),
        ("synthetic-root-c", "2026-01-01T02:00:00.000Z", "2026-01-01T02:00:10.000Z", None, False),
    ]
    if below_peak_support:
        specs = specs[:4]
    sessions = []
    canaries: list[bytes] = [
        DELEGATION_CONTENT_CANARY.encode(),
        DELEGATION_FILENAME_CANARY.encode(),
        DELEGATION_PATH_CANARY.encode(),
    ]
    for session_id, start, end, parent_id, subagent in specs:
        session, nonces, identifiers = _session(
            session_id,
            start=start,
            end=end,
            parent_session_id=parent_id,
            subagent=subagent,
        )
        sessions.append(session)
        canaries.extend((*nonces, *identifiers))

    if include_unknown_lane:
        session, nonces, identifiers = _session(
            "synthetic-unknown-lane",
            start="2026-01-01T03:00:00.000Z",
            end="2026-01-01T03:00:10.000Z",
            contradictory_lane=True,
        )
        sessions.append(session)
        canaries.extend((*nonces, *identifiers))

    if include_untimed_root:
        session, nonces, identifiers = _session(
            "synthetic-untimed-root",
            start=None,
            end=None,
        )
        sessions.append(session)
        canaries.extend((*nonces, *identifiers))

    corpus = json.loads(normalize_claude(tuple(sessions)))
    return SyntheticDelegationInput(corpus=corpus, canaries=tuple(canaries))


__all__ = [
    "DELEGATION_CONTENT_CANARY",
    "DELEGATION_FILENAME_CANARY",
    "DELEGATION_PATH_CANARY",
    "SyntheticDelegationInput",
    "synthetic_delegation_input",
]
