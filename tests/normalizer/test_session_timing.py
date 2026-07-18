"""MYB-19.10: private timing normalization and Codex close inference."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from mybench.claims.canonical import canonical_bytes
from mybench.commitments import leaf_commitment
from mybench.normalizer import (
    SESSION_TIMING_NORMALIZER_VERSION,
    VerifiedRecord,
    VerifiedSession,
    normalize_session_timing_bytes,
    normalize_session_timings,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries
from tests.normalizer.synthetic import synthetic_codex_normalizer_input


def _raw(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _session(*values: dict) -> VerifiedSession:
    records = []
    for index, value in enumerate(values):
        raw = _raw(value)
        records.append(
            VerifiedRecord(
                index=index,
                raw_bytes=raw,
                record_commitment=leaf_commitment(bytes([index + 1]) * 32, raw).hex(),
                attribution="subject",
            )
        )
    return VerifiedSession(
        source="codex",
        session_id="opaque-timing-unit",
        session_root="synthetic-root-not-consumed",
        records=tuple(records),
        subject_owned=True,
    )


def test_codex_close_is_versioned_and_requires_structural_task_complete():
    fixture = synthetic_codex_normalizer_input()
    timing = normalize_session_timings(fixture.sessions)[0]

    assert timing.normalizer_version == SESSION_TIMING_NORMALIZER_VERSION == "1.0.0"
    assert timing.open_status == "scan-inferred"
    assert timing.close_status == "scan-inferred"
    assert timing.opened_at == "2026-01-02T00:00:00.000000Z"
    assert timing.closed_at == "2026-01-02T00:00:17.000000Z"
    # A later arbitrary compaction record exists at :18. It is not guessed as
    # the close and is outside the eligible timing interval.
    assert "2026-01-02T00:00:18.000000Z" not in timing.event_observed_at
    # The deliberately malformed synthetic row makes active-time coverage
    # honest without invalidating the observed terminal boundary.
    assert timing.observed_at_status == "partial"


def test_absent_or_malformed_codex_terminal_timestamp_is_unknown_not_last_record():
    no_close = _session(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "type": "session_meta",
            "payload": {},
        },
        {
            "timestamp": "2026-01-01T12:00:00Z",
            "type": "response_item",
            "payload": {"type": "reasoning"},
        },
    )
    timing = normalize_session_timings((no_close,))[0]
    assert timing.close_status == "unknown"
    assert timing.closed_at is None

    malformed = _session(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "type": "session_meta",
            "payload": {},
        },
        {
            "timestamp": "not-a-timestamp",
            "type": "event_msg",
            "payload": {"type": "task_complete"},
        },
    )
    timing = normalize_session_timings((malformed,))[0]
    assert timing.close_status == "unknown"
    assert timing.closed_at is None


def test_reversed_terminal_timestamp_keeps_structural_close_bound():
    reversed_close = _session(
        {
            "timestamp": "2026-01-01T10:00:00Z",
            "type": "session_meta",
            "payload": {},
        },
        {
            "timestamp": "2026-01-01T09:00:00Z",
            "type": "event_msg",
            "payload": {"type": "task_complete"},
        },
        {
            "timestamp": "2026-01-01T12:00:00Z",
            "type": "response_item",
            "payload": {"type": "reasoning"},
        },
    )

    timing = normalize_session_timings((reversed_close,))[0]

    assert timing.close_status == "unknown"
    assert timing.closed_at is None
    assert timing.event_observed_at == ("2026-01-01T10:00:00.000000Z",)
    assert "2026-01-01T12:00:00.000000Z" not in timing.event_observed_at


def test_unknown_attribution_does_not_contribute_timing_observations():
    session = _session(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "type": "session_meta",
            "payload": {},
        },
        {
            "timestamp": "2026-01-01T00:30:00Z",
            "type": "response_item",
            "payload": {"type": "reasoning"},
        },
        {
            "timestamp": "2026-01-01T01:00:00Z",
            "type": "event_msg",
            "payload": {"type": "task_complete"},
        },
    )
    records = list(session.records)
    records[1] = replace(records[1], attribution="unknown")
    session = replace(session, records=tuple(records))

    timing = normalize_session_timings((session,))[0]

    assert timing.observed_at_status == "complete"
    assert timing.event_observed_at == (
        "2026-01-01T00:00:00.000000Z",
        "2026-01-01T01:00:00.000000Z",
    )


def test_timing_normalization_is_input_order_independent_and_identifier_free():
    fixture = synthetic_codex_normalizer_input()
    first = fixture.sessions[0]
    second = replace(first, session_id="opaque-codex-session-two")

    forward = normalize_session_timings((first, second))
    reverse = normalize_session_timings((second, first))
    assert [item.local_record() for item in forward] == [item.local_record() for item in reverse]
    encoded = canonical_bytes([item.local_record() for item in forward])
    assert b"opaque-codex-session" not in encoded
    assert b"session_id" not in encoded


def test_timing_local_output_is_leak_free_and_scanner_fires(tmp_path):
    fixture = synthetic_codex_normalizer_input()
    records = [item.local_record() for item in normalize_session_timings(fixture.sessions)]
    safe = tmp_path / "timing.json"
    safe.write_bytes(normalize_session_timing_bytes(fixture.sessions))
    assert assert_no_canaries([safe], list(fixture.canaries)) == 1

    planted = tmp_path / "planted.json"
    planted.write_bytes(canonical_bytes(records) + fixture.canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], list(fixture.canaries))
