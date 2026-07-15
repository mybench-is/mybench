"""Live -> A9 pointer fallback and honest dangling-pointer coverage."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from mybench.commitments import leaf_commitment
from mybench.normalizer.claude import (
    ResolutionIntegrityError,
    ResolutionRecord,
    normalize_claude,
    resolve_content_pointer,
    resolution_coverage,
)
from tests.normalizer.synthetic import AGENT_CANARY, synthetic_normalizer_input


@pytest.fixture
def pointer_case():
    synthetic = synthetic_normalizer_input()
    session = synthetic.sessions[0]
    artifact = json.loads(normalize_claude(synthetic.sessions))
    event = next(
        event
        for event in artifact["events"]
        if event["session_id"] == session.session_id
        and event["record_index"] == 4
        and "pointer" in event
    )
    nonces = synthetic.nonces[: len(session.records)]
    candidates = tuple(
        ResolutionRecord(record.raw_bytes, nonce, record.attribution)
        for record, nonce in zip(session.records, nonces)
    )
    return event, candidates


def test_live_source_resolves_first_without_exposing_value_in_repr(pointer_case):
    event, candidates = pointer_case
    result = resolve_content_pointer(
        event["pointer"],
        live_records=candidates,
        archive_records=None,
    )
    assert result.status == "resolved" and result.source == "live"
    assert result.value == "final " + AGENT_CANARY
    assert AGENT_CANARY not in repr(result)


def test_mutated_or_missing_live_source_falls_back_to_verified_a9(pointer_case):
    event, candidates = pointer_case
    mutated = list(candidates)
    mutated[event["record_index"]] = replace(
        mutated[event["record_index"]],
        raw_bytes=b'{"synthetic":"changed-live-source"}',
    )
    result = resolve_content_pointer(
        event["pointer"],
        live_records=tuple(mutated),
        archive_records=candidates,
    )
    assert result.status == "resolved" and result.source == "archive"
    assert result.value == "final " + AGENT_CANARY


def test_pruned_live_layout_and_full_archive_use_independent_verification(pointer_case):
    event, candidates = pointer_case
    result = resolve_content_pointer(
        event["pointer"],
        live_records=candidates[4:],
        archive_records=candidates,
    )
    assert result.status == "resolved" and result.source == "live"
    assert result.value == "final " + AGENT_CANARY


def test_deleted_live_and_archive_targets_are_unknown_not_zero_or_failure(pointer_case):
    event, _ = pointer_case
    result = resolve_content_pointer(
        event["pointer"],
        live_records=None,
        archive_records=None,
    )
    assert result.status == "unknown"
    assert result.reason == "target-missing"
    assert result.value is None
    assert resolution_coverage([result]) == {
        "coverage_class": "none",
        "references_total": 1,
        "references_resolved": 0,
        "references_unknown": 1,
    }


def test_present_but_commitment_invalid_archive_is_integrity_error(pointer_case):
    event, candidates = pointer_case
    corrupted = list(candidates)
    corrupted[event["record_index"]] = replace(
        corrupted[event["record_index"]],
        raw_bytes=b'{"synthetic":"corrupt-archive"}',
    )
    with pytest.raises(ResolutionIntegrityError, match="archive record commitment mismatch"):
        resolve_content_pointer(
            event["pointer"],
            live_records=None,
            archive_records=tuple(corrupted),
        )


def test_resolution_coverage_is_counts_only_and_total(pointer_case):
    event, candidates = pointer_case
    resolved = resolve_content_pointer(
        event["pointer"],
        live_records=candidates,
        archive_records=None,
    )
    unknown = resolve_content_pointer(
        event["pointer"],
        live_records=None,
        archive_records=None,
    )
    assert resolution_coverage([])["coverage_class"] == "not-applicable"
    assert resolution_coverage([resolved])["coverage_class"] == "complete"
    assert resolution_coverage([resolved, unknown]) == {
        "coverage_class": "partial",
        "references_total": 2,
        "references_resolved": 1,
        "references_unknown": 1,
    }


def test_dense_normalized_index_never_selects_the_wrong_raw_record():
    synthetic = synthetic_normalizer_input()
    main = synthetic.sessions[0]
    main_nonces = list(synthetic.nonces[: len(main.records)])
    order = [6, *range(6), *range(7, len(main.records))]
    records = tuple(
        replace(main.records[old_index], index=new_index)
        for new_index, old_index in enumerate(order)
    )
    nonces = tuple(main_nonces[index] for index in order)
    reordered = replace(main, records=records)
    artifact = json.loads(normalize_claude((reordered,)))
    event = next(
        event
        for event in artifact["events"]
        if event["event_kind"] == "turn" and "pointer" in event
    )
    assert event["record_index"] != 5  # the pointed raw record's source position
    candidates = tuple(
        ResolutionRecord(record.raw_bytes, nonce, record.attribution)
        for record, nonce in zip(records, nonces)
    )
    result = resolve_content_pointer(
        event["pointer"],
        live_records=candidates,
        archive_records=None,
    )
    assert result.status == "resolved"
    assert result.value == "final " + AGENT_CANARY


def test_tool_input_pointer_resolves_the_committed_structure_without_repr_leak():
    command = "pytest synthetic_private_suite_8b1f"
    raw = json.dumps(
        {
            "type": "assistant",
            "isSidechain": False,
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "name": "Bash",
                        "input": {"command": command},
                    }
                ],
            },
        },
        separators=(",", ":"),
    ).encode()
    nonce = bytes.fromhex("72" * 32)
    commitment = leaf_commitment(nonce, raw).hex()
    from mybench.normalizer.claude import VerifiedRecord, VerifiedSession

    session = VerifiedSession(
        "claude-code",
        "opaque-tool-pointer-session",
        "00" * 32,
        (VerifiedRecord(0, raw, commitment, "subject"),),
        True,
    )
    artifact = json.loads(normalize_claude((session,)))
    event = next(event for event in artifact["events"] if event["event_kind"] == "test")
    result = resolve_content_pointer(
        event["pointer"],
        live_records=(ResolutionRecord(raw, nonce, "subject"),),
        archive_records=None,
    )
    assert result.value == {"command": command}
    assert command not in repr(result)


@pytest.mark.parametrize(
    ("value", "pointer_fields"),
    [
        (
            {"type": "user", "message": {"role": "user", "content": "synthetic"}},
            {"field": "message-text", "start": 0, "end": 1, "unit": "unicode-scalar"},
        ),
        (
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "tool_result", "text": "synthetic"}],
                },
            },
            {
                "field": "content-block-text",
                "block_index": 0,
                "start": 0,
                "end": 1,
                "unit": "unicode-scalar",
            },
        ),
        (
            {
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [{"type": "tool_use", "input": {"value": "synthetic"}}],
                },
            },
            {"field": "tool-input", "block_index": 0},
        ),
        (
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "synthetic"},
                        {"type": "tool_use", "input": {}},
                    ],
                },
            },
            {
                "field": "content-block-text",
                "block_index": 0,
                "start": 0,
                "end": 1,
                "unit": "unicode-scalar",
            },
        ),
    ],
    ids=["user-text", "non-text-block", "user-tool-input", "mixed-assistant-record"],
)
def test_resolver_refuses_commitment_valid_but_ineligible_raw_sources(value, pointer_fields):
    raw = json.dumps(value, separators=(",", ":")).encode()
    nonce = bytes.fromhex("83" * 32)
    pointer = {
        **pointer_fields,
        "record_commitment": leaf_commitment(nonce, raw).hex(),
    }
    with pytest.raises(ResolutionIntegrityError, match="ineligible|unavailable"):
        resolve_content_pointer(
            pointer,
            live_records=(ResolutionRecord(raw, nonce, "subject"),),
        )


def test_resolver_refuses_non_subject_assistant_record_even_when_commitment_matches():
    raw = b'{"message":{"content":"synthetic","role":"assistant"},"type":"assistant"}'
    nonce = bytes.fromhex("94" * 32)
    pointer = {
        "field": "message-text",
        "start": 0,
        "end": 1,
        "unit": "unicode-scalar",
        "record_commitment": leaf_commitment(nonce, raw).hex(),
    }
    with pytest.raises(ResolutionIntegrityError, match="ineligible attribution"):
        resolve_content_pointer(
            pointer,
            live_records=(ResolutionRecord(raw, nonce, "non-subject"),),
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": "resolved"},
        {"status": "resolved", "source": "bogus"},
        {"status": "resolved", "source": "live", "reason": "target-missing"},
        {"status": "unknown", "source": "live", "reason": "target-missing"},
        {"status": "unknown", "reason": "different"},
    ],
)
def test_content_resolution_rejects_forged_states(kwargs):
    from mybench.normalizer.claude import ContentResolution, NormalizationError

    with pytest.raises(NormalizationError, match="invalid state"):
        ContentResolution(**kwargs)
