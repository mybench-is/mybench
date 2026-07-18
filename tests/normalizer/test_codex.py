"""MYB-10.18: Codex rollout adapter, consent boundary, and privacy evidence."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import replace

import pytest
from jsonschema import ValidationError

from mybench import normalized_store, paths
from mybench.commitments import leaf_commitment
from mybench.normalizer import (
    CODEX_ADAPTER_VERSION,
    NormalizationError,
    ResolutionRecord,
    normalize_claude,
    normalize_codex,
    resolve_content_pointer,
    validate_corpus_artifact,
)
from mybench.normalizer.claude import VerifiedRecord, VerifiedSession
from mybench.schemas import load_validator
from tests.conftest import REPO_ROOT
from tests.fixtures import CanaryLeakError, assert_no_canaries
from tests.normalizer.synthetic import (
    CODEX_AGENT_CANARY,
    CODEX_CONTENT_CANARY,
    CODEX_FILENAME_CANARY,
    CODEX_NON_SUBJECT_CANARY,
    CODEX_PATH_CANARY,
    CODEX_RESULT_CANARY,
    CODEX_UNKNOWN_CANARY,
    synthetic_codex_normalizer_input,
    synthetic_normalizer_input,
)


def _artifact() -> tuple[bytes, dict]:
    data = normalize_codex(synthetic_codex_normalizer_input().sessions)
    return data, json.loads(data)


def _event(artifact: dict, kind: str, **fields) -> dict:
    return next(
        event
        for event in artifact["events"]
        if event["event_kind"] == kind
        and all(event.get(key) == value for key, value in fields.items())
    )


def _raw(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _one_record_session(value: dict, *, attribution: str = "subject") -> VerifiedSession:
    raw = _raw(value)
    nonce = b"c" * 32
    return VerifiedSession(
        source="codex",
        session_id="opaque-codex-unit",
        session_root="synthetic-root-not-an-a8-input",
        records=(
            VerifiedRecord(
                index=0,
                raw_bytes=raw,
                record_commitment=leaf_commitment(nonce, raw).hex(),
                attribution=attribution,
            ),
        ),
        subject_owned=True,
    )


def test_codex_uses_the_shared_corpus_contract_and_validates():
    data, artifact = _artifact()

    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]
    assert artifact["manifest"]["normalizer"] == json.loads(
        normalize_codex(synthetic_codex_normalizer_input().sessions)
    )["manifest"]["normalizer"]
    assert artifact["manifest"]["adapters"] == [
        {"source": "codex", "version": CODEX_ADAPTER_VERSION}
    ]
    assert {event["source"] for event in artifact["events"]} == {"codex"}

    claude_artifact = json.loads(normalize_claude(synthetic_normalizer_input().sessions))
    assert artifact["schema_version"] == claude_artifact["schema_version"] == "3"
    assert artifact["manifest"]["normalizer"] == claude_artifact["manifest"]["normalizer"]
    assert set(artifact) == set(claude_artifact)


def test_full_rollout_field_set_maps_without_guessing_or_schema_fork():
    _, artifact = _artifact()
    events = artifact["events"]

    model = _event(artifact, "model", model="gpt-5-codex")
    assert model["reasoning_effort"] == "xhigh"
    assert "provider" not in model
    assert _event(artifact, "model", provider="openai")["record_index"] == 0
    assert _event(artifact, "model", model="gpt-5-codex-max")["reasoning_effort"] == "high"
    assert _event(artifact, "lifecycle", lifecycle_marker="model-change")

    usage = _event(artifact, "token-usage")["token_usage"]
    assert usage == {
        "input_tokens": 17,
        "output_tokens": 7,
        "cache_read_input_tokens": 3,
    }
    assert "reasoning_output_tokens" not in usage and "total_tokens" not in usage

    assert {event["tool_family"] for event in events if event["event_kind"] == "tool-call"} == {
        "execute",
        "read",
        "edit",
    }
    assert _event(artifact, "reference", reference_kind="source")
    assert _event(artifact, "test", test_status="unknown")
    assert all(
        event["tool_relation"]["status"] == "linked"
        for event in events
        if event["event_kind"] == "tool-result"
    )

    boundaries = [
        event
        for event in events
        if event.get("lifecycle_marker") == "context-boundary"
    ]
    assert [event.get("context_generation_id") for event in boundaries] == [1, 2]
    assert _event(artifact, "lifecycle", lifecycle_marker="session-start")
    assert not any(event.get("lifecycle_marker") == "session-end" for event in events)


def test_missing_metadata_is_absent_and_observed_zero_is_preserved():
    session = _one_record_session(
        {
            "timestamp": "2026-01-03T00:00:00.000Z",
            "type": "event_msg",
            "payload": {
                "type": "token_count",
                "info": {"last_token_usage": {"input_tokens": 0}},
            },
        }
    )
    artifact = json.loads(normalize_codex((session,)))
    usage = _event(artifact, "token-usage")["token_usage"]
    assert usage == {"input_tokens": 0}

    model_session = _one_record_session(
        {
            "timestamp": "2026-01-03T00:00:00.000Z",
            "type": "turn_context",
            "payload": {"model": "gpt-5-codex"},
        }
    )
    model = _event(json.loads(normalize_codex((model_session,))), "model")
    assert set(model).isdisjoint({"provider", "reasoning_effort", "token_usage"})


def test_codex_lane_markers_remain_absent_even_for_launcher_shaped_metadata():
    session = _one_record_session(
        {
            "timestamp": "2026-01-03T00:00:00.000Z",
            "type": "session_meta",
            "payload": {
                "originator": "codex_exec",
                "isSidechain": True,
                "source": "exec",
            },
        }
    )
    session = replace(session, parent_session_id="opaque-parent-session")
    manifest_session = json.loads(normalize_codex((session,)))["manifest"]["sessions"][0]
    assert manifest_session["parent_session_id"] == "opaque-parent-session"
    assert set(manifest_session).isdisjoint({"lane_role", "launcher_marker"})

    artifact = json.loads(normalize_codex((session,)))
    artifact["manifest"]["sessions"][0]["lane_role"] = "subagent"
    with pytest.raises(ValidationError):
        load_validator("normalized_corpus.schema.json").validate(artifact)


def test_authorship_and_consent_filter_run_before_normalized_derivation():
    synthetic = synthetic_codex_normalizer_input()
    baseline = normalize_codex(synthetic.sessions)
    session = synthetic.sessions[0]

    filtered = tuple(record for record in session.records if record.attribution != "non-subject")
    assert normalize_codex((replace(session, records=filtered),)) == baseline

    mutated = tuple(
        replace(
            record,
            index=-999,
            raw_bytes=CODEX_NON_SUBJECT_CANARY.encode(),
            record_commitment="not-a-commitment",
        )
        if record.attribution == "non-subject"
        else record
        for record in session.records
    )
    assert normalize_codex((replace(session, records=mutated),)) == baseline

    artifact = json.loads(baseline)
    assert {event["authorship"] for event in artifact["events"]} <= {
        "human-turn",
        "agent-turn",
        "pasted-content-span",
    }
    unknown_index = next(
        index
        for index, record in enumerate(filtered)
        if CODEX_UNKNOWN_CANARY.encode() in record.raw_bytes
    )
    unknown_events = [
        event for event in artifact["events"] if event["record_index"] == unknown_index
    ]
    assert unknown_events
    assert {event["event_kind"] for event in unknown_events} == {"pasted-span"}
    assert all("pointer" not in event for event in unknown_events)


def test_input_order_is_deterministic_and_wrong_source_fails_closed():
    session = synthetic_codex_normalizer_input().sessions[0]
    child = replace(
        session,
        session_id="opaque-codex-child",
        parent_session_id=session.session_id,
    )
    assert normalize_codex((session, child)) == normalize_codex((child, session))

    wrong = replace(session, source="claude-code")
    with pytest.raises(NormalizationError, match="unsupported source"):
        normalize_codex((wrong,))


def test_codex_pointers_resolve_against_verified_records():
    synthetic = synthetic_codex_normalizer_input()
    data = normalize_codex(synthetic.sessions)
    artifact = json.loads(data)
    session = synthetic.sessions[0]

    for event_kind in ("turn", "tool-call"):
        event = next(
            event
            for event in artifact["events"]
            if event["event_kind"] == event_kind and "pointer" in event
        )
        commitment = event["pointer"]["record_commitment"]
        source_record = next(
            record for record in session.records if record.record_commitment == commitment
        )
        nonce = synthetic.nonces[source_record.index]
        resolution = resolve_content_pointer(
            event["pointer"],
            archive_records=(ResolutionRecord(source_record.raw_bytes, nonce, "subject"),),
        )
        assert resolution.status == "resolved" and resolution.source == "archive"
        assert resolution.value is not None

    assert resolve_content_pointer(event["pointer"]).status == "unknown"


def test_artifact_logs_and_private_store_have_zero_canary_hits(tmp_path, capsys):
    synthetic = synthetic_codex_normalizer_input()
    data = normalize_codex(synthetic.sessions)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""

    artifact_file = tmp_path / "codex-corpus.json"
    artifact_file.write_bytes(data)
    assert assert_no_canaries([artifact_file], list(synthetic.canaries)) == 1

    stored = normalized_store.store_corpus_artifact(data)
    assert stored.read_bytes() == data
    assert stored.resolve().is_relative_to(paths.data_dir().resolve())
    assert REPO_ROOT not in stored.resolve().parents
    for directory in (paths.data_dir(), paths.normalized_dir(), stored.parent):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600
    assert stored.stat().st_nlink == 1


def test_companion_scan_fires_on_fixture_derived_artifact(tmp_path):
    synthetic = synthetic_codex_normalizer_input()
    planted = tmp_path / "planted-codex-corpus.json"
    planted.write_bytes(normalize_codex(synthetic.sessions) + CODEX_CONTENT_CANARY.encode())

    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], list(synthetic.canaries))


def test_malformed_and_future_records_degrade_to_coverage_without_echo(capsys):
    data, artifact = _artifact()
    coverage = artifact["manifest"]["coverage"]
    assert coverage["records_malformed"] == 1
    assert coverage["records_unsupported"] == 1
    assert coverage["records_ambiguous_authorship"] == 1
    assert CODEX_CONTENT_CANARY.encode() not in data
    assert CODEX_AGENT_CANARY.encode() not in data
    assert CODEX_RESULT_CANARY.encode() not in data
    assert CODEX_FILENAME_CANARY.encode() not in data
    assert CODEX_PATH_CANARY.encode() not in data
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_non_subject_session_is_presence_insensitive_even_when_malformed():
    baseline = normalize_codex(synthetic_codex_normalizer_input().sessions)
    excluded = VerifiedSession(
        source="not-codex",
        session_id=CODEX_NON_SUBJECT_CANARY,
        session_root=CODEX_NON_SUBJECT_CANARY,
        records=(object(),),
        subject_owned=False,
    )
    assert normalize_codex((*synthetic_codex_normalizer_input().sessions, excluded)) == baseline


def test_test_environment_data_root_is_outside_repo_and_private():
    paths.ensure_data_dir()
    assert REPO_ROOT not in paths.data_dir().resolve().parents
    assert stat.S_IMODE(os.stat(paths.data_dir()).st_mode) == 0o700
