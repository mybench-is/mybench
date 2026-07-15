"""Claude adapter mapping, schema, filtering, and fail-closed behavior."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from jsonschema import ValidationError

from mybench.commitments import leaf_commitment, session_root
from mybench.claims.canonical import canonical_bytes
from mybench.normalizer.claude import (
    NoEvidence,
    NormalizationError,
    VerifiedRecord,
    VerifiedSession,
    corpus_commitment,
    normalize_claude,
    validate_corpus_artifact,
)
from mybench.schemas import load_validator
from tests.fixtures import CanaryLeakError, assert_no_canaries
from tests.normalizer.synthetic import (
    AGENT_CANARY,
    CONTENT_CANARY,
    NON_SUBJECT_CANARY,
    PASTE_CANARY,
    PATH_CANARY,
    RESULT_CANARY,
    UNKNOWN_CANARY,
    synthetic_normalizer_input,
)


@pytest.fixture
def normalized():
    synthetic = synthetic_normalizer_input()
    data = normalize_claude(synthetic.sessions)
    return synthetic, data, json.loads(data)


def events_for(artifact, session_id, *, kind=None):
    events = [event for event in artifact["events"] if event["session_id"] == session_id]
    return [event for event in events if event["event_kind"] == kind] if kind else events


def _one_record_session(raw: bytes, *, commitment: str | None = None) -> VerifiedSession:
    nonce = bytes.fromhex("91" * 32)
    record_commitment = commitment or leaf_commitment(nonce, raw).hex()
    return VerifiedSession(
        source="claude-code",
        session_id="opaque-test-session",
        session_root=session_root([bytes.fromhex(record_commitment)]).hex(),
        records=(VerifiedRecord(0, raw, record_commitment, "subject"),),
        subject_owned=True,
    )


def _rebound(artifact: dict) -> bytes:
    artifact["manifest"]["event_count"] = len(artifact["events"])
    artifact["corpus_commitment"] = corpus_commitment(
        artifact["manifest"], artifact["events"]
    )
    return canonical_bytes(artifact) + b"\n"


def test_corpus_is_canonical_schema_valid_and_self_verifying(normalized):
    _, data, artifact = normalized
    load_validator("normalized_corpus.schema.json").validate(artifact)
    assert data == json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]
    assert artifact["manifest"]["event_count"] == len(artifact["events"])
    assert all(event["authorship"] in {
        "human-turn",
        "agent-turn",
        "pasted-content-span",
    } for event in artifact["events"])


def test_block_level_authorship_never_treats_tool_result_as_human(normalized):
    _, _, artifact = normalized
    main_events = events_for(artifact, "opaque-main-session")
    result = next(event for event in main_events if event["event_kind"] == "tool-result")
    assert result["authorship"] == "pasted-content-span"
    assert "pointer" not in result
    assert result["tool_relation"] == {
        "status": "linked",
        "record_index": 1,
        "subevent_index": 3,
    }
    assert result["result_status"] == "success"

    mixed_text = next(
        event
        for event in main_events
        if event["record_index"] == 2 and event["event_kind"] == "turn"
    )
    assert mixed_text["authorship"] == "human-turn"
    assert "pointer" not in mixed_text


def test_human_and_sidechain_text_are_structural_only(normalized):
    _, _, artifact = normalized
    main_turns = events_for(artifact, "opaque-main-session", kind="turn")
    human_turns = [event for event in main_turns if event["authorship"] == "human-turn"]
    assert human_turns
    assert all("pointer" not in event for event in human_turns)

    side_turns = events_for(artifact, "opaque-sidechain-session", kind="turn")
    delegated_prompt = next(event for event in side_turns if event["record_index"] == 0)
    assert delegated_prompt["authorship"] == "agent-turn"
    assert "pointer" not in delegated_prompt


def test_only_assistant_text_only_records_receive_content_pointers(normalized):
    _, _, artifact = normalized
    main_turns = events_for(artifact, "opaque-main-session", kind="turn")
    mixed_assistant = next(event for event in main_turns if event["record_index"] == 1)
    final_assistant = next(event for event in main_turns if event["record_index"] == 4)
    assert "pointer" not in mixed_assistant
    assert final_assistant["pointer"]["field"] == "content-block-text"
    assert final_assistant["pointer"]["block_index"] == 0
    assert final_assistant["pointer"]["record_commitment"] == (
        synthetic_normalizer_input().sessions[0].records[4].record_commitment
    )


def test_tool_inputs_are_pointer_only_reference_and_test_evidence(normalized):
    _, data, artifact = normalized
    main_events = events_for(artifact, "opaque-main-session")
    tool_call = next(event for event in main_events if event["event_kind"] == "tool-call")
    reference = next(event for event in main_events if event["event_kind"] == "reference")
    assert tool_call["pointer"]["field"] == "tool-input"
    assert reference["reference_kind"] == "source"
    assert reference["pointer"] == tool_call["pointer"]
    assert PATH_CANARY.encode() not in data

    command_canary = "pytest -q synthetic_private_suite_5f0a"
    raw = json.dumps(
        {
            "type": "assistant",
            "isSidechain": False,
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "synthetic-test-tool",
                        "name": "Bash",
                        "input": {"command": command_canary},
                    }
                ],
            },
        },
        separators=(",", ":"),
    ).encode()
    test_data = normalize_claude((_one_record_session(raw),))
    test_artifact = json.loads(test_data)
    test_event = next(
        event for event in test_artifact["events"] if event["event_kind"] == "test"
    )
    assert test_event["test_scope"] == "other"
    assert test_event["test_status"] == "unknown"
    assert test_event["pointer"]["field"] == "tool-input"
    assert command_canary.encode() not in test_data
    load_validator("normalized_corpus.schema.json").validate(test_artifact)
    assert validate_corpus_artifact(test_data) == test_artifact["corpus_commitment"]


def test_closed_metadata_preserves_explicit_zero_without_guessing(normalized):
    _, _, artifact = normalized
    main_events = events_for(artifact, "opaque-main-session")
    model = next(event for event in main_events if event["event_kind"] == "model")
    usage = next(event for event in main_events if event["event_kind"] == "token-usage")
    assert (model["model"], model["provider"], model["reasoning_effort"]) == (
        "synthetic-model-v1",
        "synthetic",
        "high",
    )
    assert usage["token_usage"] == {"input_tokens": 0, "output_tokens": 7}
    assert all("provider" not in event for event in events_for(
        artifact, "opaque-sidechain-session"
    ))


def test_observed_context_generation_and_lifecycle_are_not_inferred(normalized):
    _, _, artifact = normalized
    main_events = events_for(artifact, "opaque-main-session")
    lifecycle = next(event for event in main_events if event["event_kind"] == "lifecycle")
    assert lifecycle["lifecycle_marker"] == "context-boundary"
    assert lifecycle["context_generation_id"] == 1
    assert all(
        "context_generation_id" not in event
        for event in main_events
        if event is not lifecycle
    )


def test_versioned_episode_stitcher_links_only_recorded_parent_lineage(normalized):
    _, _, artifact = normalized
    sessions = artifact["manifest"]["sessions"]
    assert [session["session_id"] for session in sessions] == [
        "opaque-main-session",
        "opaque-sidechain-session",
    ]
    assert sessions[0]["task_episode_id"] == sessions[1]["task_episode_id"]
    assert sessions[1]["parent_session_id"] == "opaque-main-session"


def test_episode_stitcher_uses_conservative_repo_head_time_continuity():
    raw = b'{"isSidechain":false,"message":{"content":"synthetic","role":"user"},"type":"user"}'
    first = replace(
        _one_record_session(raw),
        session_id="opaque-continuity-first",
        repo_id="ab" * 8,
        head_before="1" * 40,
        head_after="2" * 40,
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:05:00Z",
    )
    second = replace(
        _one_record_session(raw),
        session_id="opaque-continuity-second",
        repo_id="ab" * 8,
        head_before="2" * 40,
        head_after="3" * 40,
        started_at="2026-01-01T00:10:00Z",
        ended_at="2026-01-01T00:15:00Z",
    )
    data = normalize_claude((second, first))
    artifact = json.loads(data)
    sessions = artifact["manifest"]["sessions"]
    assert sessions[0]["task_episode_id"] == sessions[1]["task_episode_id"]
    assert sessions[1]["episode_predecessor"] == {
        "session_id": "opaque-continuity-first",
        "signals": ["repo-id", "head-continuity", "temporal-adjacency"],
    }
    assert b"abababababababab" not in data
    assert ("2" * 40).encode() not in data
    load_validator("normalized_corpus.schema.json").validate(artifact)
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]

    distant = replace(
        second,
        started_at="2026-01-01T01:00:00Z",
        ended_at="2026-01-01T01:05:00Z",
    )
    distant_sessions = json.loads(normalize_claude((first, distant)))["manifest"][
        "sessions"
    ]
    assert all("task_episode_id" not in session for session in distant_sessions)


def test_standalone_session_does_not_guess_a_task_episode():
    raw = json.dumps(
        {
            "type": "user",
            "isSidechain": False,
            "message": {"role": "user", "content": "synthetic standalone"},
        },
        separators=(",", ":"),
    ).encode()
    artifact = json.loads(normalize_claude((_one_record_session(raw),)))
    assert "task_episode_id" not in artifact["manifest"]["sessions"][0]
    assert all("task_episode_id" not in event for event in artifact["events"])


def test_external_parent_is_preserved_as_unresolved_without_minting_episode():
    raw = b'{"isSidechain":false,"message":{"content":"synthetic","role":"user"},"type":"user"}'
    session = replace(
        _one_record_session(raw), parent_session_id="opaque-parent-not-in-corpus"
    )
    data = normalize_claude((session,))
    artifact = json.loads(data)
    manifest_session = artifact["manifest"]["sessions"][0]
    assert manifest_session["parent_session_id"] == "opaque-parent-not-in-corpus"
    assert "task_episode_id" not in manifest_session
    assert artifact["manifest"]["coverage"]["lineage_unresolved"] == 1
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]


def test_non_subject_session_and_records_are_filtered_before_a8(normalized):
    _, data, artifact = normalized
    manifest = artifact["manifest"]
    assert all(
        session["session_id"] != "opaque-non-subject-session"
        for session in manifest["sessions"]
    )
    assert manifest["coverage"]["records_ambiguous_authorship"] == 1
    assert "sessions_excluded_non_subject" not in manifest["coverage"]
    assert "records_excluded_non_subject" not in manifest["coverage"]
    assert all("session_root" not in session for session in manifest["sessions"])
    assert NON_SUBJECT_CANARY.encode() not in data


def test_changing_non_subject_bytes_and_commitments_cannot_change_a8():
    synthetic = synthetic_normalizer_input()
    baseline = normalize_claude(synthetic.sessions)
    main = synthetic.sessions[0]
    changed_raw = b'{"synthetic":"different excluded third-party bytes"}'
    changed_commitment = leaf_commitment(synthetic.nonces[6], changed_raw).hex()
    records = list(main.records)
    records[6] = replace(
        records[6],
        raw_bytes=changed_raw,
        record_commitment=changed_commitment,
    )
    changed_root = session_root(
        [bytes.fromhex(record.record_commitment) for record in records]
    ).hex()
    changed_main = replace(main, records=tuple(records), session_root=changed_root)
    assert normalize_claude((changed_main, *synthetic.sessions[1:])) == baseline


def test_corrupt_duplicate_and_reordered_non_subject_inputs_are_presence_insensitive():
    synthetic = synthetic_normalizer_input()
    baseline = normalize_claude(synthetic.sessions)
    main, sidechain, non_subject = synthetic.sessions

    corrupt_record = replace(
        main.records[6],
        index=[],
        raw_bytes=b"invalid\nexcluded framing",
        record_commitment=[],
        context_generation_id=-99,
    )
    corrupt_main = replace(
        main,
        records=(*main.records[:6], corrupt_record, *main.records[7:]),
    )
    assert normalize_claude((corrupt_main, sidechain, non_subject)) == baseline

    corrupt_session = replace(
        non_subject,
        source=[],
        session_id=main.session_id,
        session_root=[],
        records=[],
        parent_session_id=main.session_id,
    )
    assert normalize_claude((main, sidechain, corrupt_session)) == baseline

    unadjusted = (main.records[6], *main.records[:6], *main.records[7:])
    assert normalize_claude((replace(main, records=unadjusted), sidechain, non_subject)) == baseline

    reordered = tuple(
        replace(record, index=index) for index, record in enumerate(unadjusted)
    )
    assert normalize_claude((replace(main, records=reordered), sidechain, non_subject)) == baseline


def test_unknown_and_explicit_fenced_pastes_emit_shape_only(normalized):
    _, data, artifact = normalized
    pasted = events_for(artifact, "opaque-main-session", kind="pasted-span")
    assert {event["record_index"] for event in pasted} == {3, 6}
    assert all(event["authorship"] == "pasted-content-span" for event in pasted)
    assert all("pointer" not in event for event in pasted)
    assert PASTE_CANARY.encode() not in data
    assert UNKNOWN_CANARY.encode() not in data


def test_unknown_unsupported_blocks_keep_coverage_internally_consistent():
    raw = b'{"message":{"content":[7],"role":"user"},"type":"user"}'
    session = _one_record_session(raw)
    session = replace(
        session,
        records=(replace(session.records[0], attribution="unknown"),),
    )
    data = normalize_claude((session,))
    artifact = json.loads(data)
    coverage = artifact["manifest"]["coverage"]
    assert coverage["blocks_seen"] == coverage["blocks_unsupported"] == 1
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]


def test_malformed_and_future_records_are_total_coverage_not_pipeline_failures(normalized):
    _, _, artifact = normalized
    coverage = artifact["manifest"]["coverage"]
    assert coverage["records_malformed"] == 1
    assert coverage["records_unsupported"] == 1
    assert coverage["records_seen"] == 11


def test_artifact_contains_no_raw_content_path_identifier_or_nonce_canaries(tmp_path, normalized):
    synthetic, data, _ = normalized
    artifact = tmp_path / "normalized.json"
    artifact.write_bytes(data)
    log = tmp_path / "normalizer.log"
    log.write_text("source=claude-code status=ok events=synthetic\n")
    assert assert_no_canaries([artifact, log], list(synthetic.canaries)) == 2


def test_privacy_scan_companion_fires_when_a_canary_is_planted(tmp_path):
    artifact = tmp_path / "planted.json"
    artifact.write_text(CONTENT_CANARY)
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([artifact], [CONTENT_CANARY.encode()])


@pytest.mark.parametrize("payload", [PATH_CANARY, CONTENT_CANARY, RESULT_CANARY, AGENT_CANARY])
def test_closed_schema_rejects_content_smuggling(normalized, payload):
    _, _, artifact = normalized
    artifact["events"][0]["text"] = payload
    with pytest.raises(ValidationError):
        load_validator("normalized_corpus.schema.json").validate(artifact)


def test_core_validator_rejects_extra_fields_and_root_tampering_without_echo(normalized):
    _, _, artifact = normalized
    artifact["events"][0]["text"] = CONTENT_CANARY
    data = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(NormalizationError) as extra:
        validate_corpus_artifact(data)
    assert CONTENT_CANARY not in str(extra.value)

    del artifact["events"][0]["text"]
    artifact["corpus_commitment"] = "00" * 32
    data = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(NormalizationError, match="commitment does not match"):
        validate_corpus_artifact(data)


def test_core_validator_enforces_episode_graph_and_event_identity(normalized):
    _, _, baseline = normalized

    artifact = json.loads(json.dumps(baseline))
    artifact["events"][0]["task_episode_id"] = "ep-" + "0" * 32
    with pytest.raises(NormalizationError, match="event episode identity"):
        validate_corpus_artifact(_rebound(artifact))

    artifact = json.loads(json.dumps(baseline))
    del artifact["manifest"]["sessions"][0]["task_episode_id"]
    with pytest.raises(NormalizationError, match="manifest episode identity"):
        validate_corpus_artifact(_rebound(artifact))

    artifact = json.loads(json.dumps(baseline))
    artifact["manifest"]["sessions"][0]["parent_session_id"] = (
        "opaque-sidechain-session"
    )
    with pytest.raises(NormalizationError, match="lineage contains a cycle"):
        validate_corpus_artifact(_rebound(artifact))

    standalone_raw = b'{"isSidechain":false,"message":{"content":"synthetic","role":"user"},"type":"user"}'
    artifact = json.loads(normalize_claude((_one_record_session(standalone_raw),)))
    fake_episode = "ep-" + "1" * 32
    artifact["manifest"]["sessions"][0]["task_episode_id"] = fake_episode
    for event in artifact["events"]:
        event["task_episode_id"] = fake_episode
    with pytest.raises(NormalizationError, match="manifest episode identity"):
        validate_corpus_artifact(_rebound(artifact))


def test_closed_core_event_union_rejects_cross_kind_fields(normalized):
    _, _, artifact = normalized
    artifact["events"][0]["lifecycle_marker"] = "session-start"
    with pytest.raises(NormalizationError, match="another event kind"):
        validate_corpus_artifact(_rebound(artifact))


def test_core_validator_enforces_cross_event_record_and_tool_relations(normalized):
    _, _, baseline = normalized
    artifact = json.loads(json.dumps(baseline))
    result = next(event for event in artifact["events"] if event["event_kind"] == "tool-result")
    result["tool_relation"] = {"status": "linked", "record_index": 0, "subevent_index": 0}
    with pytest.raises(NormalizationError, match="prior tool call"):
        validate_corpus_artifact(_rebound(artifact))

    artifact = json.loads(json.dumps(baseline))
    same_record = [
        event
        for event in artifact["events"]
        if event["session_id"] == "opaque-main-session" and event["record_index"] == 1
    ]
    same_record[-1]["parent_link"] = {"status": "root"}
    with pytest.raises(NormalizationError, match="source record"):
        validate_corpus_artifact(_rebound(artifact))

    artifact = json.loads(json.dumps(baseline))
    reference = next(event for event in artifact["events"] if event["event_kind"] == "reference")
    reference["pointer"]["record_commitment"] = "77" * 32
    with pytest.raises(NormalizationError, match="pointers disagree"):
        validate_corpus_artifact(_rebound(artifact))

    artifact = json.loads(json.dumps(baseline))
    artifact["manifest"]["coverage"]["content_references"] += 1
    with pytest.raises(NormalizationError, match="reference coverage"):
        validate_corpus_artifact(_rebound(artifact))

    artifact = json.loads(json.dumps(baseline))
    artifact["manifest"]["coverage"]["content_unknown"] = 0
    with pytest.raises(NormalizationError, match="unknown-content coverage"):
        validate_corpus_artifact(_rebound(artifact))

    artifact = json.loads(json.dumps(baseline))
    artifact["manifest"]["coverage"]["blocks_unsupported"] = (
        artifact["manifest"]["coverage"]["blocks_seen"] + 1
    )
    with pytest.raises(NormalizationError, match="block coverage"):
        validate_corpus_artifact(_rebound(artifact))


def test_zero_session_input_has_no_root():
    with pytest.raises(NoEvidence, match="no verified sessions"):
        normalize_claude(())


def test_nonempty_non_subject_input_has_valid_manifest_only_root():
    synthetic = synthetic_normalizer_input()
    data = normalize_claude((synthetic.sessions[2],))
    artifact = json.loads(data)
    assert artifact["events"] == []
    assert artifact["manifest"]["sessions"] == []
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]


def test_malformed_duplicate_keys_and_role_mismatch_fail_closed():
    duplicate = b'{"type":"user","type":"assistant"}'
    role_mismatch = json.dumps(
        {
            "type": "user",
            "isSidechain": False,
            "message": {"role": "assistant", "content": CONTENT_CANARY},
        },
        separators=(",", ":"),
    ).encode()
    for raw, expected in ((duplicate, "records_malformed"), (role_mismatch, "records_unsupported")):
        artifact = json.loads(normalize_claude((_one_record_session(raw),)))
        assert artifact["events"] == []
        assert artifact["manifest"]["coverage"][expected] == 1


def test_oversized_integer_is_malformed_not_a_parser_exception():
    raw = b'{"integer":' + b"9" * 5000 + b"}"
    artifact = json.loads(normalize_claude((_one_record_session(raw),)))
    assert artifact["events"] == []
    assert artifact["manifest"]["coverage"]["records_malformed"] == 1


def test_parser_recursion_error_is_malformed_not_an_exception(monkeypatch):
    from mybench.normalizer import claude as claude_normalizer

    def recursion_error(*_args, **_kwargs):
        raise RecursionError

    with monkeypatch.context() as scoped:
        scoped.setattr(claude_normalizer.json, "loads", recursion_error)
        data = normalize_claude((_one_record_session(b'{"synthetic":true}'),))
    artifact = json.loads(data)
    assert artifact["events"] == []
    assert artifact["manifest"]["coverage"]["records_malformed"] == 1

    with monkeypatch.context() as scoped:
        scoped.setattr(claude_normalizer.json, "loads", recursion_error)
        with pytest.raises(NormalizationError, match="not valid JSON"):
            validate_corpus_artifact(data)


@pytest.mark.parametrize(
    "value",
    [
        {"type": []},
        {
            "type": "assistant",
            "isSidechain": False,
            "message": {
                "role": "assistant",
                "provider": [],
                "effort": [],
                "content": "synthetic",
            },
        },
        {"type": "system", "subtype": []},
        {
            "type": "assistant",
            "isSidechain": False,
            "message": {"role": "assistant", "content": [{"type": []}]},
        },
        {
            "type": "assistant",
            "isSidechain": False,
            "message": {
                "role": "assistant",
                "content": "synthetic",
                "usage": {
                    "input_tokens": True,
                    "output_tokens": -1,
                    "cache_read_input_tokens": 1.5,
                },
            },
        },
    ],
)
def test_unhashable_and_invalid_future_values_are_total(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    data = normalize_claude((_one_record_session(raw),))
    artifact = json.loads(data)
    load_validator("normalized_corpus.schema.json").validate(artifact)
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]


def test_unhashable_artifact_labels_raise_safe_validation_errors(normalized):
    _, _, baseline = normalized
    for mutate in (
        lambda artifact: artifact["manifest"]["adapters"][0].update(source=[]),
        lambda artifact: artifact["events"][0].update(event_kind=[]),
        lambda artifact: artifact["events"][0].update(source=[]),
    ):
        artifact = json.loads(json.dumps(baseline))
        mutate(artifact)
        data = canonical_bytes(artifact) + b"\n"
        with pytest.raises(NormalizationError):
            validate_corpus_artifact(data)


def test_context_generation_is_emitted_only_for_strict_observed_boundaries():
    user_raw = json.dumps(
        {
            "type": "user",
            "isSidechain": False,
            "message": {"role": "user", "content": "synthetic"},
        },
        separators=(",", ":"),
    ).encode()
    boundary_raw = b'{"subtype":"compact_boundary","type":"system"}'
    raws = (user_raw, boundary_raw, boundary_raw)
    nonces = tuple(bytes([31 + index]) * 32 for index in range(3))
    commitments = tuple(
        leaf_commitment(nonce, raw) for nonce, raw in zip(nonces, raws)
    )
    session = VerifiedSession(
        source="claude-code",
        session_id="opaque-context-session",
        session_root=session_root(commitments).hex(),
        records=tuple(
            VerifiedRecord(index, raw, commitments[index].hex(), "subject", generation)
            for index, (raw, generation) in enumerate(zip(raws, (99, 1, 1)))
        ),
        subject_owned=True,
    )
    data = normalize_claude((session,))
    artifact = json.loads(data)
    contexts = [
        event["context_generation_id"]
        for event in artifact["events"]
        if "context_generation_id" in event
    ]
    assert contexts == [1]
    assert artifact["manifest"]["coverage"]["metadata_invalid"] == 2
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]

    turn = next(event for event in artifact["events"] if event["event_kind"] == "turn")
    turn["context_generation_id"] = 2
    with pytest.raises(NormalizationError, match="another event kind"):
        validate_corpus_artifact(_rebound(artifact))

    strict_session = replace(
        session,
        records=tuple(
            replace(record, context_generation_id=generation)
            for record, generation in zip(session.records, (None, 1, 2))
        ),
    )
    strict_artifact = json.loads(normalize_claude((strict_session,)))
    boundaries = [
        event
        for event in strict_artifact["events"]
        if "context_generation_id" in event
    ]
    boundaries[1]["context_generation_id"] = 1
    with pytest.raises(NormalizationError, match="strictly increasing"):
        validate_corpus_artifact(_rebound(strict_artifact))


def test_inconsistent_raw_session_identifier_excludes_all_records_without_leak():
    raws = [
        json.dumps(
            {
                "type": "user",
                "isSidechain": False,
                "sessionId": raw_id,
                "message": {"role": "user", "content": CONTENT_CANARY},
            },
            separators=(",", ":"),
        ).encode()
        for raw_id in ("raw-a", "raw-b")
    ]
    nonces = [bytes([70 + index]) * 32 for index in range(2)]
    commitments = [leaf_commitment(nonce, raw) for nonce, raw in zip(nonces, raws)]
    session = VerifiedSession(
        "claude-code",
        "opaque-inconsistent-session",
        session_root(commitments).hex(),
        tuple(
            VerifiedRecord(index, raw, commitments[index].hex(), "subject")
            for index, raw in enumerate(raws)
        ),
        True,
    )
    artifact = json.loads(normalize_claude((session,)))
    assert artifact["events"] == []
    assert artifact["manifest"]["coverage"]["records_unsupported"] == 2
    assert b"raw-a" not in normalize_claude((session,))


def test_input_session_order_does_not_change_bytes():
    sessions = synthetic_normalizer_input().sessions
    assert normalize_claude(sessions) == normalize_claude(tuple(reversed(sessions)))


def test_shared_schema_and_store_validator_leave_room_for_codex_without_a_fork():
    raw = json.dumps(
        {
            "type": "user",
            "isSidechain": False,
            "message": {"role": "user", "content": "synthetic shared schema"},
        },
        separators=(",", ":"),
    ).encode()
    artifact = json.loads(normalize_claude((_one_record_session(raw),)))
    manifest = artifact["manifest"]
    manifest["adapters"] = [{"source": "codex", "version": "1.0.0"}]
    manifest["sessions"][0]["source"] = "codex"
    base = artifact["events"][0]
    base["source"] = "codex"

    model = {
        key: value
        for key, value in base.items()
        if key not in {"content_shape", "event_kind", "authorship"}
    }
    model.update(
        {
            "subevent_index": 1,
            "event_kind": "model",
            "authorship": "agent-turn",
            "model": "gpt-5",
            "provider": "openai",
            "reasoning_effort": "xhigh",
        }
    )
    reference = {
        key: value
        for key, value in base.items()
        if key not in {"content_shape", "event_kind", "authorship"}
    }
    reference.update(
        {
            "subevent_index": 2,
            "event_kind": "reference",
            "authorship": "agent-turn",
            "reference_kind": "plan",
            "pointer": {
                "field": "message-text",
                "start": 0,
                "end": 1,
                "unit": "unicode-scalar",
                "record_commitment": "55" * 32,
            },
        }
    )
    test_event = {
        key: value
        for key, value in base.items()
        if key not in {"content_shape", "event_kind", "authorship"}
    }
    test_event.update(
        {
            "subevent_index": 3,
            "event_kind": "test",
            "authorship": "agent-turn",
            "test_scope": "integration",
            "test_status": "passed",
        }
    )
    artifact["events"] = [base, model, reference, test_event]
    manifest["event_count"] = len(artifact["events"])
    manifest["coverage"]["content_references"] = sum(
        "pointer" in event for event in artifact["events"]
    )
    artifact["corpus_commitment"] = corpus_commitment(manifest, artifact["events"])
    data = canonical_bytes(artifact) + b"\n"
    load_validator("normalized_corpus.schema.json").validate(artifact)
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]
