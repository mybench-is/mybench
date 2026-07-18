"""MYB-19.11 exact forge classifier, result join, and privacy boundary."""

from __future__ import annotations

import json

import pytest
from jsonschema import ValidationError

from mybench.claims.canonical import canonical_bytes
from mybench.commitments import leaf_commitment, session_root
from mybench.normalizer import (
    FORGE_ACTION_CLASSIFIER_VERSION,
    classify_forge_invocation,
    normalize_claude,
    normalize_codex,
    validate_corpus_artifact,
)
from mybench.normalizer.claude import (
    NormalizationError,
    VerifiedRecord,
    VerifiedSession,
    corpus_commitment,
)
from mybench.schemas import load_validator
from tests.fixtures import CanaryLeakError, assert_no_canaries

TITLE_CANARY = "MYBENCH-FORGE-TITLE-CANARY-2fa1"
BODY_CANARY = "MYBENCH-FORGE-BODY-CANARY-70b4"
REVIEW_CANARY = "MYBENCH-FORGE-REVIEW-CANARY-a913"
RUNG_TWO_CANARY = "https://synthetic.invalid/private/pull/7310"
MERGE_CANARY = "MYBENCH-FORGE-MERGE-CONFIRMATION-CANARY-90ce"
REPO_ID = "ab" * 8


def _record(index: int, value: dict, *, salt: int) -> tuple[VerifiedRecord, bytes]:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    nonce = bytes([salt]) * 32
    commitment = leaf_commitment(nonce, raw)
    return VerifiedRecord(index, raw, commitment.hex(), "subject"), commitment


def _claude_session(
    result_content: str | None = None,
    *,
    result_error: bool | None = False,
    repo_id: str | None = REPO_ID,
) -> VerifiedSession:
    command = f'gh pr create --title "{TITLE_CANARY}" --body "{BODY_CANARY}"'
    values = [
        {
            "isSidechain": False,
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "synthetic-forge-call",
                        "name": "Bash",
                        "input": {"command": command},
                    }
                ],
            },
            "parentUuid": None,
            "sessionId": "synthetic-raw-forge-session",
            "type": "assistant",
            "uuid": "synthetic-forge-uuid-0",
        }
    ]
    if result_content is not None:
        values.append(
            {
                "isSidechain": False,
                "message": {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "synthetic-forge-call",
                            "content": result_content,
                            "is_error": result_error,
                        }
                    ],
                },
                "parentUuid": "synthetic-forge-uuid-0",
                "sessionId": "synthetic-raw-forge-session",
                "type": "user",
                "uuid": "synthetic-forge-uuid-1",
            }
        )
    records_and_commitments = [
        _record(index, value, salt=index + 31) for index, value in enumerate(values)
    ]
    records = tuple(item[0] for item in records_and_commitments)
    commitments = [item[1] for item in records_and_commitments]
    return VerifiedSession(
        source="claude-code",
        session_id="opaque-forge-session",
        session_root=session_root(commitments).hex(),
        records=records,
        subject_owned=True,
        repo_id=repo_id,
    )


def _codex_session() -> VerifiedSession:
    values = [
        {
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "mcp__github__merge_pull_request",
                "arguments": json.dumps(
                    {"owner": "synthetic", "repo": "fixture", "pull_number": 7},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "call_id": "synthetic-mcp-forge-call",
            },
        },
        {
            "type": "response_item",
            "payload": {
                "type": "function_call_output",
                "call_id": "synthetic-mcp-forge-call",
                "status": "failed",
                "output": f"{MERGE_CANARY} {RUNG_TWO_CANARY}",
            },
        },
    ]
    records_and_commitments = [
        _record(index, value, salt=index + 41) for index, value in enumerate(values)
    ]
    return VerifiedSession(
        source="codex",
        session_id="opaque-codex-forge",
        session_root=session_root([item[1] for item in records_and_commitments]).hex(),
        records=tuple(item[0] for item in records_and_commitments),
        subject_owned=True,
        repo_id=REPO_ID,
    )


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "expected"),
    [
        ("Bash", {"command": "gh pr create --draft"}, "pr-open"),
        ("exec_command", {"cmd": "gh pr comment 7 --body synthetic"}, "pr-comment"),
        ("bash", {"command": "gh pr edit 7 --add-reviewer synthetic"}, "pr-review-request"),
        ("shell", {"command": "gh pr merge 7 --merge"}, "pr-merge-attempt"),
        ("bash", {"command": "git push origin synthetic"}, "push"),
        ("bash", {"command": "gh pr view 7"}, "other"),
        ("mcp__github__create_pull_request", {}, "pr-open"),
        ("mcp__github__add_pull_request_comment", {}, "pr-comment"),
        ("mcp__github__request_pull_request_review", {}, "pr-review-request"),
        ("mcp__github__merge_pull_request", {}, "pr-merge-attempt"),
        ("mcp__github__push_files", {}, "push"),
    ],
)
def test_pinned_exact_rules_recognize_cli_and_github_mcp(tool_name, tool_input, expected):
    assert classify_forge_invocation(tool_name, tool_input) == {
        "classification": "forge-action",
        "classifier_version": FORGE_ACTION_CLASSIFIER_VERSION,
        "forge_action_kind": expected,
    }


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("bash", {"command": "please gh pr create"}),
        ("bash", {"command": "git pushy origin synthetic"}),
        ("mcp__github__create_pull_request_extra", {}),
        ("read_file", {"path": "gh pr create"}),
        (None, {"command": "gh pr create"}),
    ],
)
def test_unknown_is_versioned_and_never_fuzzy(tool_name, tool_input):
    assert classify_forge_invocation(tool_name, tool_input) == {
        "classification": "unknown",
        "classifier_version": FORGE_ACTION_CLASSIFIER_VERSION,
    }


def test_claude_forge_event_is_pointer_only_and_joins_existing_result_status(tmp_path):
    result = f"{REVIEW_CANARY} {RUNG_TWO_CANARY} {MERGE_CANARY}"
    data = normalize_claude((_claude_session(result),))
    artifact = json.loads(data)
    forge = next(event for event in artifact["events"] if event["event_kind"] == "forge-action")
    tool_call = next(event for event in artifact["events"] if event["event_kind"] == "tool-call")

    assert forge == {
        "schema_version": "5",
        "kind": "normalized-event",
        "source": "claude-code",
        "session_id": "opaque-forge-session",
        "record_index": 0,
        "subevent_index": 1,
        "event_kind": "forge-action",
        "authorship": "agent-turn",
        "parent_link": {"status": "root"},
        "forge_action_kind": "pr-open",
        "classifier_version": FORGE_ACTION_CLASSIFIER_VERSION,
        "outcome": "success",
        "repo_id": REPO_ID,
        "pointer": tool_call["pointer"],
        "tool_relation": {"status": "linked", "record_index": 0, "subevent_index": 0},
    }
    load_validator("normalized_corpus.schema.json").validate(artifact)
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]

    output = tmp_path / "forge-artifact.json"
    output.write_bytes(data)
    canaries = [TITLE_CANARY, BODY_CANARY, REVIEW_CANARY, RUNG_TWO_CANARY, MERGE_CANARY]
    assert assert_no_canaries([output], [value.encode() for value in canaries]) == 1


def test_codex_github_mcp_signature_emits_error_without_tool_result_content():
    data = normalize_codex((_codex_session(),))
    artifact = json.loads(data)
    forge = next(event for event in artifact["events"] if event["event_kind"] == "forge-action")
    assert forge["forge_action_kind"] == "pr-merge-attempt"
    assert forge["outcome"] == "error"
    assert forge["repo_id"] == REPO_ID
    assert MERGE_CANARY.encode() not in data
    assert RUNG_TWO_CANARY.encode() not in data
    assert validate_corpus_artifact(data) == artifact["corpus_commitment"]


def test_core_validator_recomputes_forge_outcome_from_normalized_result_status():
    artifact = json.loads(normalize_claude((_claude_session("synthetic result"),)))
    forge = next(event for event in artifact["events"] if event["event_kind"] == "forge-action")
    forge["outcome"] = "error"
    artifact["corpus_commitment"] = corpus_commitment(artifact["manifest"], artifact["events"])
    with pytest.raises(NormalizationError, match="forge outcome is inconsistent"):
        validate_corpus_artifact(canonical_bytes(artifact) + b"\n")


def test_preexisting_session_rederives_event_with_honest_absent_markers():
    data = normalize_claude((_claude_session(None, repo_id=None),))
    forge = next(
        event for event in json.loads(data)["events"] if event["event_kind"] == "forge-action"
    )
    assert forge["outcome"] == "unknown"
    assert "repo_id" not in forge
    assert set(forge).isdisjoint(
        {"pull_request_id", "pull_request_url", "merge_confirmed", "tool_result"}
    )


def test_rung_two_tool_result_bytes_are_structurally_invisible_and_oq61_gated():
    first = RUNG_TWO_CANARY + " " + MERGE_CANARY
    second = "x" * len(first)
    assert normalize_claude((_claude_session(first),)) == normalize_claude(
        (_claude_session(second),)
    )

    artifact = json.loads(normalize_claude((_claude_session(first),)))
    forge = next(event for event in artifact["events"] if event["event_kind"] == "forge-action")
    forge["merge_confirmed"] = True
    artifact["corpus_commitment"] = corpus_commitment(artifact["manifest"], artifact["events"])
    data = canonical_bytes(artifact) + b"\n"
    with pytest.raises(ValidationError):
        load_validator("normalized_corpus.schema.json").validate(artifact)
    with pytest.raises(NormalizationError, match="fields from another event kind"):
        validate_corpus_artifact(data)


def test_forge_leak_scan_companion_fires_when_canary_is_planted(tmp_path):
    planted = tmp_path / "forge-planted.json"
    planted.write_text(TITLE_CANARY)
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], [TITLE_CANARY.encode()])
