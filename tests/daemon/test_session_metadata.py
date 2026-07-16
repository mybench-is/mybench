"""MYB-12.5: closed Claude/Codex metadata adapters and capture integration."""

from __future__ import annotations

import json
import logging

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mybench import paths
from mybench.anchor.batch import build_batch
from mybench.anchor.event import build_event, stage_event
from mybench.daemon.capture import Daemon, DaemonConfig, WatchSpec, session_id_for
from mybench.daemon.session_metadata import extract_session_metadata
from tests.fixtures import CanaryLeakError, assert_no_canaries

TS = "2026-07-16T12:00:00Z"


def raw(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def assistant(
    *,
    model: str = "claude-synthetic-1",
    usage: dict | None = None,
    version: str = "2.1.211",
    **message_fields,
) -> bytes:
    message = {
        "role": "assistant",
        "model": model,
        "provider": "anthropic",
        "content": [{"type": "text", "text": "synthetic private reply"}],
        **message_fields,
    }
    if usage is not None:
        message["usage"] = usage
    return raw({"type": "assistant", "version": version, "message": message})


def test_claude_contract_sums_usage_and_keeps_effort_unobservable():
    records = [
        raw(
            {
                "type": "user",
                "version": "2.1.210",
                "cwd": "/synthetic/private/path",
                "message": {"role": "user", "content": "synthetic private prompt"},
            }
        ),
        assistant(
            model="claude-synthetic-z",
            usage={
                "input_tokens": 10,
                "output_tokens": 4,
                "cache_creation_input_tokens": 3,
                "cache_read_input_tokens": 2,
            },
            effort="high",
            thinking=[{"text": "synthetic private thinking"}],
        ),
        assistant(
            model="claude-synthetic-a",
            usage={"input_tokens": 0, "output_tokens": 6},
        ),
    ]
    assert extract_session_metadata("claude-code", records).ledger_fields() == {
        "models_seen": ["claude-synthetic-a", "claude-synthetic-z"],
        "provider": "anthropic",
        "input_tokens": 10,
        "output_tokens": 10,
        "cache_creation_input_tokens": 3,
        "cache_read_input_tokens": 2,
        "harness_version": "2.1.211",
    }


def test_claude_missing_or_malformed_usage_is_unknown_not_zero():
    missing = extract_session_metadata(
        "claude-code", [assistant(usage=None, effort="xhigh")]
    ).ledger_fields()
    assert missing == {
        "models_seen": ["claude-synthetic-1"],
        "provider": "anthropic",
        "harness_version": "2.1.211",
    }
    malformed = extract_session_metadata(
        "claude-code",
        [assistant(usage={"input_tokens": 5, "output_tokens": "synthetic-invalid"})],
    ).ledger_fields()
    assert set(malformed).isdisjoint(
        {"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"}
    )


def codex_record(record_type: str, payload: dict) -> bytes:
    return raw({"timestamp": TS, "type": record_type, "payload": payload})


def test_codex_contract_uses_latest_cumulative_snapshot_without_double_counting():
    records = [
        codex_record(
            "session_meta",
            {
                "cli_version": "0.144.4",
                "model_provider": "openai",
                "cwd": "/synthetic/private/path",
                "base_instructions": {"text": "synthetic private instructions"},
            },
        ),
        codex_record(
            "turn_context",
            {"model": "gpt-5-codex", "effort": "high", "summary": "synthetic private"},
        ),
        codex_record(
            "event_msg",
            {
                "type": "token_count",
                "info": {
                    "total_token_usage": {
                        "input_tokens": 10,
                        "cached_input_tokens": 2,
                        "output_tokens": 3,
                        "reasoning_output_tokens": 1,
                        "total_tokens": 13,
                    },
                    "last_token_usage": {
                        "input_tokens": 10,
                        "cached_input_tokens": 2,
                        "output_tokens": 3,
                    },
                },
            },
        ),
        codex_record(
            "event_msg",
            {
                "type": "thread_settings_applied",
                "thread_settings": {
                    "model": "gpt-5-codex-max",
                    "model_provider_id": "openai",
                    "reasoning_effort": "xhigh",
                    "cwd": "/synthetic/private/other",
                },
            },
        ),
        codex_record(
            "event_msg",
            {
                "type": "token_count",
                "info": {
                    "total_token_usage": {
                        "input_tokens": 18,
                        "cached_input_tokens": 5,
                        "output_tokens": 7,
                    },
                    "last_token_usage": {
                        "input_tokens": 8,
                        "cached_input_tokens": 3,
                        "output_tokens": 4,
                    },
                },
            },
        ),
    ]
    assert extract_session_metadata("codex", records).ledger_fields() == {
        "models_seen": ["gpt-5-codex", "gpt-5-codex-max"],
        "provider": "openai",
        "effort": "xhigh",
        "input_tokens": 18,
        "output_tokens": 7,
        "cache_read_input_tokens": 5,
        "harness_version": "0.144.4",
    }


def test_codex_missing_effort_and_usage_are_absent_not_guessed():
    fields = extract_session_metadata(
        "codex",
        [
            codex_record(
                "session_meta", {"cli_version": "0.144.4", "model_provider": "openai"}
            ),
            codex_record("turn_context", {"model": "gpt-5-codex"}),
        ],
    ).ledger_fields()
    assert fields == {
        "models_seen": ["gpt-5-codex"],
        "provider": "openai",
        "harness_version": "0.144.4",
    }


@settings(max_examples=80, deadline=None)
@given(
    content=st.text(max_size=200),
    path=st.text(max_size=120),
    unknown=st.dictionaries(
        st.text(min_size=1, max_size=20),
        st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=80)),
        max_size=8,
    ),
)
def test_non_whitelisted_claude_bytes_cannot_influence_metadata(content, path, unknown):
    baseline = {
        "type": "assistant",
        "version": "2.1.211",
        "message": {
            "role": "assistant",
            "model": "claude-synthetic-1",
            "provider": "synthetic",
            "usage": {"input_tokens": 3, "output_tokens": 2},
        },
    }
    varied = {
        **baseline,
        "cwd": path,
        "unknown": unknown,
        "message": {
            **baseline["message"],
            "content": [{"type": "text", "text": content}],
            "thinking": content,
            "tool_result": {"path": path, "value": unknown},
        },
    }
    assert raw(varied) != raw(baseline) or not (content or path or unknown)
    assert extract_session_metadata("claude-code", [raw(varied)]) == (
        extract_session_metadata("claude-code", [raw(baseline)])
    )


@settings(max_examples=80, deadline=None)
@given(content=st.text(max_size=200), path=st.text(max_size=120))
def test_non_whitelisted_codex_bytes_cannot_influence_metadata(content, path):
    baseline = [
        codex_record(
            "session_meta", {"cli_version": "0.144.4", "model_provider": "openai"}
        ),
        codex_record("turn_context", {"model": "gpt-5-codex", "effort": "high"}),
        codex_record(
            "event_msg",
            {
                "type": "token_count",
                "info": {
                    "total_token_usage": {
                        "input_tokens": 8,
                        "cached_input_tokens": 2,
                        "output_tokens": 3,
                    }
                },
            },
        ),
    ]
    varied = [
        raw(
            {
                **json.loads(record),
                "private": content,
                "payload": {
                    **json.loads(record)["payload"],
                    "cwd": path,
                    "content": content,
                    "tool_result": {"path": path, "output": content},
                },
            }
        )
        for record in baseline
    ]
    assert extract_session_metadata("codex", varied) == extract_session_metadata(
        "codex", baseline
    )


def test_grown_session_appends_one_latest_complete_prefix_observation(tmp_path):
    watch_dir = tmp_path / "synthetic-claude-watch"
    watch_dir.mkdir()
    transcript = watch_dir / "00000000-0000-4000-8000-000000000125.jsonl"
    transcript.write_bytes(
        assistant(
            model="claude-synthetic-a",
            usage={"input_tokens": 5, "output_tokens": 2},
            version="2.1.210",
        )
        + b"\n"
    )
    watch = WatchSpec(watch_dir, "claude-code")
    daemon = Daemon(DaemonConfig(watches=(watch,)))
    session_id = session_id_for(transcript, watch, paths.ensure_session_scope_key())

    assert daemon.scan_once() == 1
    assert daemon.scan_once() == 0
    transcript.write_bytes(
        transcript.read_bytes()
        + assistant(
            model="claude-synthetic-b",
            usage={"input_tokens": 7, "output_tokens": 4},
            version="2.1.211",
        )
        + b"\n"
    )
    assert daemon.scan_once() == 1
    assert daemon.scan_once() == 0

    rows = [
        row
        for row in daemon.ledger.rows()
        if row["type"] == "session" and row["session_id"] == session_id
    ]
    assert [row["item_count"] for row in rows] == [1, 2]
    assert rows[-1]["models_seen"] == ["claude-synthetic-a", "claude-synthetic-b"]
    assert rows[-1]["input_tokens"] == 12
    assert rows[-1]["output_tokens"] == 6
    assert rows[-1]["harness_version"] == "2.1.211"
    assert len({row["item_count"] for row in rows}) == len(rows)
    assert daemon.ledger.verify_chain() == 3


def test_metadata_canaries_reach_no_ledger_log_or_anchor_staging(tmp_path, caplog):
    canaries = (
        b"MYBENCH-CANARY-metadata-content-61a8",
        b"MYBENCH-CANARY-metadata-filename-4c2e.py",
        b"MYBENCH-CANARY-metadata-path-809f",
        b"MYBENCH-CANARY-metadata-result-77d1",
    )
    watch_dir = tmp_path / "synthetic-codex-watch"
    watch_dir.mkdir()
    transcript = watch_dir / "00000000-0000-4000-8000-000000000126.jsonl"
    records = [
        codex_record(
            "session_meta",
            {
                "cli_version": "0.144.4",
                "model_provider": "openai",
                "cwd": "/synthetic/" + canaries[2].decode(),
                "base_instructions": {"text": canaries[0].decode()},
            },
        ),
        codex_record(
            "turn_context",
            {
                "model": "gpt-5-codex",
                "effort": "high",
                "cwd": "/synthetic/" + canaries[1].decode(),
            },
        ),
        codex_record(
            "response_item",
            {
                "type": "function_call_output",
                "output": canaries[3].decode(),
                "content": canaries[0].decode(),
            },
        ),
    ]
    transcript.write_bytes(b"\n".join(records) + b"\n")
    caplog.set_level(logging.INFO, logger="mybench.daemon")
    daemon = Daemon(DaemonConfig(watches=(WatchSpec(watch_dir, "codex"),)))
    assert daemon.scan_once() == 1

    event = build_event(build_batch(daemon.ledger), daemon.ledger.rows(), date="2026-07-16")
    stage_event(event, b"synthetic-pending-proof", paths.anchors_dir())
    log_path = tmp_path / "synthetic-daemon.log"
    log_path.write_text(caplog.text)
    assert assert_no_canaries(
        [daemon.ledger.path, log_path, paths.anchors_dir()], list(canaries)
    ) >= 4


def test_metadata_canary_scanner_companion_fires():
    marker = b"MYBENCH-CANARY-metadata-firing-3b0e"
    paths.ensure_data_dir()
    planted = paths.anchors_dir() / "synthetic-metadata-canary"
    planted.write_bytes(marker)
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([paths.anchors_dir()], [marker])
