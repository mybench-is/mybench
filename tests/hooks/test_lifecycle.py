"""MYB-12.4: synthetic Claude lifecycle hooks → queue → schema-v2 A3 rows."""

from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from mybench import paths
from mybench.daemon import capture
from mybench.hooks import lifecycle
from mybench.hooks.__main__ import main as hooks_cli
from mybench.ledger import Ledger, TornTailError
from tests.fixtures import CanaryLeakError, assert_no_canaries

TS = "2026-07-15T20:00:00Z"
SCOPE_KEY = bytes.fromhex("11" * 32)


def _watch(tmp_path: Path) -> Path:
    watch = tmp_path / "synthetic-home" / ".claude" / "projects"
    watch.mkdir(parents=True)
    return watch


def _transcript(watch: Path, name: str, project: str = "synthetic-project") -> Path:
    path = watch / project / f"{name}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _payload(event: str, transcript: Path, **fields) -> dict:
    return {
        "session_id": "raw-claude-id-must-not-be-stored",
        "transcript_path": str(transcript),
        "cwd": "/synthetic/raw/cwd/must/not/be/stored",
        "hook_event_name": event,
        **fields,
    }


def _record(event: str, trigger: str, session_id: str, ts: str = TS) -> dict:
    return {
        "queue_version": "1",
        "ts": ts,
        "event_kind": event,
        "trigger": trigger,
        "session_id": session_id,
        "harness": "claude-code",
    }


def _event_rows() -> list[dict]:
    return [row for row in Ledger().rows() if row["type"] == "event"]


# --- Closed payload map + E2E/idempotency (AC #1) ---------------------------------


def test_all_pinned_lifecycle_observations_append_exactly_once(tmp_path):
    paths.ensure_data_dir()
    watch = _watch(tmp_path)
    cases = [
        ("SessionStart", {"source": "startup"}, "session_start", "startup"),
        ("SessionStart", {"source": "resume"}, "session_start", "resume"),
        ("SessionStart", {"source": "clear"}, "session_start", "clear"),
        ("SessionStart", {"source": "compact"}, "session_start", "compact"),
        ("SessionEnd", {"reason": "logout"}, "session_end", "unknown"),
        ("PreCompact", {"trigger": "manual"}, "compact_pre", "manual"),
        ("PreCompact", {"trigger": "auto"}, "compact_pre", "auto"),
    ]
    for index, (hook_event, fields, _kind, _trigger) in enumerate(cases):
        transcript = _transcript(watch, f"00000000-0000-4000-8000-{index:012d}")
        ts = f"2026-07-15T20:00:{index:02d}Z"
        payload = _payload(hook_event, transcript, **fields)
        assert lifecycle.handle_payload(
            payload,
            watch_root=watch,
            scope_key=SCOPE_KEY,
            now=lambda ts=ts: ts,
        ) == 0
        # A repeated hook delivery writes the same tuple; scan-time replay is idempotent.
        assert lifecycle.handle_payload(
            payload,
            watch_root=watch,
            scope_key=SCOPE_KEY,
            now=lambda ts=ts: ts,
        ) == 0

    assert lifecycle.flush_queue() == len(cases)
    assert lifecycle.flush_queue() == 0
    assert Ledger().verify_chain() == len(cases) + 1
    rows = _event_rows()
    assert [(row["event_kind"], row["trigger"]) for row in rows] == [
        (kind, trigger) for _event, _fields, kind, trigger in cases
    ]
    assert all(row["schema_version"] == "2" for row in rows)
    assert all(row["harness"] == "claude-code" for row in rows)


def test_context_generations_increment_only_at_observed_compaction(tmp_path):
    paths.ensure_data_dir()
    watch = _watch(tmp_path)
    transcript = _transcript(watch, "11111111-1111-4111-8111-111111111111")
    sequence = [
        ("SessionStart", {"source": "startup"}),
        ("PreCompact", {"trigger": "manual"}),
        ("SessionStart", {"source": "compact"}),
        ("SessionEnd", {"reason": "other"}),
        ("PreCompact", {"trigger": "auto"}),
        ("SessionStart", {"source": "compact"}),
    ]
    for index, (event, fields) in enumerate(sequence):
        ts = f"2026-07-15T21:00:{index:02d}Z"
        lifecycle.handle_payload(
            _payload(event, transcript, **fields),
            watch_root=watch,
            scope_key=SCOPE_KEY,
            now=lambda ts=ts: ts,
        )
    assert lifecycle.flush_queue() == len(sequence)
    assert [row["context_gen"] for row in _event_rows()] == [0, 1, 1, 1, 2, 2]


def test_unknown_extra_fields_are_dropped_and_new_enum_values_become_unknown(tmp_path):
    paths.ensure_data_dir()
    watch = _watch(tmp_path)
    transcript = _transcript(watch, "22222222-2222-4222-8222-222222222222")
    payload = _payload(
        "SessionStart",
        transcript,
        source="future-source",
        model="model-field-is-owned-by-MYB-12.5",
        prompt="prompt-field-must-never-be-stored",
    )
    event = lifecycle.extract_event(
        payload,
        watch_root=watch,
        scope_key=SCOPE_KEY,
        observed_ts=TS,
    )
    assert event == _record("session_start", "unknown", event["session_id"])


# --- Shared identity + scan integration (AC #2) ------------------------------------


def test_lifecycle_and_file_capture_join_on_the_same_opaque_session_id(tmp_path):
    paths.ensure_data_dir()
    watch_root = _watch(tmp_path)
    transcript = _transcript(watch_root, "33333333-3333-4333-8333-333333333333")
    transcript.write_bytes(b'{"synthetic":"session-record"}\n')
    scope_key = paths.ensure_session_scope_key()
    lifecycle.handle_payload(
        _payload("SessionStart", transcript, source="startup"),
        watch_root=watch_root,
        scope_key=scope_key,
        now=lambda: TS,
    )
    watch = capture.WatchSpec(watch_root, "claude-code")
    daemon = capture.Daemon(capture.DaemonConfig(watches=(watch,)))
    assert daemon.scan_once() == 2  # one queued lifecycle row + one session row
    rows = daemon.ledger.rows()
    event = next(row for row in rows if row["type"] == "event")
    session = next(row for row in rows if row["type"] == "session")
    assert event["session_id"] == session["session_id"]
    assert event["session_id"] == capture.session_id_for(transcript, watch, scope_key)
    assert daemon.ledger.verify_chain() == 3


# --- Non-blocking failure boundary (AC #3) -----------------------------------------


def test_missing_data_dir_is_a_silent_noop(tmp_path):
    watch = _watch(tmp_path)
    transcript = _transcript(watch, "44444444-4444-4444-8444-444444444444")
    assert not paths.data_dir().exists()
    assert lifecycle.handle_payload(
        _payload("SessionStart", transcript, source="startup"),
        watch_root=watch,
        scope_key=SCOPE_KEY,
        now=lambda: TS,
    ) == 0
    assert not paths.data_dir().exists()


def test_adapter_errors_are_swallowed_counted_and_class_only_logged(
    tmp_path, monkeypatch
):
    paths.ensure_data_dir()
    watch = _watch(tmp_path)
    transcript = _transcript(watch, "55555555-5555-4555-8555-555555555555")

    class SyntheticQueueFailure(RuntimeError):
        pass

    def fail(_record):
        raise SyntheticQueueFailure("MYBENCH-CANARY-message-never-log-this-path")

    monkeypatch.setattr(lifecycle, "enqueue_event", fail)
    assert lifecycle.handle_payload(
        _payload("SessionStart", transcript, source="startup"),
        watch_root=watch,
        scope_key=SCOPE_KEY,
        now=lambda: TS,
    ) == 0
    assert paths.claude_lifecycle_failure_path().read_text() == "1\n"
    hook_log = paths.data_dir() / "hooks.log"
    assert "SyntheticQueueFailure" in hook_log.read_text()
    assert "MYBENCH-CANARY" not in hook_log.read_text()
    assert str(transcript) not in hook_log.read_text()


def test_installed_handler_is_async_and_timeout_bounded(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    assert lifecycle.install(settings, python_executable="/synthetic/python") == lifecycle.HOOK_EVENTS
    installed = json.loads(settings.read_text())
    for event in lifecycle.HOOK_EVENTS:
        handler = installed["hooks"][event][0]["hooks"][0]
        assert handler == {
            "type": "command",
            "command": "/synthetic/python",
            "args": list(lifecycle.HOOK_ARGS),
            "async": True,
            "timeout": 1,
        }


def test_malformed_stdin_never_emits_or_raises(capsys):
    paths.ensure_data_dir()
    assert lifecycle.run_from_stdin(io.BytesIO(b"not-json-and-never-persisted")) == 0
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert paths.claude_lifecycle_failure_path().read_text() == "1\n"


# --- Leak scan + firing companion (AC #4/#5) --------------------------------------


def test_payload_canaries_reach_no_queue_row_log_or_anchor_staging(tmp_path):
    paths.ensure_data_dir()
    canaries = [
        b"MYBENCH-CANARY-secret-01234567",
        b"MYBENCH-CANARY-path-89abcdef",
        b"MYBENCH-CANARY-prompt-fedcba98",
        b"MYBENCH-CANARY-raw-session-76543210",
    ]
    watch = _watch(tmp_path)
    transcript = _transcript(
        watch,
        "66666666-6666-4666-8666-666666666666",
        project=canaries[1].decode(),
    )
    payload = {
        "session_id": canaries[3].decode(),
        "transcript_path": str(transcript),
        "cwd": f"/synthetic/{canaries[1].decode()}",
        "hook_event_name": "PreCompact",
        "trigger": "manual",
        "custom_instructions": canaries[2].decode(),
        "future_secret": canaries[0].decode(),
    }
    lifecycle.handle_payload(
        payload,
        watch_root=watch,
        scope_key=SCOPE_KEY,
        now=lambda: TS,
    )
    assert lifecycle.flush_queue() == 1
    rows = _event_rows()
    assert set(rows[0]) == {
        "schema_version",
        "i",
        "type",
        "ts",
        "prev",
        "h",
        "event_kind",
        "trigger",
        "session_id",
        "context_gen",
        "harness",
    }
    targets = [paths.claude_lifecycle_queue_path(), Ledger().path, paths.anchors_dir()]
    hook_log = paths.data_dir() / "hooks.log"
    if hook_log.exists():
        targets.append(hook_log)
    assert assert_no_canaries(targets, canaries) >= 2


def test_canary_scanner_companion_fires_on_a_planted_marker():
    paths.ensure_data_dir()
    marker = b"MYBENCH-CANARY-firing-a1b2c3d4"
    planted = paths.anchors_dir() / "synthetic-planted-canary"
    planted.write_bytes(marker)
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([paths.anchors_dir()], [marker])


# --- Queue recovery + install reversibility (AC #6/#7) -----------------------------


def test_install_uninstall_is_idempotent_reversible_and_user_config_only(tmp_path):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = claude_dir / "settings.json"
    original = {
        "cleanupPeriodDays": 30,
        "hooks": {
            "SessionStart": [
                {
                    "matcher": "startup",
                    "hooks": [
                        {"type": "command", "command": "/synthetic/existing-hook"}
                    ],
                }
            ]
        },
    }
    settings.write_text(json.dumps(original))
    before_files = {path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file()}
    assert lifecycle.install(settings, python_executable="/synthetic/python") == lifecycle.HOOK_EVENTS
    installed_bytes = settings.read_bytes()
    assert lifecycle.install(settings, python_executable="/different/python") == ()
    assert settings.read_bytes() == installed_bytes
    assert lifecycle.uninstall(settings) == lifecycle.HOOK_EVENTS
    assert json.loads(settings.read_text()) == original
    assert stat.S_IMODE(settings.stat().st_mode) == 0o600
    after_files = {path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file()}
    assert after_files == before_files == {Path(".claude/settings.json")}
    assert not paths.data_dir().exists()  # install never activates capture or publication


def test_lifecycle_cli_reports_the_exact_user_settings_delta(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text("{}\n")
    assert hooks_cli(["lifecycle", "install"]) == 0
    assert capsys.readouterr().out == (
        f"installed SessionStart, SessionEnd, PreCompact in {settings}\n"
    )
    assert hooks_cli(["lifecycle", "uninstall"]) == 0
    assert capsys.readouterr().out == (
        f"uninstalled SessionStart, SessionEnd, PreCompact in {settings}\n"
    )


def test_partial_queue_tail_is_preserved_and_never_corrupts_the_ledger():
    paths.ensure_data_dir()
    queue_path = paths.claude_lifecycle_queue_path()
    first = _record("session_start", "startup", "synthetic-queue-a")
    second = _record(
        "session_end",
        "unknown",
        "synthetic-queue-b",
        ts="2026-07-15T20:00:01Z",
    )
    first_line = json.dumps(first, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    second_line = json.dumps(second, sort_keys=True, separators=(",", ":")).encode()
    queue_path.write_bytes(first_line + second_line[:-5])
    queue_path.chmod(0o600)
    assert lifecycle.flush_queue() == 1
    assert queue_path.read_bytes() == second_line[:-5]
    with queue_path.open("ab") as queue:
        queue.write(second_line[-5:] + b"\n")
    assert lifecycle.flush_queue() == 1
    assert Ledger().verify_chain() == 3


def test_sigkill_during_event_append_replays_to_a_recoverable_chain(tmp_path):
    paths.ensure_data_dir()
    lifecycle.enqueue_event(
        _record("session_start", "startup", "synthetic-crash-session")
    )
    env = dict(
        os.environ,
        PYTHONPATH=str(Path(__file__).resolve().parents[2] / "src"),
        MYBENCH_FAULT_ROW="1",
    )
    proc = subprocess.run(
        [sys.executable, "-c", "from mybench.hooks.lifecycle import flush_queue; flush_queue()"],
        env=env,
        capture_output=True,
        check=False,
    )
    assert proc.returncode < 0
    ledger = Ledger()
    with pytest.raises(TornTailError):
        ledger.verify_chain()
    assert ledger.recover() > 0
    assert lifecycle.flush_queue(ledger) == 1
    assert ledger.verify_chain() == 2
    assert [row["type"] for row in ledger.rows()] == ["genesis", "event"]
