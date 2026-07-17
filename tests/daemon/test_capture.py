"""MYB-2.5: capture daemon E2E over synthetic fixtures — watch → commit → append."""

import json
import logging
import os
import re

import pytest

from mybench import commitments as c
from mybench import nonces, paths
from mybench.daemon import capture
from mybench.ledger import Ledger
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures


@pytest.fixture
def fx(tmp_path):
    return generate_fixtures(tmp_path / "fx")


@pytest.fixture
def config(fx):
    return capture.DaemonConfig(
        watches=(
            capture.WatchSpec(fx.root / "claude" / "projects", "claude-code"),
            capture.WatchSpec(fx.root / "codex" / "sessions", "codex"),
        )
    )


def session_rows(ledger):
    return {r["session_id"]: r for r in ledger.rows() if r["type"] == "session"}


def sid(config, f):
    for w in config.watches:
        if f.is_relative_to(w.path):
            return capture.session_id_for(f, w, paths.ensure_session_scope_key())
    raise AssertionError(f"{f} not under any watch")


def recomputed_root(config, session_file):
    items = capture._complete_lines(session_file.read_bytes())
    known = nonces.load_nonces(sid(config, session_file))
    leaves = [c.leaf_commitment(k, m) for k, m in zip(known, items)]
    return c.session_root(leaves).hex()


# --- E2E (AC #1) ---------------------------------------------------------------


def test_e2e_fixture_dirs_to_verified_ledger(fx, config):
    daemon = capture.Daemon(config)
    assert daemon.scan_once() == len(fx.sessions) == 3
    assert daemon.ledger.verify_chain() == 4  # genesis + one row per session
    rows = session_rows(daemon.ledger)
    for s in fx.sessions:
        row = rows[sid(config, s)]
        assert row["item_count"] == len(s.read_bytes().splitlines())
        assert row["session_root"] == recomputed_root(config, s)
        assert row["source"] == ("claude-code" if "claude" in s.parts else "codex")


def test_append_event_produces_new_row_over_all_items(fx, config):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    target = fx.sessions[0]
    before = session_rows(daemon.ledger)[sid(config, target)]["item_count"]
    with target.open("ab") as f:
        f.write(json.dumps({"type": "user", "synthetic": "appended-1"}).encode() + b"\n")
        f.write(json.dumps({"type": "user", "synthetic": "appended-2"}).encode() + b"\n")
    assert daemon.scan_once() == 1  # only the grown session gets a row
    row = session_rows(daemon.ledger)[sid(config, target)]
    assert row["item_count"] == before + 2
    assert row["session_root"] == recomputed_root(config, target)
    assert daemon.ledger.verify_chain() == 5


def test_partial_trailing_line_is_not_yet_an_item(fx, config):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    target = fx.sessions[0]
    with target.open("ab") as f:
        f.write(b'{"type": "user", "synthetic": "torn')
    assert daemon.scan_once() == 0
    with target.open("ab") as f:
        f.write(b'"}\n')
    assert daemon.scan_once() == 1


def test_nonce_file_and_parent_are_durable_before_ledger_append(
    tmp_path, monkeypatch
):
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()
    (watch_dir / "opaque.jsonl").write_bytes(
        b'{"synthetic":"first"}\n{"synthetic":"second"}\n'
    )
    cfg = capture.DaemonConfig(
        watches=(capture.WatchSpec(watch_dir, "synthetic"),)
    )
    daemon = capture.Daemon(cfg)
    events = []
    real_file_fsync = nonces._fsync_file
    real_parent_fsync = nonces._fsync_parent
    real_append_session = daemon.ledger.append_session

    def fsync_file(fd):
        events.append("nonce_file_fsync")
        real_file_fsync(fd)

    def fsync_parent(directory):
        events.append(
            "nonce_dir_fsync" if directory == paths.nonces_dir() else "data_dir_fsync"
        )
        real_parent_fsync(directory)

    def append_session(**kwargs):
        events.append("ledger_append")
        return real_append_session(**kwargs)

    monkeypatch.setattr(nonces, "_fsync_file", fsync_file)
    monkeypatch.setattr(nonces, "_fsync_parent", fsync_parent)
    monkeypatch.setattr(daemon.ledger, "append_session", append_session)
    assert daemon.scan_once() == 1

    ledger_at = events.index("ledger_append")
    assert events[:ledger_at].count("nonce_file_fsync") == 3
    assert events[:ledger_at].count("nonce_dir_fsync") == 2
    assert events[-4:] == [
        "nonce_file_fsync",
        "nonce_dir_fsync",
        "data_dir_fsync",
        "ledger_append",
    ]


def test_complete_unfsynced_orphan_nonce_is_redurabilized_before_a3(
    tmp_path, monkeypatch
):
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()
    session_file = watch_dir / "orphan.jsonl"
    session_file.write_bytes(b'{"synthetic":"orphan-complete-row"}\n')
    watch = capture.WatchSpec(watch_dir, "synthetic")
    cfg = capture.DaemonConfig(watches=(watch,))
    paths.ensure_data_dir()
    session_id = capture.session_id_for(
        session_file, watch, paths.ensure_session_scope_key()
    )
    nonce = c.generate_nonce()
    nonce_file = nonces.session_nonce_file(session_id)
    fd = os.open(nonce_file, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        row = json.dumps({"i": 0, "nonce": nonce.hex()}).encode() + b"\n"
        assert os.write(fd, row) == len(row)
        # Deliberately no file or parent fsync: restart can still see this
        # complete page-cache row, but A3 must not reference it yet.
    finally:
        os.close(fd)

    daemon = capture.Daemon(cfg)
    events = []
    real_file_fsync = nonces._fsync_file
    real_parent_fsync = nonces._fsync_parent
    real_append_session = daemon.ledger.append_session

    def fsync_file(sync_fd):
        events.append("nonce_file_fsync")
        real_file_fsync(sync_fd)

    def fsync_parent(directory):
        events.append(
            "nonce_dir_fsync" if directory == paths.nonces_dir() else "data_dir_fsync"
        )
        real_parent_fsync(directory)

    def append_session(**kwargs):
        events.append("ledger_append")
        return real_append_session(**kwargs)

    monkeypatch.setattr(nonces, "_fsync_file", fsync_file)
    monkeypatch.setattr(nonces, "_fsync_parent", fsync_parent)
    monkeypatch.setattr(daemon.ledger, "append_session", append_session)
    assert daemon.scan_once() == 1
    assert events == [
        "nonce_file_fsync",
        "nonce_dir_fsync",
        "data_dir_fsync",
        "ledger_append",
    ]
    assert nonces.load_nonces(session_id) == [nonce]
    assert daemon.ledger.verify_chain() == 2


# --- Idempotency (AC #2) ----------------------------------------------------------


def test_rescan_and_restart_append_nothing(fx, config):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    baseline = [r["h"] for r in daemon.ledger.rows()]
    assert daemon.scan_once() == 0
    restarted = capture.Daemon(config, ledger=Ledger())  # fresh instance = restart
    assert restarted.scan_once() == 0
    assert [r["h"] for r in restarted.ledger.rows()] == baseline


def test_historical_preview_is_no_write_and_import_is_idempotent(fx, config):
    paths.ensure_session_scope_key()
    daemon = capture.Daemon(config)

    def private_snapshot():
        root = paths.data_dir()
        return sorted(
            (
                path.relative_to(root).as_posix(),
                path.is_dir(),
                b"" if path.is_dir() else path.read_bytes(),
            )
            for path in root.rglob("*")
        )

    before = private_snapshot()
    assert daemon.preview_historical() == len(fx.sessions) == 3
    assert private_snapshot() == before
    assert not daemon.ledger.path.exists()

    assert daemon.scan_once(historical=True) == 3
    rows = daemon.ledger.rows()
    evidence = [row for row in rows if row["type"] != "genesis"]
    assert sum(row["type"] == "schema_version" for row in evidence) == 1
    assert all(row["schema_version"] == "3" for row in evidence)
    assert all(row["provenance"] == "IMPORTED" for row in evidence)
    baseline = daemon.ledger.path.read_bytes()

    assert daemon.preview_historical() == 0
    assert daemon.scan_once(historical=True) == 0
    assert daemon.ledger.path.read_bytes() == baseline

    target = fx.sessions[0]
    with target.open("ab") as stream:
        stream.write(b'{"synthetic":"live growth"}\n')
    assert daemon.scan_once() == 1
    live = daemon.ledger.rows()[-1]
    assert live["type"] == "session"
    assert live["schema_version"] == "2"
    assert "provenance" not in live
    assert sum(row["type"] == "schema_version" for row in daemon.ledger.rows()) == 1


def test_shrunken_source_never_rewrites_history(fx, config):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    target = fx.sessions[0]
    lines = target.read_bytes().splitlines(keepends=True)
    target.write_bytes(b"".join(lines[:1]))
    assert daemon.scan_once() == 0
    assert daemon.ledger.verify_chain() == 4


# --- Config discipline (AC #3) -----------------------------------------------------


def test_default_config_forbidden_in_test_mode():
    with pytest.raises(capture.ConfigError, match="test mode"):
        capture.default_config()


def test_config_requires_explicit_watches_and_known_sources(tmp_path):
    with pytest.raises(capture.ConfigError):
        capture.DaemonConfig(watches=())
    with pytest.raises(capture.ConfigError):
        capture.DaemonConfig(watches=(capture.WatchSpec(tmp_path, "cursor"),))
    with pytest.raises(capture.ConfigError, match="explicit boolean"):
        capture.DaemonConfig(
            watches=(capture.WatchSpec(tmp_path, "synthetic"),),
            archive_enabled="yes",  # type: ignore[arg-type]
        )


def test_missing_watch_dir_is_skipped_not_fatal(tmp_path):
    cfg = capture.DaemonConfig(watches=(capture.WatchSpec(tmp_path / "gone", "synthetic"),))
    assert capture.Daemon(cfg).scan_once() == 0


def test_bad_session_filename_does_not_stop_the_scan(fx, config):
    bad = fx.sessions[0].parent / "not a valid id!.jsonl"
    bad.write_bytes(b'{"synthetic": true}\n')
    daemon = capture.Daemon(config)
    assert daemon.scan_once() == len(fx.sessions)  # bad file skipped, rest captured
    assert daemon.ledger.verify_chain() == 1 + len(fx.sessions)


def test_same_stem_in_different_dirs_are_distinct_sessions(fx, config):
    # MYB-2.7 regression: real Claude Code nests subagent transcripts that can
    # reuse a stem across files; each file must get its own identity.
    twin_dir = fx.sessions[0].parent / "subagents"
    twin_dir.mkdir()
    twin = twin_dir / fx.sessions[0].name  # same stem, different dir, other content
    twin.write_bytes(b'{"synthetic": "twin-a"}\n{"synthetic": "twin-b"}\n')
    daemon = capture.Daemon(config)
    assert daemon.scan_once() == len(fx.sessions) + 1
    rows = session_rows(daemon.ledger)
    assert sid(config, twin) != sid(config, fx.sessions[0])
    for f in (twin, fx.sessions[0]):
        assert rows[sid(config, f)]["session_root"] == recomputed_root(config, f)


def test_session_ids_are_opaque_and_valid(fx, config):
    for s in fx.sessions:
        session_id = sid(config, s)
        assert len(session_id) <= 64
        assert nonces.session_nonce_file(session_id)  # passes the opaque-id gate
        # Exactly truncated stem + keyed 16-hex tag: structurally nothing else
        # (no directory component, however short) can appear in the id.
        assert re.fullmatch(re.escape(s.stem[:40]) + r"-[0-9a-f]{16}", session_id)


# --- Codex production wiring (MYB-12.2) ----------------------------------------


def test_production_watches_codex_exists_guard(tmp_path):
    # Without a Codex install: Claude Code only (its dir is NOT exists-guarded —
    # a missing dir must surface per-scan as missing_dir, never vanish here).
    watches = capture.production_watches(tmp_path)
    assert [(w.path, w.source) for w in watches] == [
        (tmp_path / ".claude" / "projects", "claude-code")
    ]
    # With ~/.codex/sessions present, the Codex watch appears.
    (tmp_path / ".codex" / "sessions").mkdir(parents=True)
    watches = capture.production_watches(tmp_path)
    assert [(w.path, w.source) for w in watches] == [
        (tmp_path / ".claude" / "projects", "claude-code"),
        (tmp_path / ".codex" / "sessions", "codex"),
    ]


def test_codex_nested_dates_same_stem_are_distinct_sessions(fx, config):
    # Real rollout layout nests sessions/YYYY/MM/DD; the same filename on two
    # dates must be two sessions (path-HMAC id), like the subagent-twin case.
    original = next(s for s in fx.sessions if "codex" in s.parts)
    other_day = original.parent.parent / "09"
    other_day.mkdir()
    twin = other_day / original.name
    twin.write_bytes(b'{"synthetic": "other-day-a"}\n{"synthetic": "other-day-b"}\n')
    daemon = capture.Daemon(config)
    assert daemon.scan_once() == len(fx.sessions) + 1
    rows = session_rows(daemon.ledger)
    assert sid(config, twin) != sid(config, original)
    for f in (twin, original):
        assert rows[sid(config, f)]["session_root"] == recomputed_root(config, f)


def test_binary_line_is_committed_opaquely_without_crash(fx, config):
    # Commitment capture is independent of metadata parsing: an unknown/binary
    # record (ADR-0002 §2 exact raw bytes) is never a crash or a skipped item.
    target = next(s for s in fx.sessions if "codex" in s.parts)
    daemon = capture.Daemon(config)
    daemon.scan_once()
    before = session_rows(daemon.ledger)[sid(config, target)]["item_count"]
    with target.open("ab") as f:
        f.write(b"\x00\xff\xfe not json at all \x80\n")
    assert daemon.scan_once() == 1
    row = session_rows(daemon.ledger)[sid(config, target)]
    assert row["item_count"] == before + 1
    assert row["session_root"] == recomputed_root(config, target)
    assert daemon.ledger.verify_chain() == 1 + len(fx.sessions) + 1


def test_unreadable_entry_is_counted_and_skipped(fx, config, caplog):
    # A *.jsonl path that cannot be read as a file (here: a directory) takes
    # the capture_error path — class-only log line — and the scan continues.
    trap = next(s for s in fx.sessions if "codex" in s.parts).parent / "trap.jsonl"
    trap.mkdir()
    daemon = capture.Daemon(config)
    with caplog.at_level(logging.ERROR, logger="mybench.daemon"):
        assert daemon.scan_once() == len(fx.sessions)  # every real session captured
    errors = [r for r in caplog.records if "capture_error" in r.getMessage()]
    assert len(errors) == 1
    assert "trap" not in errors[0].getMessage()  # class only, never the path
    assert daemon.ledger.verify_chain() == 1 + len(fx.sessions)


def test_symlinked_transcript_is_rejected_without_reading_target(tmp_path, caplog):
    watch_dir = tmp_path / "watch"
    outside = tmp_path / "outside"
    watch_dir.mkdir()
    outside.mkdir()
    canary = "MYBENCH-SYMLINK-TARGET-CANARY"
    target = outside / "target.jsonl"
    target.write_text(json.dumps({"synthetic": canary}) + "\n")
    (watch_dir / "linked.jsonl").symlink_to(target)
    cfg = capture.DaemonConfig(
        watches=(capture.WatchSpec(watch_dir, "synthetic"),),
        archive_enabled=True,
    )

    with caplog.at_level(logging.INFO, logger="mybench.daemon"):
        assert capture.Daemon(cfg).scan_once() == 0
    assert "event=source_symlink" in caplog.text
    assert canary not in caplog.text
    assert Ledger().rows() == []
    assert not list(paths.archive_dir().glob("*/*"))


def test_symlinked_watch_directory_is_rejected(tmp_path, caplog):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target.jsonl").write_text('{"synthetic":"outside"}\n')
    linked_watch = tmp_path / "linked-watch"
    linked_watch.symlink_to(outside, target_is_directory=True)
    cfg = capture.DaemonConfig(
        watches=(capture.WatchSpec(linked_watch, "synthetic"),),
        archive_enabled=True,
    )

    with caplog.at_level(logging.INFO, logger="mybench.daemon"):
        assert capture.Daemon(cfg).scan_once() == 0
    assert "event=watch_symlink" in caplog.text
    assert Ledger().rows() == []


# --- Leak surface (AC #4) -----------------------------------------------------------


def test_ledger_and_daemon_logs_pass_leak_scan(fx, config, tmp_path):
    logfile = tmp_path / "daemon.log"
    handler = logging.FileHandler(logfile)
    logger = logging.getLogger("mybench.daemon")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        daemon = capture.Daemon(config)
        daemon.scan_once()
        with fx.sessions[0].open("ab") as f:
            f.write(b'{"synthetic": "growth"}\n')
        daemon.scan_once()
    finally:
        logger.removeHandler(handler)
        handler.close()

    used_nonces = []
    for nf in paths.nonces_dir().glob("*.jsonl"):
        used_nonces.extend(nonces.load_nonces(nf.stem))
    assert used_nonces, "capture must have generated nonces"

    log_text = logfile.read_text()
    assert "scan complete" in log_text  # the scan is not vacuous
    for s in fx.sessions:  # logs never name watched files or dirs
        assert s.stem not in log_text
    assert str(fx.root) not in log_text

    scanned = assert_no_canaries(
        [daemon.ledger.path, logfile], fx.all_canaries() + used_nonces
    )
    assert scanned == 2

    # Companion firing test (never-vacuous rule): the same scan on the same
    # surface DOES catch a planted canary in the daemon log.
    with logfile.open("a") as f:
        f.write(fx.content_canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([logfile], fx.all_canaries())
