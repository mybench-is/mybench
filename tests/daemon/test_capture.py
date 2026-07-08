"""MYB-2.5: capture daemon E2E over synthetic fixtures — watch → commit → append."""

import json
import logging

import pytest

from mybench import commitments as c
from mybench import nonces, paths
from mybench.daemon import capture
from mybench.ledger import Ledger
from tests.fixtures import assert_no_canaries, generate_fixtures


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


# --- Idempotency (AC #2) ----------------------------------------------------------


def test_rescan_and_restart_append_nothing(fx, config):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    baseline = [r["h"] for r in daemon.ledger.rows()]
    assert daemon.scan_once() == 0
    restarted = capture.Daemon(config, ledger=Ledger())  # fresh instance = restart
    assert restarted.scan_once() == 0
    assert [r["h"] for r in restarted.ledger.rows()] == baseline


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
        # No readable path component beyond the stem itself leaks into the id.
        assert s.parent.name not in session_id


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
