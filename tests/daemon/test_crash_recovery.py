"""MYB-2.6: kill the daemon mid-write; the ledger must survive, recover, resume."""

import json
import fcntl
import os
import random
import signal
import stat
import subprocess
import sys
import time

import pytest

from mybench import archive as archive_store
from mybench import commitments as c
from mybench import ledger as ledger_store
from mybench import nonces, paths
from mybench.daemon import capture
from mybench.ledger import Ledger, LedgerError, TornTailError
from tests.fixtures import assert_no_canaries, generate_fixtures

TIMEOUT = 30


@pytest.fixture
def fx(tmp_path):
    return generate_fixtures(tmp_path / "fx")


@pytest.fixture
def config(fx):
    return capture.DaemonConfig(
        watches=(
            capture.WatchSpec(fx.root / "claude" / "projects", "claude-code"),
            capture.WatchSpec(fx.root / "codex" / "sessions", "codex"),
        ),
        archive_enabled=True,
    )


def daemon_cmd(fx, *extra):
    return [
        sys.executable,
        "-m",
        "mybench.daemon",
        "--watch",
        f"{fx.root / 'claude' / 'projects'}:claude-code",
        "--watch",
        f"{fx.root / 'codex' / 'sessions'}:codex",
        "--archive",
        *extra,
    ]


def sid(config, f):
    for w in config.watches:
        if f.is_relative_to(w.path):
            return capture.session_id_for(f, w, paths.ensure_session_scope_key())
    raise AssertionError(f"{f} not under any watch")


def archive_path(config, f):
    watch = next(w for w in config.watches if f.is_relative_to(w.path))
    return paths.archive_session_path(watch.source, sid(config, f))


def assert_matches_ground_truth(ledger, fx, config):
    rows = [r for r in ledger.rows() if r["type"] == "session"]
    latest = {}
    for r in rows:
        latest[r["session_id"]] = r
    assert set(latest) == {sid(config, s) for s in fx.sessions}
    for s in fx.sessions:
        items = capture._complete_lines(s.read_bytes())
        row = latest[sid(config, s)]
        assert row["item_count"] == len(items)
        known = nonces.load_nonces(sid(config, s))
        assert len(known) == len(items)  # no gaps, no over-commitment
        leaves = [c.leaf_commitment(k, m) for k, m in zip(known, items)]
        assert row["session_root"] == c.session_root(leaves).hex()


def assert_archives_match_ground_truth(fx, config):
    for session_file in fx.sessions:
        expected = b"".join(
            item + b"\n" for item in capture._complete_lines(session_file.read_bytes())
        )
        archived = archive_path(config, session_file)
        assert archived.read_bytes() == expected
        assert stat.S_IMODE(archived.stat().st_mode) == 0o600


# --- Deterministic fault injection (AC #1, #3) ------------------------------------


@pytest.mark.parametrize("fault_row", [0, 2], ids=["torn-genesis", "torn-after-acks"])
def test_sigkill_exactly_mid_append_then_recover_and_resume(fx, config, tmp_path, fault_row):
    env = dict(os.environ, MYBENCH_FAULT_ROW=str(fault_row))
    with (tmp_path / "daemon.log").open("ab") as logf:
        proc = subprocess.run(
            daemon_cmd(fx, "--once"), env=env, stderr=logf, timeout=TIMEOUT
        )
    assert proc.returncode == -signal.SIGKILL

    ledger = Ledger()
    with pytest.raises(TornTailError):
        ledger.rows()  # the torn tail is really there
    acknowledged = fault_row  # rows fully written (and fsynced) before the fault
    quarantined = ledger.recover()
    assert quarantined > 0
    assert ledger.verify_chain() == acknowledged  # acknowledged rows survive exactly

    qfile = ledger.path.with_name(ledger.path.name + ".quarantine")
    assert qfile.parent == paths.ledger_dir()  # recovery artifacts stay in the data dir
    assert stat.S_IMODE(qfile.stat().st_mode) == 0o600

    # Capture resumes to exactly ground truth: one row per session, no dupes.
    capture.Daemon(config).scan_once()
    ledger = Ledger()
    assert ledger.verify_chain() == 1 + len(fx.sessions)
    assert_matches_ground_truth(ledger, fx, config)
    assert_archives_match_ground_truth(fx, config)

    # AC #5: quarantine, ledger, and daemon log are all leak-free.
    used = [n for f in paths.nonces_dir().glob("*.jsonl") for n in nonces.load_nonces(f.stem)]
    assert used
    scanned = assert_no_canaries(
        [ledger.path, qfile, tmp_path / "daemon.log"], fx.all_canaries() + used
    )
    assert scanned == 3


def test_scan_once_self_heals_torn_tail(fx, config):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    with daemon.ledger.path.open("ab") as f:
        f.write(b'{"schema_version":"1","i":9')  # simulate a torn append
    assert daemon.scan_once() == 0  # heals, nothing new to capture
    assert daemon.ledger.verify_chain() == 1 + len(fx.sessions)


# --- Recovery is surgical -----------------------------------------------------------


def test_recover_on_clean_ledger_is_a_no_op(fx, config):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    assert daemon.ledger.recover() == 0
    assert not daemon.ledger.path.with_name("ledger.jsonl.quarantine").exists()


def test_recover_redurabilizes_complete_visible_ledger(fx, config, monkeypatch):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    ledger_bytes = daemon.ledger.path.read_bytes()

    daemon.ledger.path.unlink()
    fd = os.open(daemon.ledger.path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        assert os.write(fd, ledger_bytes) == len(ledger_bytes)
        # Deliberately no file or directory fsync: this models a process dying
        # after a complete A3 write became page-cache-visible but before either
        # durability barrier completed.
    finally:
        os.close(fd)

    events = []
    real_file_fsync = ledger_store._fsync_file
    real_directory_fsync = ledger_store._fsync_directory

    def tracked_file_fsync(sync_fd):
        events.append("ledger_file")
        real_file_fsync(sync_fd)

    def tracked_directory_fsync(directory):
        assert directory == paths.ledger_dir()
        events.append("ledger_dir")
        real_directory_fsync(directory)

    monkeypatch.setattr(ledger_store, "_fsync_file", tracked_file_fsync)
    monkeypatch.setattr(ledger_store, "_fsync_directory", tracked_directory_fsync)

    assert Ledger().recover() == 0
    assert events == ["ledger_file", "ledger_dir"]
    assert Ledger().verify_chain() == 1 + len(fx.sessions)


def test_recover_never_truncates_mid_file_corruption(fx, config):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    lines = daemon.ledger.path.read_text().splitlines()
    lines[1] = lines[1][:-3] + "xxx"  # tamper a NON-final row
    daemon.ledger.path.write_text("\n".join(lines) + "\n")
    before = daemon.ledger.path.read_bytes()
    with pytest.raises(LedgerError):
        daemon.ledger.recover()  # evidence, not a crash artifact
    assert daemon.ledger.path.read_bytes() == before


def test_crash_between_nonces_and_row_produces_row_on_next_scan(fx, config):
    # The nonces-written-but-no-row crash window: nonces exist for items no
    # ledger row covers. The next scan must reconcile against ledger coverage.
    daemon = capture.Daemon(config)
    daemon.scan_once()
    target = fx.sessions[0]
    with target.open("ab") as f:
        f.write(b'{"synthetic": "crash-window"}\n')
    items = capture._complete_lines(target.read_bytes())
    nonces.append_nonce(sid(config, target), c.generate_nonce())  # crash happened right here
    assert len(nonces.load_nonces(sid(config, target))) == len(items)
    assert daemon.scan_once() == 1  # not silence
    assert_matches_ground_truth(Ledger(), fx, config)


def test_sigkill_mid_archive_append_completes_prefix_without_rewrite(
    fx, config, tmp_path, monkeypatch
):
    env = dict(os.environ, MYBENCH_FAULT_ARCHIVE="1")
    with (tmp_path / "archive-crash.log").open("ab") as logf:
        proc = subprocess.run(
            daemon_cmd(fx, "--once"), env=env, stderr=logf, timeout=TIMEOUT
        )
    assert proc.returncode == -signal.SIGKILL

    # Capture-first ordering: the A3 row is already durable while A9 holds a
    # strict prefix from the interrupted append.
    ledger = Ledger()
    assert ledger.verify_chain() == 2  # genesis + first session
    partial_files = [p for p in paths.archive_dir().glob("*/*") if p.is_file()]
    assert len(partial_files) == 1
    partial_file = partial_files[0]
    partial = partial_file.read_bytes()
    target = next(s for s in fx.sessions if archive_path(config, s) == partial_file)
    full = b"".join(item + b"\n" for item in capture._complete_lines(target.read_bytes()))
    assert 0 < len(partial) < len(full)
    inode = partial_file.stat().st_ino

    durable = []
    real_fsync_directories = archive_store._fsync_archive_directories

    def tracked_fsync_directories(source_dir):
        if source_dir == partial_file.parent:
            assert partial_file.read_bytes() == full
            durable.append(source_dir)
        real_fsync_directories(source_dir)

    monkeypatch.setattr(
        archive_store, "_fsync_archive_directories", tracked_fsync_directories
    )
    capture.Daemon(config).scan_once()
    assert partial_file.read_bytes().startswith(partial)
    assert partial_file.stat().st_ino == inode
    assert partial_file.parent in durable
    assert Ledger().verify_chain() == 1 + len(fx.sessions)
    assert_matches_ground_truth(Ledger(), fx, config)
    assert_archives_match_ground_truth(fx, config)

    assert assert_no_canaries(
        [Ledger().path, tmp_path / "archive-crash.log"], fx.all_canaries()
    ) == 2


def test_two_daemon_processes_serialize_nonce_and_ledger_reconciliation(
    fx, config, tmp_path
):
    claude = fx.root / "claude" / "projects"
    codex = fx.root / "codex" / "sessions"
    script = f"""
import time
from pathlib import Path
from mybench.daemon.capture import Daemon, DaemonConfig, WatchSpec
original = Daemon._capture_file
def slow_capture(self, *args, **kwargs):
    time.sleep(0.25)
    return original(self, *args, **kwargs)
Daemon._capture_file = slow_capture
Daemon(DaemonConfig(watches=(
    WatchSpec(Path({str(claude)!r}), 'claude-code'),
    WatchSpec(Path({str(codex)!r}), 'codex'),
), archive_enabled=True)).scan_once()
"""
    first_log = tmp_path / "daemon-first.log"
    second_log = tmp_path / "daemon-second.log"
    with first_log.open("wb") as first_stderr, second_log.open("wb") as second_stderr:
        first = subprocess.Popen([sys.executable, "-c", script], stderr=first_stderr)

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            lock_path = paths.capture_scan_lock_path()
            if lock_path.exists():
                fd = os.open(lock_path, os.O_WRONLY)
                try:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        break  # first daemon owns the whole-scan lock
                    else:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
            time.sleep(0.01)
        else:
            first.kill()
            first.wait(timeout=TIMEOUT)
            pytest.fail("first daemon never acquired the capture scan lock")

        second = subprocess.Popen(
            daemon_cmd(fx, "--once"),
            stderr=second_stderr,
        )
        assert first.wait(timeout=TIMEOUT) == 0
        assert second.wait(timeout=TIMEOUT) == 0

    ledger = Ledger()
    assert ledger.verify_chain() == 1 + len(fx.sessions)
    assert_matches_ground_truth(ledger, fx, config)
    assert_archives_match_ground_truth(fx, config)
    assert assert_no_canaries(
        [ledger.path, first_log, second_log], fx.all_canaries()
    ) == 3


# --- Randomized kill loop (AC #2, #4) -------------------------------------------------


def test_random_kill_loop_never_corrupts_or_loses_acknowledged_rows(fx, config, tmp_path):
    rng = random.Random(20260708)
    acknowledged = 0
    with (tmp_path / "kills.log").open("ab") as logf:
        for i in range(20):
            grow = rng.choice(fx.sessions)
            with grow.open("ab") as f:
                f.write(json.dumps({"synthetic": f"growth-{i}"}).encode() + b"\n")
            proc = subprocess.Popen(daemon_cmd(fx, "--interval", "0.003"), stderr=logf)
            time.sleep(rng.uniform(0.02, 0.15))
            proc.kill()
            proc.wait(timeout=TIMEOUT)

            ledger = Ledger()
            ledger.recover()
            count = ledger.verify_chain()
            assert count >= acknowledged, "a previously acknowledged row disappeared"
            acknowledged = count

    # After the dust settles: one clean scan reaches exact ground truth.
    capture.Daemon(config).scan_once()
    ledger = Ledger()
    assert ledger.verify_chain() >= acknowledged
    assert_matches_ground_truth(ledger, fx, config)
    assert_archives_match_ground_truth(fx, config)
