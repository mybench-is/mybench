"""MYB-2.6: kill the daemon mid-write; the ledger must survive, recover, resume."""

import json
import os
import random
import signal
import stat
import subprocess
import sys
import time

import pytest

from mybench import commitments as c
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
        )
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
        *extra,
    ]


def sid(config, f):
    for w in config.watches:
        if f.is_relative_to(w.path):
            return capture.session_id_for(f, w, paths.ensure_session_scope_key())
    raise AssertionError(f"{f} not under any watch")


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
