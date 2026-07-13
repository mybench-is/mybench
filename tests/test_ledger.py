"""MYB-2.4: hash-chained append-only ledger — schema whitelist, chain, torn tails, leaks."""

import json
import random
import stat

import pytest

from mybench import commitments as c
from mybench import paths
from mybench.ledger import GENESIS_PREV, Ledger, LedgerError, TornTailError, row_hash
from tests.fixtures import assert_no_canaries, generate_fixtures

TS = "2026-01-01T00:00:00Z"


def build(n_sessions=4, seed=23) -> Ledger:
    rng = random.Random(seed)
    led = Ledger()
    for i in range(n_sessions):
        led.append_session(
            session_id=f"synthetic-{i}",
            session_root=rng.randbytes(32),
            item_count=rng.randrange(1, 9),
            source="synthetic",
            ts=TS,
        )
    return led


# --- Chain + genesis (AC #3) ----------------------------------------------------


def test_genesis_defined_and_chain_verifies():
    led = build(3)
    rows = led.rows()
    assert led.verify_chain() == 4  # genesis + 3 sessions
    assert rows[0]["type"] == "genesis" and rows[0]["prev"] == GENESIS_PREV
    for prev_row, row in zip(rows, rows[1:]):
        assert row["prev"] == prev_row["h"]


def test_empty_ledger_verifies_as_zero_rows():
    assert Ledger().verify_chain() == 0


def test_second_genesis_rejected():
    led = build(1)
    rows = led.rows()
    fake = dict(rows[0], i=2, prev=rows[-1]["h"])
    fake["h"] = row_hash(fake)
    # Schema allows only i=0 for genesis, and verify enforces position.
    with pytest.raises(LedgerError):
        led._validate_row(fake, "test")


# --- Schema whitelist on read and write (AC #1) -----------------------------------


def test_append_rejects_bad_source_and_bad_root():
    led = Ledger()
    with pytest.raises(LedgerError):
        led.append_session(
            session_id="s", session_root=bytes(32), item_count=1, source="cursor", ts=TS
        )
    with pytest.raises(LedgerError):
        led.append_session(
            session_id="../x", session_root=bytes(32), item_count=1, source="synthetic", ts=TS
        )


def test_injected_filename_field_rejected_on_read():
    led = build(2)
    lines = led.path.read_text().splitlines()
    row = json.loads(lines[-1])
    row["filename"] = "synthetic_leak.py"
    row["h"] = row_hash(row)  # even with a recomputed valid hash…
    lines[-1] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(LedgerError, match="schema"):
        led.rows()  # …the whitelist rejects the extra field


# --- Tamper detection (AC #2) ------------------------------------------------------


def test_any_single_bit_flip_detected():
    led = build(4)
    original = led.path.read_bytes()
    rng = random.Random(29)
    for _ in range(60):
        pos, bit = rng.randrange(len(original)), 1 << rng.randrange(8)
        mutated = bytearray(original)
        mutated[pos] ^= bit
        led.path.write_bytes(bytes(mutated))
        with pytest.raises(LedgerError):
            led.verify_chain()
    led.path.write_bytes(original)
    assert led.verify_chain() == 5


def test_row_deletion_insertion_and_reorder_detected():
    led = build(5)
    lines = led.path.read_text().splitlines()

    def rewrite(new_lines):
        led.path.write_text("\n".join(new_lines) + "\n")

    rewrite(lines[:2] + lines[3:])  # delete a middle row
    with pytest.raises(LedgerError):
        led.verify_chain()
    rewrite(lines[:3] + [lines[2]] + lines[3:])  # duplicate/insert a row
    with pytest.raises(LedgerError):
        led.verify_chain()
    rewrite(lines[:2] + [lines[3], lines[2]] + lines[4:])  # reorder two rows
    with pytest.raises(LedgerError):
        led.verify_chain()


def test_trailing_truncation_detected_against_expected_tip():
    # The chain alone cannot see trailing deletion (a valid prefix is a valid
    # chain) — that is exactly what anchored roots are for. verify_chain takes
    # the anchored tip and closes the gap.
    led = build(4)
    tip = led.rows()[-1]["h"]
    assert led.verify_chain(expect_tip=tip) == 5
    lines = led.path.read_text().splitlines()
    led.path.write_text("\n".join(lines[:-1]) + "\n")
    assert led.verify_chain() == 4  # honest prefix still chains…
    with pytest.raises(LedgerError, match="tip"):
        led.verify_chain(expect_tip=tip)  # …but not against the anchored tip


# --- Torn trailing writes (AC #4) ---------------------------------------------------


def test_torn_final_write_without_newline_detected():
    led = build(2)
    with led.path.open("ab") as f:
        f.write(b'{"schema_version":"1","i":3')
    with pytest.raises(TornTailError):
        led.verify_chain()


def test_truncated_final_line_detected_as_torn():
    led = build(2)
    data = led.path.read_bytes()
    led.path.write_bytes(data[:-7])
    with pytest.raises(TornTailError):
        led.verify_chain()


def test_mid_file_corruption_is_not_reported_as_torn():
    led = build(3)
    lines = led.path.read_text().splitlines()
    lines[1] = lines[1][:-3] + "xxx"
    led.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(LedgerError) as exc:
        led.verify_chain()
    assert not isinstance(exc.value, TornTailError)


# --- Storage location + leak-scan (AC #5, invariants #1/#2) -----------------------------


def test_ledger_lives_under_data_dir_mode_0600():
    led = build(1)
    assert led.path.parent == paths.ledger_dir()
    assert stat.S_IMODE(led.path.stat().st_mode) == 0o600


def test_ledger_from_canary_fixtures_passes_leak_scan(tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    led = Ledger()
    used_nonces = []
    for s in fx.sessions:
        items = s.read_bytes().splitlines()
        nonces = list(fx.nonce_canaries[: len(items)])
        nonces += [c.generate_nonce() for _ in items[len(nonces) :]]
        used_nonces.extend(nonces)
        leaves = [c.leaf_commitment(k, m) for k, m in zip(nonces, items)]
        led.append_session(
            session_id=s.stem.replace(".", "-"),
            session_root=c.session_root(leaves),
            item_count=len(items),
            source="synthetic",
            ts=TS,
        )
    assert led.verify_chain() == len(fx.sessions) + 1
    assert assert_no_canaries([led.path], fx.all_canaries() + used_nonces) == 1


# --- Concurrent writers (MYB-3.7) -------------------------------------------------


def test_concurrent_writers_never_fork_the_chain(tmp_path):
    """Two writer processes append in parallel; the ``<ledger>.lock`` writer lock
    makes each read-tip→append atomic, so the result is one linear chain (the
    genesis race included). Without it, interleaved writers produce duplicate
    ``i``/``prev`` rows — a fork ``verify_chain`` rejects and ``recover`` cannot
    repair — which is routine once the reconciliation sweep runs alongside the
    live post-commit hook."""
    import os
    import subprocess
    import sys

    per_writer = 15
    writer = (
        "import os, sys, time\n"
        "from mybench.ledger import Ledger\n"
        "go = sys.argv[1]\n"
        "offset = int(sys.argv[2])\n"
        f"n = {per_writer}\n"
        "while not os.path.exists(go):\n"
        "    time.sleep(0.001)\n"
        "led = Ledger()\n"
        "for i in range(n):\n"
        "    led.append_binding(commit_hash=format(offset + i, '040x'),\n"
        f"                       commit_ts={TS!r}, repo_id='ab' * 8)\n"
    )
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    go = tmp_path / "go"
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", writer, str(go), str(w * 4096)],
            env=env, stderr=subprocess.PIPE,
        )
        for w in (1, 2)
    ]
    go.touch()  # both writers start (and race the genesis row) together
    for p in procs:
        _, err = p.communicate(timeout=120)
        assert p.returncode == 0, err.decode()
    assert Ledger().verify_chain() == 2 * per_writer + 1  # genesis + every row, linear
