"""MYB-5.1: skeptic verify CLI — zero context, tamper detection, honest OTS status."""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mybench import paths
from mybench.anchor.batch import build_batch, canonical_bytes, signed_bytes
from mybench.anchor.ots import stamp_batch, upgrade_batch_proof
from mybench.commitments import generate_nonce, leaf_commitment, session_root
from mybench.verify.cli import VerifyFailure, render, verify_anchors
from tests.anchor.conftest import BLOCK_HEIGHT
from tests.fixtures import generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger

README = Path(__file__).parents[2] / "README.md"


def make_public_dir(tmp_path, calendar, batches=1, upgrade=False):
    """Cut+stamp batches from a canary ledger; copy staged pairs to a public dir."""
    fx = generate_fixtures(tmp_path / "fx")
    led, _ = build_canary_ledger(fx)
    previous = None
    for k in range(batches):
        if k:  # grow the ledger so another batch exists
            items = fx.sessions[0].read_bytes().splitlines()
            nonces = [generate_nonce() for _ in items]
            leaves = [leaf_commitment(n, m) for n, m in zip(nonces, items)]
            led.append_session(session_id=f"extra-{k}", session_root=session_root(leaves),
                               item_count=len(items), source="synthetic",
                               ts=f"2026-01-02T00:00:0{k}Z")
        previous = build_batch(led, previous=previous)
        _, proof = stamp_batch(previous, calendars=[calendar.base_url])
        if upgrade:
            assert upgrade_batch_proof(proof)
    public = tmp_path / "public"
    public.mkdir()
    for f in paths.anchors_dir().iterdir():
        shutil.copy(f, public / f.name)
    return public


def agreeing_fetch(merkle_root_hex):
    def fetch(url, timeout=15.0):
        if "block-height" in url:
            return "f" * 64
        return json.dumps({"merkle_root": merkle_root_hex})
    return fetch


def resign(batch):
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(paths.device_key_path().read_bytes(), None)
    b = {k: v for k, v in batch.items() if k != "sig"}
    b["sig"] = key.sign(signed_bytes(b)).hex()
    return b


# --- Honest OTS status (AC #5) --------------------------------------------------------


def test_pending_counts_toward_pass_and_is_labeled(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar, batches=2, upgrade=False)

    def must_not_fetch(url, timeout=15.0):
        raise AssertionError("no bitcoin attestation exists — nothing to fetch")

    result = verify_anchors(str(public), fetch=must_not_fetch)
    assert result["verdict"] == "PASS"
    assert result["pending"] == 2 and result["confirmed"] == 0
    text = render(result)
    assert "pending (calendar-attested, not yet Bitcoin-confirmed)" in text
    assert "no gaps" in text


def test_confirmed_with_agreeing_explorers(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar, upgrade=True)
    batch = json.loads(next(public.glob("*.json")).read_bytes())
    root = bytes.fromhex(batch["root"])  # mock calendar attests directly on the root
    result = verify_anchors(str(public), fetch=agreeing_fetch(root[::-1].hex()))
    assert result["verdict"] == "PASS" and result["confirmed"] == 1
    assert "header cross-checked against 2 explorers" in render(result)
    assert f"height {BLOCK_HEIGHT}" in render(result)


def test_header_mismatch_fails(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar, upgrade=True)
    result = verify_anchors(str(public), fetch=agreeing_fetch("ab" * 32))
    assert result["verdict"] == "FAIL"
    assert any("does NOT match" in f for f in result["failures"])


def test_unreachable_explorers_degrade_honestly(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar, upgrade=True)

    def down(url, timeout=15.0):
        raise OSError("no route to host")

    result = verify_anchors(str(public), fetch=down)
    assert result["verdict"] == "PASS"
    assert "verify the header independently" in render(result)


def test_offline_flag_skips_fetch(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar, upgrade=True)

    def must_not_fetch(url, timeout=15.0):
        raise AssertionError("offline mode must not fetch")

    result = verify_anchors(str(public), check_bitcoin=False, fetch=must_not_fetch)
    assert result["verdict"] == "PASS" and result["confirmed"] == 1


# --- Tamper detection (AC #3) -----------------------------------------------------------


def test_mutated_artifact_fails_with_reason(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar)
    artifact = next(public.glob("*.json"))
    data = bytearray(artifact.read_bytes())
    data[data.index(b'"root":"') + 10] ^= 0x01
    artifact.write_bytes(bytes(data))
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert result["failures"]


def test_continuity_gap_fails(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar, batches=2)
    second = sorted(public.glob("*.json"))[1]
    batch = json.loads(second.read_bytes())
    batch["row_start"] += 1
    batch["row_end"] += 1  # whole range shifted: schema-consistent, but a gap
    second.write_bytes(canonical_bytes(resign(batch)))
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert any("gap/overlap" in f for f in result["failures"])


def test_history_must_start_at_row_zero(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar)
    artifact = next(public.glob("*.json"))
    batch = json.loads(artifact.read_bytes())
    batch["row_start"] += 1
    batch["row_count"] -= 1
    artifact.write_bytes(canonical_bytes(resign(batch)))
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert any("start at row 0" in f for f in result["failures"])


def test_missing_and_mismatched_proofs_fail(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar, batches=2)
    proofs = sorted(public.glob("*.root.ots"))
    a, b = proofs[0].read_bytes(), proofs[1].read_bytes()
    proofs[0].write_bytes(b)  # swapped proof: binds the wrong root
    proofs[1].unlink()  # missing proof
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert any("does not bind" in f for f in result["failures"])
    assert any("missing OTS proof" in f for f in result["failures"])
    assert a != b


def test_empty_source_fails(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(VerifyFailure, match="no anchor artifacts"):
        verify_anchors(str(empty))


# --- Zero context: clone mode, no data dir, timing, quickstart (AC #1/#2/#4) --------------


def test_clone_url_mode(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar)
    subprocess.run(["git", "-C", str(public), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(public), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(public), "-c", "user.email=s@example.invalid",
                    "-c", "user.name=S", "commit", "-q", "-m", "anchors"], check=True)
    result = verify_anchors(f"file://{public}", check_bitcoin=False)
    assert result["verdict"] == "PASS"


def test_runs_with_no_data_dir_under_five_minutes(tmp_path, calendar):
    public = make_public_dir(tmp_path, calendar, upgrade=True)
    env = dict(os.environ, XDG_DATA_HOME="/nonexistent/never-created")
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "mybench.verify", str(public), "--offline"],
        capture_output=True, text=True, env=env, timeout=290,
    )
    elapsed = time.monotonic() - start
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "mybench verify: PASS" in proc.stdout
    assert elapsed < 300  # AC #1, generously
    assert not Path("/nonexistent/never-created").exists()


def test_readme_quickstart_documents_the_real_command():
    text = README.read_text()
    assert "python -m mybench.verify" in text
    assert "--offline" in text
    assert "blockstream.info" in text and "mempool.space" in text  # network needs documented
    assert "pending (calendar-attested" in text
