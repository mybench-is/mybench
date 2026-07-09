"""MYB-8.6: skeptic verify CLI v2 — layout v1, identity chain, coverage semantics."""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mybench import paths
from mybench.anchor.batch import build_batch
from mybench.anchor.event import build_event, stage_event, write_identity_records
from mybench.anchor.ots import stamp_root, upgrade_batch_proof
from mybench.identity import local_identity_id
from mybench.verify.cli import VerifyFailure, render, verify_anchors
from tests.anchor.conftest import BLOCK_HEIGHT
from tests.anchor.test_publish import grow_and_stage
from tests.fixtures import generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger

README = Path(__file__).parents[2] / "README.md"
DATE1, DATE2 = "2026-01-01", "2026-01-02"


def make_log(tmp_path, calendar, days=2, upgrade_first=True):
    """A layout-v1 public log dir: identity records + contiguous daily events."""
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    staging = paths.anchors_dir()
    write_identity_records(staging, "ckeenan", DATE1)
    batch = build_batch(led)
    event1 = build_event(batch, led.rows(), date=DATE1)
    proof1 = stamp_root(bytes.fromhex(event1["root"]), calendars=[calendar.base_url])
    _, proof1_path = stage_event(event1, proof1, staging)
    if upgrade_first:
        assert upgrade_batch_proof(proof1_path)
    events = [event1]
    if days > 1:
        _, event2 = grow_and_stage(led, tmp_path, calendar, DATE2, event1["row_end"])
        events.append(event2)
        # DATE2's proof stays pending AND unpublished (two-step write):
        (staging / f"anchors/{event2['identity_id']}/2026/01/02.json.ots").unlink()
    public = tmp_path / "public"
    shutil.copytree(staging, public)
    (public / "README.md").write_text("# anchors log (synthetic)\n")
    return public, events, canaries


def agreeing_fetch(merkle_root_hex):
    def fetch(url, timeout=15.0):
        if "block-height" in url:
            return "f" * 64
        return json.dumps({"merkle_root": merkle_root_hex})
    return fetch


# --- Full-chain PASS with honest proof states ---------------------------------------------


def test_pass_full_chain_with_two_step_proof_states(tmp_path, calendar):
    public, events, _ = make_log(tmp_path, calendar)
    root1 = bytes.fromhex(events[0]["root"])
    result = verify_anchors(str(public), fetch=agreeing_fetch(root1[::-1].hex()))
    assert result["verdict"] == "PASS"
    assert result["identities"] == 1
    assert result["confirmed"] == 1 and result["pending"] == 1
    text = render(result)
    assert "genesis self-certifies" in text and "'ckeenan'" in text
    assert f"height {BLOCK_HEIGHT}" in text
    assert "header cross-checked against 2 explorers" in text
    assert "proof not yet published (pending Bitcoin confirmation)" in text
    assert f"rows 0..{events[1]['row_end']} covered, 2 anchor day(s), no gaps" in text


def test_offline_and_unreachable_degrade_honestly(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)

    def down(url, timeout=15.0):
        raise OSError("no route")

    result = verify_anchors(str(public), fetch=down)
    assert result["verdict"] == "PASS"
    assert "verify the header independently" in render(result)
    result2 = verify_anchors(str(public), check_bitcoin=False,
                             fetch=lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    assert result2["verdict"] == "PASS"


def test_header_mismatch_fails(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)
    result = verify_anchors(str(public), fetch=agreeing_fetch("ab" * 32))
    assert result["verdict"] == "FAIL"
    assert any("does NOT match" in f for f in result["failures"])


# --- Identity-chain tampers ------------------------------------------------------------------


def test_unbound_device_key_fails(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)
    iid = local_identity_id()
    next((public / "identities" / iid).glob("device-*.json")).unlink()
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert any("NOT bound to the identity" in f for f in result["failures"])


def test_wrong_identity_directory_name_fails(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)
    iid = local_identity_id()
    fake = "0" * 64
    (public / "identities" / iid).rename(public / "identities" / fake)
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert any("NOT the genesis-key fingerprint" in f for f in result["failures"])


def test_tampered_binding_record_fails(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)
    iid = local_identity_id()
    handle = public / "identities" / iid / "handle-0000.json"
    record = json.loads(handle.read_bytes())
    record["handle"] = "mallory"
    handle.write_bytes(json.dumps(record, sort_keys=True, separators=(",", ":")).encode())
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"


def test_missing_genesis_fails(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)
    (public / "identities" / local_identity_id() / "genesis.json").unlink()
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert any("missing genesis" in f for f in result["failures"])


# --- Layout + coverage tampers ------------------------------------------------------------------


def test_moved_event_fails_path_consistency(tmp_path, calendar):
    public, events, _ = make_log(tmp_path, calendar, days=1)
    iid = events[0]["identity_id"]
    src = public / "anchors" / iid / "2026" / "01" / "01.json"
    dst = public / "anchors" / iid / "2026" / "01" / "07.json"  # backdate/move
    src.rename(dst)
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert any("path does not match" in f for f in result["failures"])


def test_gap_reads_as_withheld(tmp_path, calendar):
    public, events, _ = make_log(tmp_path, calendar)
    iid = events[0]["identity_id"]
    (public / "anchors" / iid / "2026" / "01" / "01.json").unlink()
    (public / "anchors" / iid / "2026" / "01" / "01.json.ots").unlink()
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert any("gap or withheld rows" in f for f in result["failures"])


def test_anchors_only_whitelist(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)
    (public / "scores.json").write_text("{}")
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "FAIL"
    assert any("anchors-only" in f for f in result["failures"])


def test_checkpoints_tolerated_and_noted(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)
    cp = public / "checkpoints" / "2026" / "01"
    cp.mkdir(parents=True)
    (cp / "01.json").write_text("{}")
    result = verify_anchors(str(public), check_bitcoin=False)
    assert result["verdict"] == "PASS"
    assert "checkpoint(s) present" in render(result)


def test_empty_log_fails(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "README.md").write_text("x")
    with pytest.raises(VerifyFailure, match="no anchor events"):
        verify_anchors(str(empty))


# --- Zero context: clone mode, no data dir, timing, docs --------------------------------------


def test_clone_url_mode(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)
    subprocess.run(["git", "-C", str(public), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(public), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(public), "-c", "user.email=s@example.invalid",
                    "-c", "user.name=S", "commit", "-q", "-m", "log"], check=True)
    result = verify_anchors(f"file://{public}", check_bitcoin=False)
    assert result["verdict"] == "PASS"


def test_runs_with_no_data_dir_under_five_minutes(tmp_path, calendar):
    public, _, _ = make_log(tmp_path, calendar, days=1)
    env = dict(os.environ, XDG_DATA_HOME="/nonexistent/never-created")
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "mybench.verify", str(public), "--offline"],
        capture_output=True, text=True, env=env, timeout=290,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "mybench verify: PASS" in proc.stdout
    assert time.monotonic() - start < 300
    assert not Path("/nonexistent/never-created").exists()


def test_readme_documents_the_real_command():
    text = README.read_text()
    assert "python -m mybench.verify" in text
    assert "--offline" in text and "blockstream.info" in text
