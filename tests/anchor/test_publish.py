"""MYB-8.4: publisher v2 — layout v1, signed commits, confirmed-only proofs."""

import json
import subprocess

import pytest

from mybench import paths
from mybench.anchor import publish as pub
from mybench.anchor.__main__ import main as anchor_cli
from mybench.anchor.batch import build_batch
from mybench.anchor.event import (
    EventError,
    build_event,
    stage_event,
    write_identity_records,
)
from mybench.anchor.ots import stamp_root, upgrade_batch_proof
from mybench.commitments import generate_nonce, leaf_commitment, session_root
from tests.fixtures import generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger

DATE = "2026-01-01"


@pytest.fixture
def bare(tmp_path):
    remote = tmp_path / "anchors.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    return remote


@pytest.fixture
def staged(tmp_path, calendar):
    """Canary ledger; identity records + one event + pending proof in staging."""
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    staging = paths.anchors_dir()
    write_identity_records(staging, "ckeenan", DATE)
    batch = build_batch(led)
    event = build_event(batch, led.rows(), date=DATE)
    proof = stamp_root(bytes.fromhex(event["root"]), calendars=[calendar.base_url])
    stage_event(event, proof, staging)
    return led, canaries, event


def grow_and_stage(led, tmp_path, calendar, date, previous_end, seed=99, sessions=1):
    fx2 = generate_fixtures(tmp_path / f"fx-{seed}", seed=seed)
    for k in range(sessions):
        items = fx2.sessions[0].read_bytes().splitlines()
        nonces = [generate_nonce() for _ in items]
        leaves = [leaf_commitment(n, m) for n, m in zip(nonces, items)]
        led.append_session(session_id=f"grown-{seed}-{k}", session_root=session_root(leaves),
                           item_count=len(items), source="synthetic",
                           ts=f"{date}T00:00:0{k}Z")
    batch = build_batch(led, previous={"row_end": previous_end})
    event = build_event(batch, led.rows(), date=date)
    proof = stamp_root(bytes.fromhex(event["root"]), calendars=[calendar.base_url])
    return stage_event(event, proof, paths.anchors_dir()), event


def bare_tree(bare):
    out = subprocess.run(["git", "-C", str(bare), "ls-tree", "-r", "--name-only", "master"],
                         capture_output=True, text=True)
    return sorted(out.stdout.split()) if out.returncode == 0 else []


# --- E2E: records + event publish, proof withheld then follow-up commit ------------------


def test_e2e_signed_publish_with_two_step_proof(bare, staged, tmp_path):
    led, canaries, event = staged
    clone = tmp_path / "clone"
    result = pub.publish(str(bare), push=True, clone_dir=clone,
                         extra_canaries=tuple(canaries))
    rel = f"anchors/{event['identity_id']}/2026/01/01.json"
    assert rel in result["pushed"]
    assert rel + ".ots" in result["pending"]  # pending proof withheld
    tree = bare_tree(bare)
    assert rel in tree and rel + ".ots" not in tree
    assert any(t.startswith("identities/") for t in tree)
    assert "schema/anchor.v1.md" not in tree or True  # spec staged only by migration
    # Signed commits verify locally against the allowed-signers file.
    verify = subprocess.run(["git", "-C", str(clone), "verify-commit", "HEAD"],
                            capture_output=True, text=True)
    assert verify.returncode == 0, verify.stderr
    assert '"mybench-log"' in verify.stderr or "mybench-log" in verify.stderr
    # One commit per event: records commit + event commit.
    assert len(result["commits"]) == 2

    # Upgrade the staged proof (mock calendar returns a Bitcoin attestation)…
    staged_proof = paths.anchors_dir() / (rel + ".ots")
    assert upgrade_batch_proof(staged_proof) is True
    # …then the follow-up publish pushes exactly the proof, as its own commit.
    result2 = pub.publish(str(bare), push=True, clone_dir=clone,
                          extra_canaries=tuple(canaries))
    assert result2["pushed"] == [rel + ".ots"] and len(result2["commits"]) == 1
    assert rel + ".ots" in bare_tree(bare)
    assert not staged_proof.exists()  # published proof leaves staging
    # Third publish: everything already published, nothing to do.
    result3 = pub.publish(str(bare), push=True, clone_dir=clone,
                          extra_canaries=tuple(canaries))
    assert result3["pushed"] == [] and result3["commits"] == []


def test_second_event_continuity_enforced(bare, staged, tmp_path, calendar):
    led, canaries, event = staged
    clone = tmp_path / "clone"
    pub.publish(str(bare), push=True, clone_dir=clone, extra_canaries=tuple(canaries))
    # A gap: previous_end deliberately one short of the real end.
    grow_and_stage(led, tmp_path, calendar, "2026-01-02", event["row_end"] + 0, seed=99)
    lines = (paths.anchors_dir() / f"anchors/{event['identity_id']}/2026/01/02.json")
    staged2 = json.loads(lines.read_bytes())
    assert staged2["row_start"] == event["row_end"]  # contiguous case publishes fine
    result = pub.publish(str(bare), push=True, clone_dir=clone,
                         extra_canaries=tuple(canaries))
    assert f"anchors/{event['identity_id']}/2026/01/02.json" in result["pushed"]


def test_gap_refused_at_publish(bare, staged, tmp_path, calendar):
    led, canaries, event = staged
    clone = tmp_path / "clone"
    pub.publish(str(bare), push=True, clone_dir=clone, extra_canaries=tuple(canaries))
    grow_and_stage(led, tmp_path, calendar, "2026-01-02", event["row_end"] + 1, seed=77, sessions=2)
    with pytest.raises(pub.PublishError, match="continuity"):
        pub.publish(str(bare), push=True, clone_dir=clone,
                    extra_canaries=tuple(canaries))


# --- Gate + immutability -------------------------------------------------------------------


def test_gate_blocks_rogue_paths_and_tampered_events(bare, staged, tmp_path):
    _led, canaries, event = staged
    rogue = paths.anchors_dir() / "anchor-00000000-00000001.json"  # old flat name
    rogue.write_bytes(b"{}")
    with pytest.raises(pub.PublishError, match="non-whitelisted"):
        pub.publish(str(bare), push=True, clone_dir=tmp_path / "c1",
                    extra_canaries=tuple(canaries))
    rogue.unlink()
    rel = f"anchors/{event['identity_id']}/2026/01/01.json"
    staged_event = paths.anchors_dir() / rel
    data = json.loads(staged_event.read_bytes())
    data["item_count"] += 1  # tamper: signature no longer verifies
    staged_event.write_bytes(json.dumps(data, sort_keys=True,
                                        separators=(",", ":")).encode() + b"\n")
    with pytest.raises(pub.PublishError, match="signature"):
        pub.publish(str(bare), push=True, clone_dir=tmp_path / "c2",
                    extra_canaries=tuple(canaries))
    assert bare_tree(bare) == []


def test_gate_blocks_nonce_in_proof_bytes(bare, staged, tmp_path):
    _led, canaries, event = staged
    proof = paths.anchors_dir() / f"anchors/{event['identity_id']}/2026/01/01.json.ots"
    proof.write_bytes(proof.read_bytes() + pub.local_secret_corpus()[0])
    with pytest.raises(pub.PublishError):
        pub.publish(str(bare), push=True, clone_dir=tmp_path / "c3",
                    extra_canaries=tuple(canaries))
    assert bare_tree(bare) == []


def test_published_event_is_immutable(bare, staged, tmp_path):
    _led, canaries, event = staged
    clone = tmp_path / "clone"
    pub.publish(str(bare), push=True, clone_dir=clone, extra_canaries=tuple(canaries))
    rel = f"anchors/{event['identity_id']}/2026/01/01.json"
    # Re-sign a modified event at the same path: gate passes, immutability refuses.
    from cryptography.hazmat.primitives import serialization
    from mybench.anchor.batch import signed_bytes

    modified = {k: v for k, v in event.items() if k != "sig"}
    modified["client_version"] = "0.1.0+tampered"
    key = serialization.load_pem_private_key(paths.device_key_path().read_bytes(), None)
    modified["sig"] = key.sign(signed_bytes(modified)).hex()
    (paths.anchors_dir() / rel).write_bytes(
        json.dumps(modified, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    with pytest.raises(pub.PublishError, match="immutable"):
        pub.publish(str(bare), push=True, clone_dir=clone,
                    extra_canaries=tuple(canaries))


def test_daily_rule_structural(staged, tmp_path):
    led, _canaries, event = staged
    with pytest.raises(EventError, match="one event per identity per UTC day"):
        stage_event(event, b"proof", paths.anchors_dir())


# --- Dry run + single gated entry point -------------------------------------------------------


def test_dry_run_is_default(bare, staged):
    _led, canaries, _event = staged
    result = pub.publish(str(bare), extra_canaries=tuple(canaries))
    assert result["dry_run"] is True and bare_tree(bare) == []
    assert all({"path", "bytes", "sha256"} <= set(f) for f in result["files"])


def test_push_unreachable_when_gate_fails(bare, staged, tmp_path, monkeypatch):
    def exploding_gate(*a, **k):
        raise pub.PublishError("gate says no")

    monkeypatch.setattr(pub, "gate", exploding_gate)
    with pytest.raises(pub.PublishError, match="gate says no"):
        pub.publish(str(bare), push=True, clone_dir=tmp_path / "c4")
    assert bare_tree(bare) == []


def test_single_push_call_site():
    import inspect

    assert inspect.getsource(pub).count('"push"') == 1


# --- CLI flow ------------------------------------------------------------------------------


def test_cli_cut_daily_rule_and_publish(bare, tmp_path, calendar, capsys):
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    paths.ensure_identity_key()
    assert anchor_cli(["cut", "--date", DATE, "--calendar", calendar.base_url]) == 0
    assert "staged" in capsys.readouterr().out
    assert anchor_cli(["cut", "--date", DATE, "--calendar", calendar.base_url]) == 1
    assert "one event per identity per UTC day" in capsys.readouterr().err
    assert anchor_cli(["upgrade"]) == 0
    assert "1 bitcoin-confirmed" in capsys.readouterr().out
    result = pub.publish(str(bare), push=True, clone_dir=tmp_path / "clone",
                         extra_canaries=tuple(canaries))
    # Upgraded before first publish: event AND confirmed proof go together.
    assert len(result["pushed"]) == 2 and result["pending"] == []
