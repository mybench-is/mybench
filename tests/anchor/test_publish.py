"""MYB-3.4: publisher + mandatory leak gate — local bare repo, no internet."""

import hashlib
import subprocess

import pytest

from mybench.anchor import publish as pub
from mybench.anchor.__main__ import main as anchor_cli
from mybench.anchor.ots import stamp_batch
from mybench.anchor.batch import build_batch
from tests.fixtures import generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger


@pytest.fixture
def bare(tmp_path):
    remote = tmp_path / "anchors.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    return remote


@pytest.fixture
def staged(tmp_path, calendar):
    """Canary ledger + one cut-and-stamped batch in the real (tmp-XDG) staging dir."""
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    batch = build_batch(led)
    stamp_batch(batch, calendars=[calendar.base_url])
    return led, canaries, batch


def bare_tree(bare):
    out = subprocess.run(
        ["git", "-C", str(bare), "ls-tree", "-r", "--name-only", "master"],
        capture_output=True,
        text=True,
    )
    return sorted(out.stdout.split()) if out.returncode == 0 else []


def commit_count(bare):
    out = subprocess.run(
        ["git", "-C", str(bare), "rev-list", "--count", "master"],
        capture_output=True,
        text=True,
    )
    return int(out.stdout.strip()) if out.returncode == 0 else 0


# --- E2E against a local bare repo (AC #1) --------------------------------------------


def test_e2e_publish_then_append_only_second_batch(bare, staged, tmp_path, calendar):
    led, canaries, batch = staged
    clone = tmp_path / "clone"
    result = pub.publish(str(bare), push=True, clone_dir=clone, extra_canaries=tuple(canaries))
    assert not result["dry_run"] and len(result["pushed"]) == 2
    stem = f"anchor-{batch['row_start']:08d}-{batch['row_end']:08d}"
    assert bare_tree(bare) == sorted([f"{stem}.json", f"{stem}.root.ots"])
    assert commit_count(bare) == 1

    # Grow the ledger, cut the next batch, publish again: strictly appended.
    fx2 = generate_fixtures(tmp_path / "fx2", seed=77)
    from mybench import commitments as c
    items = fx2.sessions[0].read_bytes().splitlines()
    nonces = [c.generate_nonce() for _ in items]
    leaves = [c.leaf_commitment(k, m) for k, m in zip(nonces, items)]
    led.append_session(
        session_id="synthetic-next",
        session_root=c.session_root(leaves),
        item_count=len(items),
        source="synthetic",
        ts="2026-01-01T00:01:00Z",
    )
    second = build_batch(led, previous=batch)
    stamp_batch(second, calendars=[calendar.base_url])
    result2 = pub.publish(str(bare), push=True, clone_dir=clone, extra_canaries=tuple(canaries))
    assert len(result2["pushed"]) == 2
    assert commit_count(bare) == 2
    assert len(bare_tree(bare)) == 4  # first pair untouched, second pair added


# --- Gate fires (AC #2) -----------------------------------------------------------------


def plant_and_expect_block(bare, staging_file, data, canaries, tmp_path):
    staging_file.write_bytes(data)
    with pytest.raises(pub.PublishError):
        pub.publish(str(bare), push=True, clone_dir=tmp_path / "clone2",
                    extra_canaries=tuple(canaries))
    assert bare_tree(bare) == []  # nothing reached the remote


def test_gate_blocks_planted_content_canary(bare, staged, tmp_path):
    _, canaries, _ = staged
    from mybench import paths
    rogue = paths.anchors_dir() / "anchor-99999999-99999999.json"
    plant_and_expect_block(bare, rogue, b'{"note": "' + canaries[0] + b'"}', canaries, tmp_path)


def test_gate_blocks_canary_filename(bare, staged, tmp_path):
    _, canaries, _ = staged
    from mybench import paths
    rogue = paths.anchors_dir() / "MYBENCH-CANARY-filename.json"
    plant_and_expect_block(bare, rogue, b"{}", canaries, tmp_path)


def test_gate_blocks_nonce_leaked_into_proof_bytes(bare, staged, tmp_path):
    led, canaries, batch = staged
    from mybench import paths
    stem = f"anchor-{batch['row_start']:08d}-{batch['row_end']:08d}"
    proof = paths.anchors_dir() / f"{stem}.root.ots"
    real_nonce = pub.local_secret_corpus()[0]
    proof.write_bytes(proof.read_bytes() + real_nonce)  # trailing bytes: parser tolerates
    with pytest.raises(pub.PublishError):
        pub.publish(str(bare), push=True, clone_dir=tmp_path / "clone2")
    assert bare_tree(bare) == []


# --- Single gated entry point (AC #3) ------------------------------------------------------


def test_push_is_unreachable_when_gate_fails(bare, staged, tmp_path, monkeypatch):
    def exploding_gate(*a, **k):
        raise pub.PublishError("gate says no")

    monkeypatch.setattr(pub, "gate", exploding_gate)
    with pytest.raises(pub.PublishError, match="gate says no"):
        pub.publish(str(bare), push=True, clone_dir=tmp_path / "clone3")
    assert bare_tree(bare) == [] and commit_count(bare) == 0


def test_single_push_call_site_by_construction():
    import inspect
    source = inspect.getsource(pub)
    assert source.count('"push"') == 1  # the one call site, inside publish()


# --- Dry run (AC #4) --------------------------------------------------------------------


def test_dry_run_is_default_and_prints_exact_bytes(bare, staged, capsys):
    _, canaries, batch = staged
    result = pub.publish(str(bare), extra_canaries=tuple(canaries))
    assert result["dry_run"] is True
    assert bare_tree(bare) == []  # nothing left the machine
    from mybench import paths
    for entry in result["files"]:
        real = (paths.anchors_dir() / entry["name"]).read_bytes()
        assert entry["sha256"] == hashlib.sha256(real).hexdigest()
        assert entry["bytes"] == len(real)
    # CLI prints the same manifest and says so.
    assert anchor_cli(["publish", "--remote", str(bare)]) == 0
    out = capsys.readouterr().out
    assert "dry run — nothing pushed" in out
    assert result["files"][0]["sha256"] in out


# --- CLI cut/upgrade round trip -------------------------------------------------------------


def test_cli_cut_then_publish_flow(bare, tmp_path, calendar, capsys):
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    assert anchor_cli(["cut", "--calendar", calendar.base_url]) == 0
    assert "cut rows [0," in capsys.readouterr().out
    assert anchor_cli(["cut", "--calendar", calendar.base_url]) == 1  # nothing new
    assert anchor_cli(["upgrade"]) == 0
    assert "1 bitcoin-confirmed" in capsys.readouterr().out
    result = pub.publish(str(bare), push=True, clone_dir=tmp_path / "clone",
                         extra_canaries=tuple(canaries))
    assert len(result["pushed"]) == 2 and commit_count(bare) == 1
