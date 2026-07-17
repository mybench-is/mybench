"""MYB-11.6 read-only/offline status and successful-scan receipt."""

from __future__ import annotations

import hashlib
import json
import socket
import stat
import subprocess
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from opentimestamps.core.notary import (
    BitcoinBlockHeaderAttestation,
    PendingAttestation,
)
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from mybench import cli, nonces, paths, scan_health, status
from mybench.anchor.batch import build_batch, canonical_bytes
from mybench.anchor.event import build_event, stage_event
from mybench.daemon.capture import Daemon, DaemonConfig, WatchSpec
from mybench.hooks import binding
from mybench.ledger import Ledger
from mybench.scan_config import ScanConfig, store as store_scan_config
from mybench.schemas import load_validator
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _bootstrap() -> None:
    paths.ensure_data_dir()
    paths.ensure_session_scope_key()
    paths.ensure_device_key()
    paths.ensure_identity_key()
    paths.ensure_commit_signing_key()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(repo: Path, name: str) -> str:
    (repo / name).write_text("synthetic\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", f"synthetic {name}")
    return _git(repo, "rev-parse", "HEAD")


def _snapshot(root: Path) -> dict[str, tuple]:
    values = {}
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        values[relative] = (
            stat.S_IFMT(info.st_mode),
            stat.S_IMODE(info.st_mode),
            info.st_size,
            info.st_mtime_ns,
            digest,
        )
    return values


def _detached_proof(root: bytes, attestation) -> bytes:
    timestamp = Timestamp(root)
    timestamp.attestations.add(attestation)
    detached = DetachedTimestampFile(OpSHA256(), timestamp)
    context = BytesSerializationContext()
    detached.serialize(context)
    return context.getbytes()


def test_fresh_init_status_is_healthy_closed_schema_and_stdout_only(capsys):
    assert cli.main(["init", "--json"]) == 0
    capsys.readouterr()

    assert cli.main(["status", "--json"]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    result = json.loads(output.out)
    load_validator("status.schema.json").validate(result)
    assert result["health"] == "healthy"
    assert result["data_dir"] == {"state": "private"}
    assert result["keys"]["ready"] == 4
    assert result["ledger"] == {"state": "absent", "rows": 0}
    assert result["scan"]["last_successful_at"] is None
    assert result["scan"]["stale"] is False
    assert result["issues"] == []
    assert not paths.scan_health_path().exists()
    assert not paths.scan_health_lock_path().exists()


def test_configured_sources_without_receipt_are_unknown_and_need_no_manual_backfill(tmp_path):
    _bootstrap()
    watch = tmp_path / "watch"
    watch.mkdir()
    store_scan_config(
        ScanConfig(
            watches=(WatchSpec(watch, "codex"),),
            exclusions=("/synthetic/withheld",),
        )
    )

    result = status.collect(now=datetime(2026, 7, 16, tzinfo=UTC))
    assert result["health"] == "attention" and result["exit_code"] == 1
    assert result["scan"]["receipt_state"] == "absent"
    assert result["scan"]["last_successful_at"] is None
    assert result["scan"]["watches"][0]["last_scanned_at"] is None
    assert result["scan"]["exclusions"] == ["/synthetic/withheld"]
    assert result["scan"]["stale"] is True
    assert "scan_never_completed" in result["issues"]
    assert not paths.scan_health_path().exists()


def test_daemon_and_unified_scan_automatically_record_actual_coverage(
    tmp_path, monkeypatch, capsys
):
    watch = tmp_path / "watch"
    watch.mkdir()
    (watch / "session.jsonl").write_text('{"synthetic":"one"}\n')
    repo = tmp_path / "repo"
    repo.mkdir()
    config = ScanConfig(
        watches=(WatchSpec(watch, "codex"),),
        repos=(repo,),
    )
    store_scan_config(config)
    first = datetime(2026, 7, 16, 10, 0, tzinfo=UTC)
    second = datetime(2026, 7, 16, 11, 0, tzinfo=UTC)
    monkeypatch.setattr(scan_health, "_clock_now", lambda: first)

    assert Daemon(DaemonConfig(watches=config.watches)).scan_once() == 1
    receipt = scan_health.load()
    assert receipt is not None
    assert receipt.capture_completed_at == "2026-07-16T10:00:00Z"
    assert receipt.full_scan_completed_at is None
    assert len(receipt.watches) == 1 and receipt.repos == ()
    assert _mode(paths.scan_health_path()) == 0o600
    assert _mode(paths.scan_health_lock_path()) == 0o600
    receipt_bytes = paths.scan_health_path().read_bytes()
    assert str(watch).encode() not in receipt_bytes
    assert str(repo).encode() not in receipt_bytes

    monkeypatch.setattr(scan_health, "_clock_now", lambda: second)
    assert cli.main(["scan", "--json"]) == 0
    capsys.readouterr()
    receipt = scan_health.load()
    assert receipt is not None
    assert receipt.capture_completed_at == "2026-07-16T11:00:00Z"
    assert receipt.full_scan_completed_at == "2026-07-16T11:00:00Z"
    assert len(receipt.watches) == 1 and len(receipt.repos) == 1

    # Completion-order races cannot move a newer successful receipt backward.
    scan_health.record_full_success(config.watches, config.repos, completed_at=first)
    assert scan_health.load() == receipt

    result = status.collect(now=second + timedelta(hours=1))
    assert result["scan"]["last_successful_at"] == "2026-07-16T11:00:00Z"
    assert result["scan"]["watches"][0]["last_scanned_at"] == "2026-07-16T11:00:00Z"
    assert result["scan"]["repos"][0]["last_scanned_at"] == "2026-07-16T11:00:00Z"


def test_failed_unified_or_daemon_scan_does_not_create_completion_receipt(
    tmp_path, monkeypatch, capsys
):
    watch = tmp_path / "watch"
    watch.mkdir()
    (watch / "session.jsonl").write_text('{"synthetic":"one"}\n')
    store_scan_config(ScanConfig(watches=(WatchSpec(watch, "codex"),)))

    def fail_upgrade():
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(cli, "_upgrade_proofs", fail_upgrade)
    assert cli.main(["scan", "--upgrade", "--json"]) == 1
    capsys.readouterr()
    assert not paths.scan_health_path().exists()

    scan_health.record_capture_success(
        (WatchSpec(watch, "codex"),),
        completed_at=datetime(2026, 7, 15, tzinfo=UTC),
    )
    prior_receipt = paths.scan_health_path().read_bytes()
    assert cli.main(["scan", "--upgrade", "--json"]) == 1
    capsys.readouterr()
    assert paths.scan_health_path().read_bytes() == prior_receipt

    daemon = Daemon(DaemonConfig(watches=(WatchSpec(watch, "codex"),)))
    monkeypatch.setattr(daemon, "_scan_once_locked", lambda: (_ for _ in ()).throw(RuntimeError()))
    with pytest.raises(RuntimeError):
        daemon.scan_once()
    assert paths.scan_health_path().read_bytes() == prior_receipt


def test_stale_scan_is_attention_with_human_nudge(tmp_path):
    _bootstrap()
    watch = tmp_path / "watch"
    watch.mkdir()
    config = ScanConfig(watches=(WatchSpec(watch, "codex"),))
    store_scan_config(config)
    scan_health.record_capture_success(
        config.watches,
        completed_at=datetime(2026, 7, 1, tzinfo=UTC),
    )

    result = status.collect(now=datetime(2026, 7, 9, 0, 0, 1, tzinfo=UTC))
    assert result["health"] == "attention"
    assert result["scan"]["stale"] is True
    assert result["issues"] == ["scan_stale"]
    assert "history scan is stale; run mybench scan" in status.render(result)


def test_enrolled_repo_unbound_count_is_a_read_only_dry_run(tmp_path):
    _bootstrap()
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Synthetic")
    _git(repo, "config", "user.email", "synthetic@example.invalid")
    _commit(repo, "base.txt")
    binding.enroll(repo)
    (repo / ".git" / "hooks" / "post-commit").unlink()
    _commit(repo, "unbound.txt")
    config = ScanConfig(repos=(repo,))
    store_scan_config(config)
    scan_health.record_full_success(
        (),
        config.repos,
        completed_at=datetime(2026, 7, 16, tzinfo=UTC),
    )
    before = _snapshot(paths.data_dir())

    result = status.collect(now=datetime(2026, 7, 16, 1, tzinfo=UTC))

    assert _snapshot(paths.data_dir()) == before
    assert result["scan"]["repos"] == [
        {
            "path": str(repo),
            "state": "ready",
            "last_scanned_at": "2026-07-16T00:00:00Z",
            "unbound_commits": 1,
        }
    ]
    assert "unbound_commits" in result["issues"]


def test_status_counts_pending_and_confirmed_proofs_fully_offline(
    tmp_path, monkeypatch
):
    _bootstrap()
    ledger = Ledger()
    ledger.append_session(
        session_id="status-anchor",
        session_root=bytes.fromhex("11" * 32),
        item_count=1,
        source="claude-code",
        ts="2026-07-15T00:00:00Z",
    )
    batch = build_batch(ledger)
    event = build_event(batch, ledger.rows(), date="2026-07-15")
    pending = _detached_proof(
        bytes.fromhex(event["root"]),
        PendingAttestation("https://synthetic.invalid"),
    )
    stage_event(event, pending, paths.anchors_dir())

    flat = paths.anchors_dir() / "anchor-00000000-00000001.json"
    flat.write_bytes(canonical_bytes(batch))
    flat.with_suffix(".root.ots").write_bytes(
        _detached_proof(bytes.fromhex(batch["root"]), BitcoinBlockHeaderAttestation(700123))
    )

    network_calls = []

    def forbidden_network(*args, **kwargs):
        network_calls.append((args, kwargs))
        raise AssertionError("status must stay offline")

    monkeypatch.setattr(socket.socket, "connect", forbidden_network)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden_network)
    result = status.collect(now=datetime(2026, 7, 16, tzinfo=UTC))

    assert result["anchors"] == {
        "anchored_through": "2026-07-15",
        "proofs": {"confirmed": 1, "pending": 1, "invalid": 0},
    }
    assert "proof_pending" in result["issues"]
    assert network_calls == []


def test_loose_permissions_are_reported_never_repaired_and_output_stays_stdout(
    capsys,
):
    _bootstrap()
    paths.data_dir().chmod(0o755)

    assert cli.main(["status", "--json"]) == 1
    output = capsys.readouterr()
    assert output.err == ""
    result = json.loads(output.out)
    assert result["health"] == "error"
    assert result["data_dir"]["state"] == "insecure"
    assert result["issues"] == ["data_tree_insecure"]
    assert _mode(paths.data_dir()) == 0o755


def test_loose_private_key_is_reported_never_repaired(capsys):
    _bootstrap()
    paths.device_key_path().chmod(0o644)

    assert cli.main(["status", "--json"]) == 1
    output = capsys.readouterr()
    assert output.err == ""
    result = json.loads(output.out)
    assert result["health"] == "error"
    assert result["keys"]["roles"]["device"] == "insecure"
    assert "data_tree_insecure" in result["issues"]
    assert _mode(paths.device_key_path()) == 0o644


def test_repeated_status_is_strictly_read_only_over_entire_data_tree(tmp_path, capsys):
    _bootstrap()
    watch = tmp_path / "watch"
    watch.mkdir()
    config = ScanConfig(watches=(WatchSpec(watch, "codex"),))
    store_scan_config(config)
    scan_health.record_capture_success(
        config.watches,
        completed_at=datetime(2026, 7, 16, tzinfo=UTC),
    )
    before = _snapshot(paths.data_dir())

    assert cli.main(["status", "--json"]) == 0
    first = capsys.readouterr()
    assert first.err == ""
    assert cli.main(["status"]) == 0
    second = capsys.readouterr()
    assert second.err == "" and "mybench status: HEALTHY" in second.out

    assert _snapshot(paths.data_dir()) == before


def test_status_output_leak_scan_and_companion_firing(tmp_path):
    _bootstrap()
    fx = generate_fixtures(tmp_path / "fixtures", claude_sessions=0, codex_sessions=1)
    watch = fx.root / "codex" / "sessions"
    config = ScanConfig(watches=(WatchSpec(watch, "codex"),))
    store_scan_config(config)
    Daemon(DaemonConfig(watches=config.watches)).scan_once()
    result = status.collect()
    rendered = tmp_path / "status-human.txt"
    encoded = tmp_path / "status.json"
    rendered.write_text(status.render(result))
    encoded.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")))
    used_nonces = [
        nonce
        for nonce_file in paths.nonces_dir().glob("*.jsonl")
        for nonce in nonces.load_nonces(nonce_file.stem)
    ]
    private_keys = [
        path.read_bytes()
        for path in (
            paths.device_key_path(),
            paths.identity_key_path(),
            paths.commit_signing_key_path(),
            paths.session_scope_key_path(),
        )
    ]
    canaries = fx.all_canaries() + used_nonces + private_keys
    assert assert_no_canaries([rendered, encoded], canaries) == 2

    planted = tmp_path / "planted-status.txt"
    planted.write_text(fx.content_canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], canaries)


@pytest.mark.parametrize("attack", ("loose_receipt", "loose_lock", "symlink", "hardlink"))
def test_scan_health_loader_refuses_insecure_storage(tmp_path, attack):
    _bootstrap()
    watch = WatchSpec(tmp_path, "codex")
    scan_health.record_capture_success(
        (watch,), completed_at=datetime(2026, 7, 16, tzinfo=UTC)
    )
    target = paths.scan_health_path()
    if attack == "loose_receipt":
        target.chmod(0o644)
    elif attack == "loose_lock":
        paths.scan_health_lock_path().chmod(0o644)
    elif attack == "symlink":
        original = target.with_suffix(".original")
        target.rename(original)
        target.symlink_to(original)
    else:
        target.with_suffix(".hardlink").hardlink_to(target)
    with pytest.raises((scan_health.ScanHealthError, OSError)):
        scan_health.load()
