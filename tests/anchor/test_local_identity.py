"""MYB-8.14: canonical offline identity state and exact founder migration."""

from __future__ import annotations

import json
import os
import socket
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from mybench import cli, identity, paths
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

DATE = "2026-01-01"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _stable_snapshot(paths_to_check: tuple[Path, ...]) -> dict[str, tuple[bytes, tuple[int, ...]]]:
    return {
        path.name: (
            path.read_bytes(),
            (
                path.lstat().st_dev,
                path.lstat().st_ino,
                path.lstat().st_mode,
                path.lstat().st_nlink,
                path.lstat().st_size,
                path.lstat().st_mtime_ns,
                path.lstat().st_ctime_ns,
            ),
        )
        for path in paths_to_check
    }


def _device_pub_hex() -> str:
    _key, public_path = paths.ensure_device_key()
    public = serialization.load_pem_public_key(public_path.read_bytes())
    return public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _write_legacy_clone(clone: Path) -> tuple[Path, tuple[Path, ...]]:
    paths.ensure_identity_key()
    paths.ensure_device_key()
    identity_id = identity.local_identity_id()
    device_pub = _device_pub_hex()
    directory = clone / "identities" / identity_id
    directory.mkdir(parents=True)
    records = (
        ("genesis.json", identity.genesis_record(DATE)),
        ("handle-0000.json", identity.handle_binding_record("synthetic-founder", DATE)),
        (
            f"device-{device_pub[:8]}.json",
            identity.device_binding_record(device_pub, DATE, scope="retroactive"),
        ),
    )
    written = []
    for index, (name, record) in enumerate(records):
        target = directory / name
        target.write_bytes(identity.record_bytes(record))
        timestamp = 1_767_225_600_000_000_000 + index * 1_000_000_000
        os.utime(target, ns=(timestamp, timestamp))
        written.append(target)
    return directory, tuple(written)


def _record_files() -> tuple[Path, ...]:
    directory = paths.identity_record_dir(identity.local_identity_id())
    return tuple(sorted(directory.iterdir()))


def test_path_api_is_canonical_private_and_rejects_non_ids():
    identity_id = "ab" * 32
    assert paths.identity_state_dir() == paths.data_dir() / "identity"
    assert paths.identity_records_dir() == paths.data_dir() / "identity" / "records"
    assert paths.identity_record_dir(identity_id) == paths.identity_records_dir() / identity_id
    with pytest.raises(paths.PathsError):
        paths.identity_record_dir("AB" * 32)
    with pytest.raises(paths.PathsError):
        paths.identity_record_dir("../not-an-id")
    paths.ensure_identity_records_dir()
    assert _mode(paths.identity_state_dir()) == 0o700
    assert _mode(paths.identity_records_dir()) == 0o700


def test_fresh_init_bootstraps_exact_local_chain_and_repeat_is_byte_stat_idempotent(
    capsys, monkeypatch
):
    network_calls = []

    def no_network(*args, **kwargs):
        network_calls.append((args, kwargs))
        raise AssertionError("identity init must remain offline")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    assert cli.main(["init"]) == 0
    first_output = capsys.readouterr()
    assert "ready locally" in first_output.out
    assert "nothing registered or published" in first_output.out

    records = _record_files()
    assert {path.name for path in records} == {
        "genesis.json",
        next(path.name for path in records if path.name.startswith("device-")),
    }
    assert not any(path.name.startswith("handle-") for path in records)
    assert _mode(records[0].parent) == 0o700
    assert all(_mode(path) == 0o600 for path in records)
    chain = identity.load_local_identity_chain()
    assert [record["type"] for record in chain] == ["genesis", "device-binding"]
    assert chain[1]["scope"] == "active"
    before = _stable_snapshot(records)

    assert cli.main(["init", "--json"]) == 0
    second_output = capsys.readouterr()
    assert json.loads(second_output.out) == {
        "command": "init",
        "identity_ready": True,
        "keys_ready": 4,
        "local_only": True,
        "published": False,
        "registered": False,
        "status": "ok",
    }
    assert _stable_snapshot(_record_files()) == before
    assert not any(paths.anchors_dir().iterdir())
    assert network_calls == []


def test_accepted_detect_uses_same_bootstrap_while_proposal_and_decline_write_nothing(
    capsys,
):
    assert cli.main(["init", "--detect", "claude", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "proposed"
    assert not paths.data_dir().exists()
    assert cli.main(["init", "--detect", "claude", "--decline", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "declined"
    assert not paths.data_dir().exists()

    assert cli.main(["init", "--detect", "claude", "--accept-all"]) == 0
    output = capsys.readouterr()
    assert "identity ready locally" in output.out
    assert "nothing registered or published" in output.out
    assert [record["type"] for record in identity.load_local_identity_chain()] == [
        "genesis",
        "device-binding",
    ]


def test_task_specified_local_first_detect_json_has_typed_boundary_without_state_divergence(
    capsys,
):
    explicit = [
        "init",
        "--local-first",
        "--detect",
        "claude",
        "--accept-all",
        "--json",
    ]
    assert cli.main(explicit) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "command": "init --detect",
        "configured": True,
        "exclusions": 0,
        "identity_ready": True,
        "keys_ready": 4,
        "local_only": True,
        "published": False,
        "registered": False,
        "repos": 0,
        "status": "ok",
        "watches": 0,
    }
    before = _stable_snapshot(_record_files())

    assert cli.main(["init", "--detect", "claude", "--accept-all", "--json"]) == 0
    legacy_payload = json.loads(capsys.readouterr().out)
    assert "local_only" not in legacy_payload
    assert legacy_payload["configured"] is True
    assert _stable_snapshot(_record_files()) == before


def test_founder_migration_copies_exact_three_records_chronology_and_never_reopens_source(
    tmp_path, capsys, monkeypatch
):
    paths.ensure_data_dir()
    paths.ensure_session_scope_key()
    paths.ensure_device_key()
    paths.ensure_identity_key()
    paths.ensure_commit_signing_key()
    clone = tmp_path / "CANARY-private-founder-clone"
    legacy_dir, legacy_files = _write_legacy_clone(clone)
    legacy_before = _stable_snapshot(legacy_files)
    key_paths = (
        paths.device_key_path(),
        paths.device_pub_path(),
        paths.identity_key_path(),
        paths.identity_pub_path(),
        paths.session_scope_key_path(),
        paths.commit_signing_key_path(),
        paths.commit_signing_pub_path(),
    )
    keys_before = _stable_snapshot(key_paths)

    assert cli.main(["init", "--migrate-founder-records-from", str(clone)]) == 0
    output = capsys.readouterr()
    assert str(clone) not in output.out + output.err
    assert identity.local_identity_id() not in output.out + output.err
    migrated = _record_files()
    assert len(migrated) == 3
    assert {path.name: path.read_bytes() for path in migrated} == {
        path.name: path.read_bytes() for path in legacy_files
    }
    assert {path.name: path.stat().st_mtime_ns for path in migrated} == {
        path.name: path.stat().st_mtime_ns for path in legacy_files
    }
    assert all(_mode(path) == 0o600 for path in migrated)
    assert _mode(migrated[0].parent) == 0o700
    migrated_before = _stable_snapshot(migrated)
    assert _stable_snapshot(legacy_files) == legacy_before
    assert _stable_snapshot(key_paths) == keys_before

    def source_must_not_reopen(*_args, **_kwargs):
        raise AssertionError("canonical state must replace the clone as durable source")

    monkeypatch.setattr(identity, "_legacy_record_files", source_must_not_reopen)
    assert cli.main(["init", "--migrate-founder-records-from", str(clone), "--json"]) == 0
    capsys.readouterr()
    assert _stable_snapshot(_record_files()) == migrated_before
    assert _stable_snapshot(legacy_files) == legacy_before
    assert _stable_snapshot(key_paths) == keys_before
    assert legacy_dir.is_dir()
    assert [record["type"] for record in identity.load_local_identity_chain()] == [
        "genesis",
        "handle-binding",
        "device-binding",
    ]


@pytest.mark.parametrize(
    "attack",
    (
        "malformed",
        "conflicting",
        "duplicate-genesis",
        "symlink",
        "hardlink",
        "wrong-identity",
        "wrong-device",
        "loose-file",
        "loose-directory",
        "noncanonical",
        "tampered",
        "unbound",
    ),
)
def test_existing_state_attacks_fail_closed_with_content_safe_errors(
    attack, tmp_path, capsys
):
    assert cli.main(["init", "--json"]) == 0
    capsys.readouterr()
    identity_id = identity.local_identity_id()
    directory = paths.identity_record_dir(identity_id)
    records = _record_files()
    genesis = directory / "genesis.json"
    device = next(path for path in records if path.name.startswith("device-"))

    if attack == "malformed":
        device.write_bytes(b"{\n")
    elif attack == "conflicting":
        (directory / "unexpected.json").write_bytes(genesis.read_bytes())
        (directory / "unexpected.json").chmod(0o600)
    elif attack == "duplicate-genesis":
        duplicate = directory / "genesis-duplicate.json"
        duplicate.write_bytes(genesis.read_bytes())
        duplicate.chmod(0o600)
    elif attack == "symlink":
        outside = tmp_path / "CANARY-outside-record"
        outside.write_bytes(device.read_bytes())
        device.unlink()
        device.symlink_to(outside)
    elif attack == "hardlink":
        linked = directory / "unexpected.json"
        linked.hardlink_to(device)
    elif attack == "wrong-identity":
        directory.rename(paths.identity_records_dir() / ("ab" * 32))
    elif attack == "wrong-device":
        other = "ab" * 32
        replacement = identity.device_binding_record(other, DATE, scope="active")
        device.unlink()
        target = directory / f"device-{other[:8]}.json"
        target.write_bytes(identity.record_bytes(replacement))
        target.chmod(0o600)
    elif attack == "unbound":
        device.unlink()
    elif attack == "loose-file":
        device.chmod(0o644)
    elif attack == "loose-directory":
        directory.chmod(0o755)
    elif attack == "noncanonical":
        device.write_text(json.dumps(json.loads(device.read_bytes()), indent=2))
        device.chmod(0o600)
    elif attack == "tampered":
        record = json.loads(device.read_bytes())
        record["date"] = "2026-01-02"
        device.write_bytes(identity.record_bytes(record))
        device.chmod(0o600)

    with pytest.raises(identity.IdentityError, match="local identity state is invalid"):
        identity.load_local_identity_chain()
    assert cli.main(["init", "--json"]) == 1
    output = capsys.readouterr()
    assert json.loads(output.err) == {
        "command": "init",
        "error": "operation_failed",
        "exit_code": 1,
        "status": "error",
    }
    assert identity_id not in output.err
    assert str(directory) not in output.err


@pytest.mark.parametrize(
    "attack",
    (
        "malformed",
        "duplicate",
        "symlink",
        "unrelated",
        "wrong-device",
        "noncanonical",
        "chronology",
    ),
)
def test_founder_migration_rejects_invalid_inputs_without_creating_canonical_state(
    attack, tmp_path, capsys
):
    paths.ensure_data_dir()
    paths.ensure_device_key()
    paths.ensure_identity_key()
    clone = tmp_path / "CANARY-invalid-founder-clone"
    _legacy_dir, legacy_files = _write_legacy_clone(clone)
    genesis, handle, device = legacy_files
    if attack == "malformed":
        handle.write_bytes(b"not-json\n")
    elif attack == "duplicate":
        (handle.parent / "handle-0001.json").write_bytes(handle.read_bytes())
    elif attack == "symlink":
        outside = tmp_path / "CANARY-symlink-record"
        outside.write_bytes(device.read_bytes())
        device.unlink()
        device.symlink_to(outside)
    elif attack == "unrelated":
        handle.parent.rename(handle.parent.parent / ("ab" * 32))
    elif attack == "wrong-device":
        record = identity.device_binding_record("ab" * 32, DATE, scope="retroactive")
        device.unlink()
        device = handle.parent / f"device-{'ab' * 4}.json"
        device.write_bytes(identity.record_bytes(record))
    elif attack == "noncanonical":
        handle.write_text(json.dumps(json.loads(handle.read_bytes()), indent=2))
    else:
        record = json.loads(handle.read_bytes())
        record["date"] = "2025-12-31"
        record["sig"] = identity.handle_binding_record(
            record["handle"], record["date"], record["seq"]
        )["sig"]
        handle.write_bytes(identity.record_bytes(record))

    assert cli.main(["init", "--migrate-founder-records-from", str(clone), "--json"]) == 1
    output = capsys.readouterr()
    assert json.loads(output.err)["error"] == "operation_failed"
    assert str(clone) not in output.err
    assert not paths.identity_record_dir(identity.local_identity_id()).exists()
    if paths.identity_records_dir().exists():
        assert not any(paths.identity_records_dir().iterdir())
    assert not paths.anchors_dir().joinpath("identities").exists()


def test_init_identity_surface_has_no_network_out_of_tree_writes_or_canary_leaks(
    tmp_path, capsys, monkeypatch
):
    fx = generate_fixtures(tmp_path / "CANARY-synthetic-identity-fixtures")
    clone = tmp_path / "CANARY-private-legacy-repository"
    paths.ensure_data_dir()
    paths.ensure_session_scope_key()
    paths.ensure_device_key()
    paths.ensure_identity_key()
    paths.ensure_commit_signing_key()
    _legacy_dir, _legacy_files = _write_legacy_clone(clone)
    before = {path for path in tmp_path.rglob("*")}

    def no_network(*_args, **_kwargs):
        raise AssertionError("identity flow attempted a network call")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    assert cli.main(["init", "--migrate-founder-records-from", str(clone)]) == 0
    output = capsys.readouterr()
    after = {path for path in tmp_path.rglob("*")}
    created = after - before
    assert created
    assert all(path == paths.identity_state_dir() or paths.identity_state_dir() in path.parents for path in created)
    assert not any(paths.anchors_dir().iterdir())

    output_file = tmp_path / "identity-cli-output.log"
    output_file.write_text(output.out + output.err)
    private_canaries = [
        paths.identity_key_path().read_bytes(),
        paths.device_key_path().read_bytes(),
        paths.session_scope_key_path().read_bytes(),
        b"CANARY-synthetic-nonce-material",
        str(clone).encode(),
        *fx.all_canaries(),
    ]
    assert assert_no_canaries(
        [paths.identity_record_dir(identity.local_identity_id()), output_file], private_canaries
    ) == 4
    planted = tmp_path / "planted-identity-output.log"
    planted.write_text(fx.content_canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], private_canaries)


def test_atomic_install_failure_leaves_no_partial_or_pending_store(monkeypatch):
    paths.ensure_data_dir()
    paths.ensure_device_key()
    paths.ensure_identity_key()
    real_write_all = identity._write_all
    calls = 0

    def fail_second_write(fd, content):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic interrupted write")
        return real_write_all(fd, content)

    monkeypatch.setattr(identity, "_write_all", fail_second_write)
    with pytest.raises(OSError, match="synthetic interrupted"):
        identity.bootstrap_or_verify_local_identity(date=DATE, fresh_install=True)
    assert not paths.identity_record_dir(identity.local_identity_id()).exists()
    assert not any(paths.identity_records_dir().iterdir())


def test_interrupted_first_cli_bootstrap_retries_cleanly_then_remains_idempotent(
    capsys, monkeypatch
):
    real_write_all = identity._write_all
    calls = 0

    def fail_second_write(fd, content):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic interrupted bootstrap")
        return real_write_all(fd, content)

    monkeypatch.setattr(identity, "_write_all", fail_second_write)
    assert cli.main(["init", "--json"]) == 1
    first = capsys.readouterr()
    assert json.loads(first.err)["error"] == "operation_failed"
    assert paths.identity_records_dir().is_dir()
    assert not any(paths.identity_records_dir().iterdir())
    assert not paths.session_scope_key_path().exists()
    assert not paths.commit_signing_key_path().exists()

    monkeypatch.setattr(identity, "_write_all", real_write_all)
    assert cli.main(["init", "--json"]) == 0
    retry = json.loads(capsys.readouterr().out)
    assert retry["local_only"] is True
    assert retry["registered"] is False
    assert retry["published"] is False
    assert [record["type"] for record in identity.load_local_identity_chain()] == [
        "genesis",
        "device-binding",
    ]
    before = _stable_snapshot(_record_files())

    assert cli.main(["init", "--json"]) == 0
    capsys.readouterr()
    assert _stable_snapshot(_record_files()) == before


@pytest.mark.parametrize("state", ("older-key-only", "interrupted-with-conflict"))
def test_only_exact_clean_interrupted_footprint_is_retryable(state, capsys, monkeypatch):
    if state == "older-key-only":
        paths.ensure_data_dir()
        paths.ensure_device_key()
        paths.ensure_identity_key()
    else:
        real_write_all = identity._write_all
        calls = 0

        def fail_second_write(fd, content):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic interrupted bootstrap")
            return real_write_all(fd, content)

        monkeypatch.setattr(identity, "_write_all", fail_second_write)
        assert cli.main(["init", "--json"]) == 1
        capsys.readouterr()
        monkeypatch.setattr(identity, "_write_all", real_write_all)
        conflict = paths.anchors_dir() / "synthetic-conflict"
        conflict.write_bytes(b"synthetic\n")
        conflict.chmod(0o600)

    assert cli.main(["init", "--json"]) == 1
    failure = json.loads(capsys.readouterr().err)
    assert failure["error"] == "operation_failed"
    assert not paths.identity_record_dir(identity.local_identity_id()).exists()


def test_descriptor_walk_fires_when_canonical_identity_directory_is_replaced(monkeypatch):
    assert cli.main(["init", "--json"]) == 0
    identity_root = paths.identity_record_dir(identity.local_identity_id())
    original_inode = identity_root.stat().st_ino
    moved = paths.identity_records_dir() / ("cd" * 32)
    real_listdir = os.listdir
    fired = False

    def replace_after_open(directory):
        nonlocal fired
        names = real_listdir(directory)
        if (
            not fired
            and isinstance(directory, int)
            and os.fstat(directory).st_ino == original_inode
        ):
            fired = True
            identity_root.rename(moved)
            identity_root.mkdir(mode=0o700)
            identity_root.chmod(0o700)
        return names

    monkeypatch.setattr(os, "listdir", replace_after_open)
    with pytest.raises(identity.IdentityError, match="local identity state is invalid"):
        identity.load_local_identity_chain()
    assert fired


def test_descriptor_walk_fires_when_legacy_record_entry_is_replaced(tmp_path, monkeypatch):
    paths.ensure_data_dir()
    paths.ensure_device_key()
    paths.ensure_identity_key()
    clone = tmp_path / "synthetic-legacy-race"
    _legacy_dir, legacy_files = _write_legacy_clone(clone)
    target = legacy_files[1]
    target_inode = target.stat().st_ino
    target_bytes = target.read_bytes()
    moved = target.with_suffix(".moved")
    real_read = os.read
    fired = False

    def replace_entry(fd, size):
        nonlocal fired
        chunk = real_read(fd, size)
        if not fired and os.fstat(fd).st_ino == target_inode:
            fired = True
            target.rename(moved)
            target.write_bytes(target_bytes)
        return chunk

    monkeypatch.setattr(os, "read", replace_entry)
    with pytest.raises(identity.IdentityError, match="local identity state is invalid"):
        identity.migrate_founder_identity_records(clone)
    assert fired
    assert not paths.identity_record_dir(identity.local_identity_id()).exists()


@pytest.mark.parametrize("mutation", ("permission", "link"))
def test_opened_record_fd_metadata_mutations_fire_closed(mutation, monkeypatch):
    assert cli.main(["init", "--json"]) == 0
    target = next(path for path in _record_files() if path.name.startswith("device-"))
    target_inode = target.stat().st_ino
    extra = target.with_name("synthetic-extra-link")
    real_read = os.read
    fired = False

    def mutate_opened_fd(fd, size):
        nonlocal fired
        chunk = real_read(fd, size)
        if not fired and os.fstat(fd).st_ino == target_inode:
            fired = True
            if mutation == "permission":
                os.fchmod(fd, 0o644)
            else:
                os.link(target, extra)
        return chunk

    monkeypatch.setattr(os, "read", mutate_opened_fd)
    with pytest.raises(identity.IdentityError, match="local identity state is invalid"):
        identity.load_local_identity_chain()
    assert fired
