"""MYB-2.1: mybench.paths — data-dir bootstrap, perms policy, repo refusal, device key."""

import os
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from mybench import paths
from tests.conftest import REPO_ROOT, scan_repo_for_data_artifacts

SRC = REPO_ROOT / "src" / "mybench"


def mode_of(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_honors_xdg_override(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "elsewhere"))
    assert paths.data_dir() == tmp_path / "elsewhere" / "mybench"


def test_fresh_bootstrap_fsyncs_managed_directory_entries_to_existing_parent(
    tmp_path, monkeypatch
):
    xdg = tmp_path / "fresh-xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    events = []
    real_fsync_directory = paths._fsync_directory

    def tracked_fsync_directory(directory):
        events.append(directory)
        real_fsync_directory(directory)

    monkeypatch.setattr(paths, "_fsync_directory", tracked_fsync_directory)
    d = paths.ensure_data_dir()
    expected = [d, xdg, tmp_path]
    for subdir in (
        paths.nonces_dir(),
        paths.ledger_dir(),
        paths.archive_dir(),
        paths.keys_dir(),
        paths.anchors_dir(),
        paths.enrollments_dir(),
    ):
        expected.extend((subdir, d))
    assert events[: len(expected)] == expected
    assert events[len(expected) :] == [d.absolute(), *d.absolute().parents]


def test_precreated_visible_data_tree_gets_restart_durability_barrier(
    tmp_path, monkeypatch
):
    xdg = tmp_path / "visible-xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    d = paths.data_dir()
    managed = (
        d,
        paths.nonces_dir(),
        paths.ledger_dir(),
        paths.archive_dir(),
        paths.keys_dir(),
        paths.anchors_dir(),
        paths.enrollments_dir(),
    )
    for directory in managed:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)

    events = []
    real_fsync_directory = paths._fsync_directory

    def tracked_fsync_directory(directory):
        events.append(directory)
        real_fsync_directory(directory)

    monkeypatch.setattr(paths, "_fsync_directory", tracked_fsync_directory)
    assert paths.ensure_data_dir() == d
    assert events[: len(managed)] == list(managed)
    assert events[len(managed) :] == [d.absolute(), *d.absolute().parents]


def test_ensure_creates_tree_0700():
    d = paths.ensure_data_dir()
    for p in (d, paths.nonces_dir(), paths.ledger_dir(), paths.archive_dir(), paths.keys_dir()):
        assert p.is_dir()
        assert mode_of(p) == 0o700


def test_ensure_is_idempotent():
    assert paths.ensure_data_dir() == paths.ensure_data_dir()


def test_loose_perms_on_existing_dir_fail_loudly():
    d = paths.data_dir()
    d.mkdir(parents=True)
    os.chmod(d, 0o755)
    with pytest.raises(paths.InsecurePermissionsError):
        paths.ensure_data_dir()
    # Decided behavior: error, don't repair — perms must be untouched.
    assert mode_of(d) == 0o755


def test_loose_perms_on_existing_subdir_fail_loudly():
    paths.ensure_data_dir()
    os.chmod(paths.nonces_dir(), 0o750)
    with pytest.raises(paths.InsecurePermissionsError):
        paths.ensure_data_dir()


def test_symlinked_data_dir_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    outside = tmp_path / "outside"
    outside.mkdir()
    d = paths.data_dir()
    d.parent.mkdir(parents=True)
    d.symlink_to(outside, target_is_directory=True)
    with pytest.raises(paths.PathsError, match="symlinked"):
        paths.ensure_data_dir()


def test_symlinked_managed_archive_dir_is_rejected(tmp_path):
    paths.ensure_data_dir()
    paths.archive_dir().rmdir()
    outside = tmp_path / "outside-archive"
    outside.mkdir()
    paths.archive_dir().symlink_to(outside, target_is_directory=True)
    with pytest.raises(paths.PathsError, match="symlinked"):
        paths.ensure_data_dir()


def test_refuses_data_dir_inside_git_worktree(tmp_path, monkeypatch):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    (tmp_path / "repo" / ".git" / "HEAD").write_text("ref: refs/heads/master\n")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "repo" / "data"))
    with pytest.raises(paths.DataDirInsideRepoError):
        paths.ensure_data_dir()
    assert not (tmp_path / "repo" / "data").exists()


def test_refuses_data_dir_whose_xdg_symlink_resolves_inside_repo(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/master\n")
    (repo / "xdg").mkdir()
    linked_xdg = tmp_path / "linked-xdg"
    linked_xdg.symlink_to(repo / "xdg", target_is_directory=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(linked_xdg))
    with pytest.raises(paths.DataDirInsideRepoError):
        paths.ensure_data_dir()


def test_refuses_linked_worktree_gitfile(tmp_path, monkeypatch):
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text("gitdir: /nowhere\n")
    monkeypatch.setenv("XDG_DATA_HOME", str(wt / "data"))
    with pytest.raises(paths.DataDirInsideRepoError):
        paths.ensure_data_dir()


def test_device_key_created_0600_and_idempotent():
    key, pub = paths.ensure_device_key()
    assert mode_of(key) == 0o600
    key_bytes, pub_bytes = key.read_bytes(), pub.read_bytes()
    # Never regenerated/overwritten on a second call (ADR-0002 §5).
    paths.ensure_device_key()
    assert key.read_bytes() == key_bytes
    assert pub.read_bytes() == pub_bytes


def test_device_key_signs_and_pub_verifies():
    key, pub = paths.ensure_device_key()
    private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    public = serialization.load_pem_public_key(pub.read_bytes())
    msg = b"synthetic anchor artifact bytes"
    public.verify(private.sign(msg), msg)  # raises on mismatch


def test_missing_pub_is_rederived_from_private():
    key, pub = paths.ensure_device_key()
    original = pub.read_bytes()
    pub.unlink()
    paths.ensure_device_key()
    assert pub.read_bytes() == original


def test_loose_perms_on_existing_key_fail_loudly():
    key, _ = paths.ensure_device_key()
    os.chmod(key, 0o644)
    with pytest.raises(paths.InsecurePermissionsError):
        paths.ensure_device_key()


def test_no_hardcoded_data_paths_outside_paths_module():
    # AC #3: only mybench.paths may construct data-dir locations.
    forbidden = ("XDG_DATA_HOME", ".local/share", "~/.local")
    offenders = [
        (py, marker)
        for py in SRC.rglob("*.py")
        if py.name != "paths.py"
        for marker in forbidden
        if marker in py.read_text()
    ]
    assert offenders == []


def test_repo_tree_clean_of_data_artifacts():
    # AC #4 (also enforced suite-wide by the pytest_sessionfinish guard).
    assert scan_repo_for_data_artifacts() == []


def test_real_default_data_dir_is_outside_all_repos(monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    d = paths.data_dir()
    probe = subprocess.run(
        ["git", "-C", str(d.parent if not d.exists() else d), "rev-parse", "--git-dir"],
        capture_output=True,
        text=True,
    )
    assert probe.returncode != 0, f"default data dir {d} resolves inside a git repo"
