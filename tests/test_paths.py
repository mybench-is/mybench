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


def test_refuses_data_dir_inside_git_worktree(tmp_path, monkeypatch):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    (tmp_path / "repo" / ".git" / "HEAD").write_text("ref: refs/heads/master\n")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "repo" / "data"))
    with pytest.raises(paths.DataDirInsideRepoError):
        paths.ensure_data_dir()
    assert not (tmp_path / "repo" / "data").exists()


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
