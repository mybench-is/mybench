"""A8 normalized-store boundary: addressing, permissions, and atomic writes."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from mybench import normalized_store, paths
from tests.conftest import REPO_ROOT

ROOT_A = "ab" * 32
ROOT_B = "cd" * 32
ARTIFACT_A = b'{"events":[],"schema_version":"1"}'
ARTIFACT_B = b'{"events":[{"kind":"synthetic"}],"schema_version":"1"}'
CANARY = "MYBENCH-CANARY-NORMALIZED-STORE"
REAL_VALIDATED_COMMITMENT = normalized_store._validated_commitment


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture(autouse=True)
def validated_artifacts(monkeypatch):
    commitments = {ARTIFACT_A: ROOT_A, ARTIFACT_B: ROOT_B}

    def validate(artifact):
        try:
            return commitments[artifact]
        except (KeyError, TypeError):
            raise normalized_store.NormalizedStoreError(
                "normalized corpus artifact is invalid"
            ) from None

    monkeypatch.setattr(normalized_store, "_validated_commitment", validate)


def assert_generic_refusal(exc: pytest.ExceptionInfo[normalized_store.NormalizedStoreError]):
    message = str(exc.value)
    assert message == "normalized corpus storage refused"
    assert CANARY not in message
    assert str(paths.data_dir()) not in message


def test_normalized_paths_are_content_addressed_and_closed():
    assert paths.normalized_dir() == paths.data_dir() / "normalized"
    assert paths.normalized_corpus_dir(ROOT_A) == paths.normalized_dir() / ROOT_A
    assert paths.normalized_corpus_path(ROOT_A) == paths.normalized_dir() / ROOT_A / "corpus.json"

    for invalid in ("", "AB" * 32, "a" * 63, "a" * 65, "../" + ROOT_A, ROOT_A + "/x", None):
        with pytest.raises(paths.PathsError, match="invalid normalized corpus commitment"):
            paths.normalized_corpus_dir(invalid)


def test_store_creates_private_tree_at_validated_root():
    artifact_path = normalized_store.store_corpus_artifact(ARTIFACT_A)

    assert artifact_path == paths.normalized_corpus_path(ROOT_A)
    assert artifact_path.read_bytes() == ARTIFACT_A
    assert artifact_path.resolve().is_relative_to(paths.data_dir().resolve())
    assert REPO_ROOT not in artifact_path.resolve().parents
    for directory in (
        paths.data_dir(),
        paths.normalized_dir(),
        paths.normalized_corpus_dir(ROOT_A),
    ):
        assert directory.is_dir()
        assert mode_of(directory) == 0o700
    assert mode_of(artifact_path) == 0o600


def test_store_creation_sets_exact_modes_under_restrictive_umask():
    # Isolate this regression to the normalized-store children: the shared data
    # root is provisioned before applying an umask that removes every mkdir bit.
    paths.ensure_data_dir()
    previous = os.umask(0o777)
    try:
        artifact_path = normalized_store.store_corpus_artifact(ARTIFACT_A)
    finally:
        os.umask(previous)

    assert mode_of(paths.normalized_dir()) == 0o700
    assert mode_of(paths.normalized_corpus_dir(ROOT_A)) == 0o700
    assert mode_of(artifact_path) == 0o600


def test_exact_existing_artifact_is_idempotent(monkeypatch):
    artifact_path = normalized_store.store_corpus_artifact(ARTIFACT_A)
    before = artifact_path.stat()

    def should_not_install(*_args, **_kwargs):
        raise AssertionError("idempotent write attempted a second installation")

    monkeypatch.setattr(normalized_store, "_install_new_artifact", should_not_install)
    assert normalized_store.store_corpus_artifact(ARTIFACT_A) == artifact_path
    after = artifact_path.stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size) == (
        before.st_dev,
        before.st_ino,
        before.st_mtime_ns,
        before.st_size,
    )


def test_new_artifact_is_fsynced_before_exclusive_atomic_install(monkeypatch):
    paths.ensure_normalized_corpus_dir(ROOT_A)
    events = []
    real_fsync = os.fsync
    real_link = os.link

    def tracked_fsync(fd):
        kind = "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
        events.append(f"fsync:{kind}")
        real_fsync(fd)

    def checked_link(src, dst, **kwargs):
        assert dst == "corpus.json"
        with pytest.raises(FileNotFoundError):
            os.stat(dst, dir_fd=kwargs["dst_dir_fd"], follow_symlinks=False)
        fd = os.open(src, os.O_RDONLY, dir_fd=kwargs["src_dir_fd"])
        try:
            assert stat.S_ISREG(os.fstat(fd).st_mode)
            assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
            assert os.read(fd, len(ARTIFACT_A) + 1) == ARTIFACT_A
        finally:
            os.close(fd)
        events.append("link")
        return real_link(src, dst, **kwargs)

    monkeypatch.setattr(normalized_store.os, "fsync", tracked_fsync)
    monkeypatch.setattr(normalized_store.os, "link", checked_link)
    normalized_store.store_corpus_artifact(ARTIFACT_A)

    assert events == ["fsync:file", "link", "fsync:dir", "fsync:dir"]


def test_failed_write_leaves_no_partial_artifact_or_temp(monkeypatch):
    corpus_dir = paths.ensure_normalized_corpus_dir(ROOT_A)

    def fail_write(_fd, _artifact):
        raise normalized_store.NormalizedStoreError("normalized corpus storage refused")

    monkeypatch.setattr(normalized_store, "_write_all", fail_write)
    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert list(corpus_dir.iterdir()) == []


def test_restart_recovers_durable_two_link_install():
    corpus_dir = paths.ensure_normalized_corpus_dir(ROOT_A)
    temp = corpus_dir / (".corpus-" + "1" * 24 + ".tmp")
    artifact_path = paths.normalized_corpus_path(ROOT_A)
    temp.write_bytes(ARTIFACT_A)
    temp.chmod(0o600)
    os.link(temp, artifact_path)
    assert artifact_path.stat().st_nlink == 2

    assert normalized_store.store_corpus_artifact(ARTIFACT_A) == artifact_path
    assert artifact_path.read_bytes() == ARTIFACT_A
    assert artifact_path.stat().st_nlink == 1
    assert not temp.exists()


def test_restart_removes_partial_orphan_temp_before_retry():
    corpus_dir = paths.ensure_normalized_corpus_dir(ROOT_A)
    orphan = corpus_dir / (".corpus-" + "2" * 24 + ".tmp")
    orphan.write_bytes(b"partial synthetic normalized artifact")
    orphan.chmod(0o600)

    artifact_path = normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert artifact_path.read_bytes() == ARTIFACT_A
    assert not orphan.exists()


def test_restart_refuses_orphan_temp_hardlinked_outside_store(tmp_path):
    corpus_dir = paths.ensure_normalized_corpus_dir(ROOT_A)
    orphan = corpus_dir / (".corpus-" + "3" * 24 + ".tmp")
    orphan.write_bytes(ARTIFACT_A)
    orphan.chmod(0o600)
    outside = tmp_path / "outside-temp-hardlink"
    os.link(orphan, outside)

    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert outside.read_bytes() == ARTIFACT_A
    assert not paths.normalized_corpus_path(ROOT_A).exists()


def test_store_creates_managed_subdirs_via_open_parent_descriptors(monkeypatch):
    def unsafe_path_helper(_commitment):
        raise AssertionError("store used the pathname-based convenience helper")

    monkeypatch.setattr(paths, "ensure_normalized_corpus_dir", unsafe_path_helper)
    artifact_path = normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert artifact_path.read_bytes() == ARTIFACT_A


def test_mismatched_existing_artifact_is_never_overwritten(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / CANARY))
    artifact_path = normalized_store.store_corpus_artifact(ARTIFACT_A)
    planted = f'{{"content":"{CANARY}"}}'.encode()
    artifact_path.write_bytes(planted)
    artifact_path.chmod(0o600)

    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert artifact_path.read_bytes() == planted


def test_validator_root_must_be_lowercase_64_hex(monkeypatch):
    monkeypatch.setattr(normalized_store, "_validated_commitment", lambda _artifact: "AB" * 32)
    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert not paths.normalized_dir().exists()


def test_symlinked_normalized_root_is_refused(tmp_path):
    paths.ensure_data_dir()
    outside = tmp_path / f"{CANARY}-root"
    outside.mkdir(mode=0o700)
    paths.normalized_dir().symlink_to(outside, target_is_directory=True)

    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert not (outside / ROOT_A).exists()


def test_symlinked_corpus_directory_is_refused(tmp_path):
    paths.ensure_normalized_dir()
    outside = tmp_path / f"{CANARY}-corpus"
    outside.mkdir(mode=0o700)
    paths.normalized_corpus_dir(ROOT_A).symlink_to(outside, target_is_directory=True)

    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert not (outside / "corpus.json").exists()


def test_symlinked_artifact_is_refused_without_following_target(tmp_path):
    corpus_dir = paths.ensure_normalized_corpus_dir(ROOT_A)
    outside = tmp_path / f"{CANARY}-artifact"
    planted = CANARY.encode()
    outside.write_bytes(planted)
    outside.chmod(0o600)
    paths.normalized_corpus_path(ROOT_A).symlink_to(outside)

    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert outside.read_bytes() == planted
    assert paths.normalized_corpus_path(ROOT_A).is_symlink()
    assert mode_of(corpus_dir) == 0o700


def test_hardlinked_artifact_is_refused_as_outside_data_tree(tmp_path):
    artifact_path = normalized_store.store_corpus_artifact(ARTIFACT_A)
    outside = tmp_path / f"{CANARY}-hardlink"
    os.link(artifact_path, outside)

    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert outside.read_bytes() == ARTIFACT_A


@pytest.mark.parametrize("target", ["root", "corpus", "artifact"])
def test_loose_existing_modes_are_refused_not_repaired(target):
    if target == "artifact":
        path = normalized_store.store_corpus_artifact(ARTIFACT_A)
        path.chmod(0o644)
        expected_mode = 0o644
    else:
        paths.ensure_normalized_corpus_dir(ROOT_A)
        path = (
            paths.normalized_dir()
            if target == "root"
            else paths.normalized_corpus_dir(ROOT_A)
        )
        path.chmod(0o750)
        expected_mode = 0o750

    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert mode_of(path) == expected_mode


def test_invalid_artifact_error_does_not_echo_artifact(monkeypatch):
    artifact = f'{{"content":"{CANARY}"}}'.encode()

    def reject(_artifact):
        raise normalized_store.NormalizedStoreError("normalized corpus artifact is invalid")

    monkeypatch.setattr(normalized_store, "_validated_commitment", reject)
    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(artifact)
    assert str(exc.value) == "normalized corpus artifact is invalid"
    assert CANARY not in str(exc.value)
    assert not paths.normalized_dir().exists()


def test_core_validation_error_is_reduced_to_a_generic_boundary_error(monkeypatch):
    artifact = f'{{"content":"{CANARY}"}}'.encode()
    monkeypatch.setattr(
        normalized_store,
        "_validated_commitment",
        REAL_VALIDATED_COMMITMENT,
    )

    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(artifact)
    assert str(exc.value) == "normalized corpus artifact is invalid"
    assert CANARY not in str(exc.value)
    assert not paths.normalized_dir().exists()


def test_store_refuses_data_dir_inside_repo_without_leaking_path(tmp_path, monkeypatch):
    repo = tmp_path / CANARY
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/master\n")
    monkeypatch.setenv("XDG_DATA_HOME", str(repo / "private-data"))

    with pytest.raises(normalized_store.NormalizedStoreError) as exc:
        normalized_store.store_corpus_artifact(ARTIFACT_A)
    assert_generic_refusal(exc)
    assert not (repo / "private-data").exists()
