"""Private A8 normalized-corpus persistence boundary.

The normalizer is pure and returns canonical bytes.  This module validates
those bytes before touching the filesystem, then installs them exactly once at
``normalized/<corpus-commitment>/corpus.json``. Transcript and repository
artifacts share this content-addressed layout. Content, source filenames, and
data-directory paths never enter an error message.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

from mybench import paths

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_ARTIFACT_NAME = "corpus.json"
_TEMP_NAME = re.compile(r"\.corpus-[0-9a-f]{24}\.tmp\Z")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_CREATE_FLAGS = (
    os.O_RDWR
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class NormalizedStoreError(RuntimeError):
    """A normalized artifact was invalid or could not be stored safely."""


def _validated_commitment(artifact: bytes) -> str:
    """Validate through the pure normalizer without relaying sensitive errors."""
    if type(artifact) is not bytes:
        raise NormalizedStoreError("normalized corpus artifact is invalid")

    from mybench.normalizer.contract import (  # imported lazily to keep this boundary narrow
        NormalizationError,
        validate_corpus_artifact,
    )
    from mybench.normalizer.repo import validate_repo_corpus_artifact

    try:
        kind = json.loads(artifact).get("kind")
        if kind == "normalized-corpus-artifact":
            commitment = validate_corpus_artifact(artifact)
        elif kind == "normalized-repo-corpus-artifact":
            commitment = validate_repo_corpus_artifact(artifact)
        else:
            raise NormalizationError("unsupported normalized artifact kind")
    except (
        AttributeError,
        NormalizationError,
        RecursionError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
    ):
        raise NormalizedStoreError("normalized corpus artifact is invalid") from None
    try:
        paths.normalized_corpus_dir(commitment)
    except paths.PathsError:
        raise NormalizedStoreError("normalized corpus artifact is invalid") from None
    return commitment


def _assert_directory(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != _DIR_MODE:
        raise NormalizedStoreError("normalized corpus storage refused")


def _assert_artifact_file(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != _FILE_MODE
        or info.st_nlink != 1
    ):
        raise NormalizedStoreError("normalized corpus storage refused")


def _open_managed_directory(parent_fd: int, name: str) -> int:
    """Create/open one child directory and require an exact private mode.

    ``mkdir`` modes are filtered by the process umask.  Tight umasks are safe
    but can otherwise make a newly created directory unusable and fail the
    exact-mode check below, so a directory created by this call is explicitly
    set to 0700 before it is opened.  Existing directories are never repaired.
    """
    created = False
    try:
        os.mkdir(name, _DIR_MODE, dir_fd=parent_fd)
    except FileExistsError:
        pass
    else:
        created = True
        os.chmod(name, _DIR_MODE, dir_fd=parent_fd)

    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    try:
        _assert_directory(fd)
        if created:
            # Persist the inode mode before its parent directory entry.
            os.fsync(fd)
            os.fsync(parent_fd)
    except Exception:
        os.close(fd)
        raise
    return fd


@contextmanager
def _open_corpus_directory(commitment: str):
    """Create/open each managed directory relative to an already-open parent."""
    descriptors: list[int] = []
    try:
        paths.ensure_data_dir()
        data_fd = os.open(paths.data_dir(), _DIRECTORY_FLAGS)
        descriptors.append(data_fd)
        _assert_directory(data_fd)

        normalized_fd = _open_managed_directory(data_fd, "normalized")
        descriptors.append(normalized_fd)

        corpus_fd = _open_managed_directory(normalized_fd, commitment)
        descriptors.append(corpus_fd)
        fcntl.flock(corpus_fd, fcntl.LOCK_EX)
        yield corpus_fd
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _read_all(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while chunk := os.read(fd, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise NormalizedStoreError("normalized corpus storage refused")
        view = view[written:]


def _existing_artifact(corpus_fd: int) -> bytes | None:
    try:
        info = os.stat(_ARTIFACT_NAME, dir_fd=corpus_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != _FILE_MODE:
        raise NormalizedStoreError("normalized corpus storage refused")

    fd = os.open(_ARTIFACT_NAME, _READ_FLAGS, dir_fd=corpus_fd)
    try:
        _assert_artifact_file(fd)
        artifact = _read_all(fd)
        # Re-establish the file durability barrier after a process restart.
        os.fsync(fd)
        return artifact
    finally:
        os.close(fd)


def _temp_entries(corpus_fd: int) -> list[str]:
    return sorted(name for name in os.listdir(corpus_fd) if _TEMP_NAME.fullmatch(name))


def _safe_temp_info(corpus_fd: int, name: str):
    info = os.stat(name, dir_fd=corpus_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != _FILE_MODE
        or info.st_nlink not in {1, 2}
    ):
        raise NormalizedStoreError("normalized corpus storage refused")
    return info


def _recover_interrupted_install(corpus_fd: int) -> None:
    """Remove private orphan temps and finish a durable two-link install."""
    temps = _temp_entries(corpus_fd)
    try:
        final_info = os.stat(_ARTIFACT_NAME, dir_fd=corpus_fd, follow_symlinks=False)
    except FileNotFoundError:
        final_info = None

    linked_temp = None
    if final_info is not None:
        if not stat.S_ISREG(final_info.st_mode) or stat.S_IMODE(final_info.st_mode) != _FILE_MODE:
            raise NormalizedStoreError("normalized corpus storage refused")
        if final_info.st_nlink == 2:
            matches = []
            for name in temps:
                info = _safe_temp_info(corpus_fd, name)
                if (info.st_dev, info.st_ino) == (final_info.st_dev, final_info.st_ino):
                    matches.append(name)
            if len(matches) != 1:
                raise NormalizedStoreError("normalized corpus storage refused")
            linked_temp = matches[0]
        elif final_info.st_nlink != 1:
            raise NormalizedStoreError("normalized corpus storage refused")

    changed = False
    for name in temps:
        info = _safe_temp_info(corpus_fd, name)
        if name != linked_temp and info.st_nlink != 1:
            raise NormalizedStoreError("normalized corpus storage refused")
        os.unlink(name, dir_fd=corpus_fd)
        changed = True
    if changed:
        os.fsync(corpus_fd)


def _new_temp(corpus_fd: int) -> tuple[str, int]:
    for _ in range(8):
        name = f".corpus-{secrets.token_hex(12)}.tmp"
        try:
            fd = os.open(name, _CREATE_FLAGS, _FILE_MODE, dir_fd=corpus_fd)
        except FileExistsError:
            continue
        try:
            os.fchmod(fd, _FILE_MODE)
            _assert_artifact_file(fd)
        except Exception:
            os.close(fd)
            _remove_temp(corpus_fd, name)
            raise
        return name, fd
    raise NormalizedStoreError("normalized corpus storage refused")


def _remove_temp(corpus_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=corpus_fd)
    except FileNotFoundError:
        pass


def _install_new_artifact(corpus_fd: int, artifact: bytes) -> None:
    temp_name, temp_fd = _new_temp(corpus_fd)
    try:
        try:
            _write_all(temp_fd, artifact)
            os.fsync(temp_fd)
            if _read_all(temp_fd) != artifact:
                raise NormalizedStoreError("normalized corpus storage refused")
        finally:
            os.close(temp_fd)

        try:
            # Hard-link installation is atomic and, unlike replace(), cannot
            # overwrite a concurrently installed or pre-existing artifact.
            os.link(
                temp_name,
                _ARTIFACT_NAME,
                src_dir_fd=corpus_fd,
                dst_dir_fd=corpus_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = _existing_artifact(corpus_fd)
            if existing != artifact:
                raise NormalizedStoreError("normalized corpus storage refused") from None
        else:
            # Persist the target directory entry before removing the temporary
            # name, so a crash can never expose a partial corpus.json.
            os.fsync(corpus_fd)
    finally:
        _remove_temp(corpus_fd, temp_name)
        os.fsync(corpus_fd)


def store_corpus_artifact(artifact: bytes) -> Path:
    """Validate and durably store one canonical A8 corpus artifact.

    An exact existing artifact is an idempotent success.  Any other existing
    entry, address mismatch, insecure mode, or managed symlink is refused and
    never overwritten.
    """
    commitment = _validated_commitment(artifact)
    try:
        # Re-check at the mutation boundary even if a caller/test substitutes
        # the validator: an invalid component must not create any directory.
        paths.normalized_corpus_dir(commitment)
        with _open_corpus_directory(commitment) as corpus_fd:
            _recover_interrupted_install(corpus_fd)
            existing = _existing_artifact(corpus_fd)
            if existing is not None:
                if existing != artifact:
                    raise NormalizedStoreError("normalized corpus storage refused")
                os.fsync(corpus_fd)
            else:
                _install_new_artifact(corpus_fd, artifact)
        return paths.normalized_corpus_path(commitment)
    except NormalizedStoreError:
        raise
    except (OSError, paths.PathsError):
        raise NormalizedStoreError("normalized corpus storage refused") from None
