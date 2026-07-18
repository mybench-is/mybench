"""Private persistence boundary for workflow-phase artifacts.

Phase streams are A8-derived and may contain ordered behavioral structure.
This boundary stores their canonical, identifier-free representation only
under the existing mode-0700 normalized data root, with mode-0600 files.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

from mybench import paths
from mybench.normalizer.workflow_phase import workflow_phase_artifact

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_PHASE_DIRECTORY = "workflow-phases"
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class WorkflowPhaseStoreError(RuntimeError):
    """A phase artifact could not be stored at the private boundary."""


def _assert_directory(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != _DIR_MODE:
        raise WorkflowPhaseStoreError("workflow phase storage refused")


def _assert_artifact(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != _FILE_MODE
        or info.st_nlink != 1
    ):
        raise WorkflowPhaseStoreError("workflow phase storage refused")


def _write_all(fd: int, artifact: bytes) -> None:
    remaining = memoryview(artifact)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise WorkflowPhaseStoreError("workflow phase storage refused")
        remaining = remaining[written:]


def _read_all(fd: int) -> bytes:
    chunks = []
    while chunk := os.read(fd, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def _open_phase_directory() -> tuple[int, Path]:
    paths.ensure_normalized_dir()
    normalized_fd = os.open(paths.normalized_dir(), _DIRECTORY_FLAGS)
    try:
        _assert_directory(normalized_fd)
        created = False
        try:
            os.mkdir(_PHASE_DIRECTORY, _DIR_MODE, dir_fd=normalized_fd)
        except FileExistsError:
            pass
        else:
            created = True
            os.chmod(_PHASE_DIRECTORY, _DIR_MODE, dir_fd=normalized_fd)
        phase_fd = os.open(_PHASE_DIRECTORY, _DIRECTORY_FLAGS, dir_fd=normalized_fd)
        try:
            _assert_directory(phase_fd)
            if created:
                os.fsync(phase_fd)
                os.fsync(normalized_fd)
        except Exception:
            os.close(phase_fd)
            raise
    finally:
        os.close(normalized_fd)
    return phase_fd, paths.normalized_dir() / _PHASE_DIRECTORY


def _store_bytes(phase_fd: int, name: str, artifact: bytes) -> None:
    try:
        existing_fd = os.open(name, _READ_FLAGS, dir_fd=phase_fd)
    except FileNotFoundError:
        existing_fd = None
    if existing_fd is not None:
        try:
            _assert_artifact(existing_fd)
            if _read_all(existing_fd) != artifact:
                raise WorkflowPhaseStoreError("workflow phase storage refused")
            os.fsync(existing_fd)
            return
        finally:
            os.close(existing_fd)

    fd = os.open(name, _CREATE_FLAGS, _FILE_MODE, dir_fd=phase_fd)
    try:
        os.fchmod(fd, _FILE_MODE)
        _assert_artifact(fd)
        try:
            _write_all(fd, artifact)
            os.fsync(fd)
        except Exception:
            os.close(fd)
            fd = -1
            os.unlink(name, dir_fd=phase_fd)
            os.fsync(phase_fd)
            raise
    finally:
        if fd >= 0:
            os.close(fd)
    os.fsync(phase_fd)


def store_workflow_phase_artifact(events: Sequence[Mapping[str, object]]) -> Path:
    """Classify and store one content-addressed artifact under private A8."""

    artifact = workflow_phase_artifact(events)
    name = hashlib.sha256(artifact).hexdigest() + ".json"
    phase_fd = -1
    try:
        phase_fd, phase_dir = _open_phase_directory()
        fcntl.flock(phase_fd, fcntl.LOCK_EX)
        _store_bytes(phase_fd, name, artifact)
        return phase_dir / name
    except WorkflowPhaseStoreError:
        raise
    except (OSError, paths.PathsError):
        raise WorkflowPhaseStoreError("workflow phase storage refused") from None
    finally:
        if phase_fd >= 0:
            os.close(phase_fd)


__all__ = ["WorkflowPhaseStoreError", "store_workflow_phase_artifact"]
