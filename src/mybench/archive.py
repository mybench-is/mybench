"""A9 raw-transcript retention archive (MYB-12.1).

Each captured session has one byte-exact, append-only file at
``archive/<source>/<session-id>`` inside the 0700 mybench data directory.
Only complete items already committed to the ledger may enter A9.  A grown
source extends the existing file in place; an interrupted append is recovered
by completing the byte prefix, never by truncating or replacing the file.

The archive is deliberately session-addressed rather than a CAS (owner ruling
D-B, 2026-07-14).  Integrity comes from fsynced read-back against the salted
session commitment in A3.  Callers must preserve capture-first ordering: a
failure here is local retention loss, but must not suppress a ledger row.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import signal
import stat
from dataclasses import dataclass

from mybench import commitments, paths

_FILE_MODE = 0o600
_LOOSE_BITS = 0o077


class ArchiveError(RuntimeError):
    """A9 storage, append-consistency, or commitment-verification failure."""


@dataclass(frozen=True)
class ArchiveResult:
    bytes_appended: int
    items_verified: int


@dataclass(frozen=True)
class ArchiveStats:
    session_files: int
    total_bytes: int
    free_bytes: int


def _assert_tight(fd: int) -> None:
    if stat.S_IMODE(os.fstat(fd).st_mode) & _LOOSE_BITS:
        raise paths.InsecurePermissionsError(
            f"archive file is group/other-accessible; expected {_FILE_MODE:04o}"
        )


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
            raise ArchiveError("archive append made no progress")
        view = view[written:]


def _fsync_dir(fd_path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(fd_path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _serialized_items(items: list[bytes]) -> bytes:
    # Capture items are raw JSONL records without the delimiter.  Reattaching
    # exactly one LF reproduces the committed source prefix, including CR in
    # CRLF input (the CR is part of the committed item).
    return b"".join(item + b"\n" for item in items)


def _items_from_readback(data: bytes) -> list[bytes]:
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise ArchiveError("archive read-back has an incomplete trailing item")
    return data[:-1].split(b"\n")


def archive_session(
    *,
    source: str,
    session_id: str,
    source_items: list[bytes],
    nonces: list[bytes],
    expected_item_count: int,
    expected_session_root: str,
) -> ArchiveResult:
    """Extend one A9 file and verify its fsynced read-back against its A3 row.

    ``source_items`` may be shorter than ``expected_item_count`` when the
    harness has already truncated a live source.  In that case an existing,
    complete archive can still verify; missing bytes are reported as an
    :class:`ArchiveError`.  It may never be longer: that would copy bytes not
    yet committed to A3.
    """
    if expected_item_count <= 0:
        raise ArchiveError("archive verification needs a positive committed item count")
    if len(source_items) > expected_item_count:
        raise ArchiveError("refusing to archive items beyond the committed ledger row")
    if len(nonces) < expected_item_count:
        raise ArchiveError("insufficient nonces to verify the committed archive")
    try:
        expected_root = bytes.fromhex(expected_session_root)
    except ValueError as exc:
        raise ArchiveError("ledger session root is not hexadecimal") from exc
    if len(expected_root) != 32:
        raise ArchiveError("ledger session root has the wrong length")

    source_dir = paths.ensure_archive_source_dir(source)
    archive_path = paths.archive_session_path(source, session_id)
    existed = archive_path.exists()
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(archive_path, flags, _FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        _assert_tight(fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ArchiveError("archive target is not a regular file")
        existing = _read_all(fd)
        target = _serialized_items(source_items)
        if target.startswith(existing):
            suffix = target[len(existing) :]
        elif existing.startswith(target):
            # The live source shrank after an earlier successful archive.  A9
            # is authoritative and append-only; read-back below decides
            # whether it still covers the ledger row.
            suffix = b""
        else:
            raise ArchiveError("archive bytes diverge from the live source prefix")

        if suffix:
            if os.environ.get("MYBENCH_FAULT_ARCHIVE"):
                # Test-only deterministic crash seam: persist a strict prefix
                # and die.  The next scan must complete it without truncation.
                _write_all(fd, suffix[: max(1, len(suffix) // 2)])
                os.fsync(fd)
                os.kill(os.getpid(), signal.SIGKILL)
            _write_all(fd, suffix)
        os.fsync(fd)
        readback = _read_all(fd)
    finally:
        os.close(fd)  # also releases flock

    if not existed:
        _fsync_dir(source_dir)

    archived_items = _items_from_readback(readback)
    if len(archived_items) != expected_item_count:
        raise ArchiveError("archive item count does not match the committed ledger row")
    leaves = [
        commitments.leaf_commitment(nonce, item)
        for nonce, item in zip(nonces[:expected_item_count], archived_items)
    ]
    if commitments.session_root(leaves) != expected_root:
        raise ArchiveError("archive read-back does not match the committed session root")
    return ArchiveResult(bytes_appended=len(suffix), items_verified=len(archived_items))


def archive_stats() -> ArchiveStats:
    """Counts-only A9 disk monitor; never reads archive bytes or exposes paths."""
    root = paths.archive_dir()
    session_files = total_bytes = 0
    if root.is_dir():
        for source in paths.ARCHIVE_SOURCES:
            source_dir = paths.archive_source_dir(source)
            if not source_dir.is_dir():
                continue
            for entry in source_dir.iterdir():
                if entry.is_file():
                    session_files += 1
                    total_bytes += entry.stat().st_size
    free_bytes = shutil.disk_usage(paths.data_dir()).free
    return ArchiveStats(
        session_files=session_files,
        total_bytes=total_bytes,
        free_bytes=free_bytes,
    )
