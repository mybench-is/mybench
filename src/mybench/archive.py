"""Private transcript archive (threat-model asset A9; MYB-12.1).

Each captured session has one byte-exact, append-only file at
``archive/<source>/<session-id>`` inside the 0700 mybench data directory.
Only complete records already committed to the ledger may enter the archive.
A grown source extends the existing file in place; an interrupted append is
recovered by completing the byte prefix, never by truncating or replacing it.

The archive is deliberately session-addressed rather than a CAS (owner ruling
D-B, 2026-07-14). Integrity comes from a flushed read-back checked with the
saved nonce records (A2) against the salted commitment in the private ledger
(A3). Neither A2 nor A3 is copied into this archive. Callers must preserve
capture-first ordering: archive failure is local retention loss, but must not
suppress a ledger row.
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
    """Private-archive storage, append-consistency, or verification failure."""


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


def _fsync_file(fd: int) -> None:
    os.fsync(fd)


def _fsync_dir(fd_path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(fd_path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_archive_directories(source_dir) -> None:
    # Persist the session-file entry, a lazily-created source-dir entry, and
    # the archive-root entry. This is intentionally repeated after every
    # successful verify: a prior process may have died between any barriers.
    _fsync_dir(source_dir)
    _fsync_dir(paths.archive_dir())
    _fsync_dir(paths.data_dir())


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


def _root_for(items: list[bytes], nonces: list[bytes]) -> bytes:
    leaves = [
        commitments.leaf_commitment(nonce, item)
        for nonce, item in zip(nonces[: len(items)], items)
    ]
    return commitments.session_root(leaves)


def _verified_items(
    data: bytes,
    nonces: list[bytes],
    expected_item_count: int,
    expected_root: bytes,
) -> list[bytes] | None:
    try:
        items = _items_from_readback(data)
    except ArchiveError:
        return None
    if len(items) != expected_item_count:
        return None
    return items if _root_for(items, nonces) == expected_root else None


def archive_session(
    *,
    source: str,
    session_id: str,
    source_items: list[bytes],
    nonces: list[bytes],
    expected_item_count: int,
    expected_session_root: str,
) -> ArchiveResult:
    """Extend one private transcript copy and verify it against its ledger row.

    A complete, commitment-valid existing archive is authoritative even if the
    live source later changes or shrinks.  Otherwise the live source must be a
    full, commitment-valid preimage before any suffix is appended; this avoids
    irreversibly archiving post-capture mutations.
    """
    if expected_item_count <= 0:
        raise ArchiveError("archive verification needs a positive committed item count")
    if len(nonces) < expected_item_count:
        raise ArchiveError("insufficient nonces to verify the committed archive")
    try:
        expected_root = bytes.fromhex(expected_session_root)
    except ValueError as exc:
        raise ArchiveError("ledger session root is not hexadecimal") from exc
    if len(expected_root) != 32:
        raise ArchiveError("ledger session root has the wrong length")

    archive_path = paths.archive_session_path(source, session_id)
    existed = archive_path.exists()
    source_verified = False
    if not existed:
        if len(source_items) != expected_item_count:
            raise ArchiveError(
                "missing archive requires a full live source before creation"
            )
        if _root_for(source_items, nonces) != expected_root:
            raise ArchiveError(
                "live source does not match the committed session root; refusing creation"
            )
        source_verified = True

    source_dir = paths.ensure_archive_source_dir(source)
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(archive_path, flags, _FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        _assert_tight(fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ArchiveError("archive target is not a regular file")
        existing = _read_all(fd)

        verified = _verified_items(existing, nonces, expected_item_count, expected_root)
        if verified is not None:
            # The bytes may be visible only through page cache after a prior
            # process wrote a complete suffix and died before file fsync.
            _fsync_file(fd)
            _fsync_archive_directories(source_dir)
            return ArchiveResult(bytes_appended=0, items_verified=len(verified))

        if not source_verified:
            if len(source_items) != expected_item_count:
                raise ArchiveError(
                    "incomplete archive requires a full live source before append"
                )
            if _root_for(source_items, nonces) != expected_root:
                raise ArchiveError(
                    "live source does not match the committed session root; refusing append"
                )

        target = _serialized_items(source_items)
        if target.startswith(existing):
            suffix = target[len(existing) :]
        else:
            raise ArchiveError("archive bytes diverge from the live source prefix")

        if suffix:
            if os.environ.get("MYBENCH_FAULT_ARCHIVE"):
                # Test-only deterministic crash seam: persist a strict prefix
                # and die.  The next scan must complete it without truncation.
                _write_all(fd, suffix[: max(1, len(suffix) // 2)])
                _fsync_file(fd)
                os.kill(os.getpid(), signal.SIGKILL)
            _write_all(fd, suffix)
        _fsync_file(fd)
        readback = _read_all(fd)
    finally:
        os.close(fd)  # also releases flock

    archived_items = _verified_items(readback, nonces, expected_item_count, expected_root)
    if archived_items is None:
        raise ArchiveError("archive read-back does not match the committed session root")
    _fsync_archive_directories(source_dir)
    return ArchiveResult(bytes_appended=len(suffix), items_verified=len(archived_items))


def archive_stats() -> ArchiveStats:
    """Counts-only archive disk monitor; never reads transcript bytes or exposes paths."""
    root = paths.archive_dir()
    session_files = total_bytes = 0
    if root.is_symlink():
        raise paths.PathsError("refusing symlinked archive root")
    if root.is_dir():
        for source in paths.ARCHIVE_SOURCES:
            source_dir = paths.archive_source_dir(source)
            if not source_dir.exists() and not source_dir.is_symlink():
                continue
            source_stat = source_dir.lstat()
            if stat.S_ISLNK(source_stat.st_mode):
                raise paths.PathsError("refusing symlinked archive source directory")
            if not stat.S_ISDIR(source_stat.st_mode):
                continue
            for entry in source_dir.iterdir():
                entry_stat = entry.lstat()
                if stat.S_ISLNK(entry_stat.st_mode):
                    raise paths.PathsError("refusing symlinked archive session entry")
                if stat.S_ISREG(entry_stat.st_mode):
                    session_files += 1
                    total_bytes += entry_stat.st_size
    free_bytes = shutil.disk_usage(paths.data_dir()).free
    return ArchiveStats(
        session_files=session_files,
        total_bytes=total_bytes,
        free_bytes=free_bytes,
    )
