"""Nonce persistence — asset A2, per ADR-0002 §4.

One append-only JSONL file per session under the data dir's ``nonces/``
(0700 dir, 0600 files), one row per item: ``{"i": <index>, "nonce": "<hex>"}``.
Each row is fsynced; before capture appends an A3 row, the complete nonce file,
nonce directory, and data directory are fsynced in that order.
Session ids must be opaque (source UUIDs) — never path- or content-derived.
Nonces never leave this directory: not into the ledger's publishable views,
any repo, log, or test output (privacy invariants #1–2).
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from mybench import paths
from mybench.commitments import NONCE_LEN

_SESSION_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_FILE_MODE = 0o600
_LOOSE_BITS = 0o077


class NonceStoreError(RuntimeError):
    pass


def session_nonce_file(session_id: str) -> Path:
    if not _SESSION_ID_RE.fullmatch(session_id):
        raise NonceStoreError(
            f"invalid session id {session_id!r}: must be opaque [A-Za-z0-9_-]{{1,64}} "
            "(never a path- or content-derived name, ADR-0002 §4)"
        )
    return paths.nonces_dir() / f"{session_id}.jsonl"


def _assert_tight(f: Path) -> None:
    if f.is_symlink():
        raise NonceStoreError("refusing symlinked nonce file")
    if stat.S_IMODE(f.stat().st_mode) & _LOOSE_BITS:
        raise paths.InsecurePermissionsError(
            f"nonce file {f} is group/other-accessible; expected {_FILE_MODE:04o}"
        )


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise NonceStoreError("nonce append made no progress")
        view = view[written:]


def _fsync_file(fd: int) -> None:
    os.fsync(fd)


def _fsync_parent(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def append_nonce(session_id: str, nonce: bytes) -> int:
    """Durably append one nonce; A2 reaches disk before A3 may reference it."""
    if len(nonce) != NONCE_LEN:
        raise NonceStoreError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
    paths.ensure_data_dir()
    f = session_nonce_file(session_id)
    existed = f.exists()
    index = len(load_nonces(session_id)) if existed else 0
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(f, flags, _FILE_MODE)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NonceStoreError("nonce target is not a regular file")
        row = json.dumps({"i": index, "nonce": nonce.hex()}).encode() + b"\n"
        _write_all(fd, row)
        _fsync_file(fd)
    finally:
        os.close(fd)
    if not existed:
        _fsync_parent(f.parent)
    _assert_tight(f)
    return index


def ensure_durable(session_id: str) -> None:
    """Re-fsync a complete A2 file, nonce dir, and data dir before A3 append.

    Restart may observe a complete row left page-cache-visible by a process
    that died before its original fsync.  Count reconciliation alone cannot
    distinguish that row from a durable one, so capture calls this even when
    it did not append a fresh nonce in the current process.
    """
    f = session_nonce_file(session_id)
    if not f.exists():
        raise NonceStoreError("nonce file is missing before ledger append")
    _assert_tight(f)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(f, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NonceStoreError("nonce target is not a regular file")
        _fsync_file(fd)
    finally:
        os.close(fd)
    _fsync_parent(f.parent)
    _fsync_parent(paths.data_dir())


def load_nonces(session_id: str) -> list[bytes]:
    """Load a session's nonces in item order; strict about gaps and malformed rows."""
    f = session_nonce_file(session_id)
    if not f.exists():
        return []
    _assert_tight(f)
    nonces = []
    for lineno, line in enumerate(f.read_text().splitlines()):
        row = json.loads(line)
        if row.get("i") != lineno:
            raise NonceStoreError(f"{f}: row {lineno} has index {row.get('i')} (gap/reorder)")
        nonce = bytes.fromhex(row["nonce"])
        if len(nonce) != NONCE_LEN:
            raise NonceStoreError(f"{f}: row {lineno} nonce is {len(nonce)} bytes")
        nonces.append(nonce)
    return nonces
