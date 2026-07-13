"""Nonce persistence — asset A2, per ADR-0002 §4.

One append-only JSONL file per session under the data dir's ``nonces/``
(0700 dir, 0600 files), one row per item: ``{"i": <index>, "nonce": "<hex>"}``.
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
    if stat.S_IMODE(f.stat().st_mode) & _LOOSE_BITS:
        raise paths.InsecurePermissionsError(
            f"nonce file {f} is group/other-accessible; expected {_FILE_MODE:04o}"
        )


def append_nonce(session_id: str, nonce: bytes) -> int:
    """Append one nonce for the session's next item; returns its item index."""
    if len(nonce) != NONCE_LEN:
        raise NonceStoreError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
    paths.ensure_data_dir()
    f = session_nonce_file(session_id)
    index = len(load_nonces(session_id)) if f.exists() else 0
    fd = os.open(f, os.O_WRONLY | os.O_APPEND | os.O_CREAT, _FILE_MODE)
    with os.fdopen(fd, "w") as out:
        out.write(json.dumps({"i": index, "nonce": nonce.hex()}) + "\n")
    _assert_tight(f)
    return index


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
