"""Hash-chained append-only ledger — asset A3, the trust root for anchors/scorer/verify.

Storage strategy (MYB-2.4 AC #4, stress-tested by MYB-2.6): one checksummed
JSON row per line in ``ledger/ledger.jsonl`` under the data dir, appended with
a single ``O_APPEND`` write followed by fsync. Every row embeds its own hash
``h = SHA-256("mybench:v1:ledgerrow" || canonical JSON without h)`` and the
previous row's ``h`` (``prev``; the genesis row uses 64 zeros). A torn
trailing write therefore fails JSON parsing or the ``h`` recomputation and is
reported as :class:`TornTailError`, distinct from corruption elsewhere.

Rows are metadata only. The schema (``schemas/ledger_entry.schema.json``,
version "1", ``additionalProperties: false``) is enforced on write AND read,
making content/filename fields structurally impossible (invariant #1).

Writers serialize on ``<ledger>.lock`` (MYB-3.7): the read-tip → append pair
must be atomic, or two concurrent writers (capture daemon, post-commit hooks,
the reconciliation sweep) fork the chain with duplicate ``i``/``prev`` — a
state ``verify_chain`` rejects and ``recover`` cannot repair. The lock is held
per append, never across a whole sweep, so a post-commit hook waits at most
one append.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from mybench import paths
from mybench.schemas import load_validator

DOMAIN_ROW = b"mybench:v1:ledgerrow"
GENESIS_PREV = "0" * 64
SCHEMA_VERSION = "1"
_FILE_MODE = 0o600
_LOOSE_BITS = 0o077


class LedgerError(RuntimeError):
    """Chain, schema, or storage violation anywhere in the ledger."""


class TornTailError(LedgerError):
    """Only the final row is unreadable — the signature of an interrupted append."""


def _canonical(row: dict) -> bytes:
    return json.dumps(
        {k: v for k, v in row.items() if k != "h"}, sort_keys=True, separators=(",", ":")
    ).encode()


def row_hash(row: dict) -> str:
    return hashlib.sha256(DOMAIN_ROW + _canonical(row)).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Ledger:
    def __init__(self, path: Path | None = None):
        self.path = path if path is not None else paths.ledger_dir() / "ledger.jsonl"
        self._schema = load_validator("ledger_entry.schema.json")

    # -- validation ------------------------------------------------------------

    def _validate_row(self, row: dict, context: str) -> None:
        errors = sorted(self._schema.iter_errors(row), key=str)
        if errors:
            raise LedgerError(f"{context}: schema violation: {errors[0].message}")

    # -- reading ---------------------------------------------------------------

    def rows(self) -> list[dict]:
        """Parse and schema-validate every row; classify a broken final line as torn."""
        if not self.path.exists():
            return []
        if stat.S_IMODE(self.path.stat().st_mode) & _LOOSE_BITS:
            raise paths.InsecurePermissionsError(f"{self.path} is group/other-accessible")
        data = self.path.read_bytes()
        lines = data.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        elif lines:
            raise TornTailError(f"{self.path}: final row has no newline (interrupted append)")
        rows = []
        for n, line in enumerate(lines):
            try:
                row = json.loads(line)
            except ValueError as exc:
                if n == len(lines) - 1:
                    raise TornTailError(f"{self.path}: final row unparseable: {exc}") from exc
                raise LedgerError(f"{self.path}: row {n} unparseable: {exc}") from exc
            self._validate_row(row, f"row {n}")
            rows.append(row)
        return rows

    def verify_chain(self, expect_tip: str | None = None) -> int:
        """Re-validate the whole chain; returns the row count (0 = no ledger yet).

        A valid prefix of the chain is itself a valid chain, so trailing-row
        deletion is undetectable from the file alone; pass ``expect_tip`` (the
        last row hash recorded elsewhere, e.g. in a published anchor) to close
        that gap (ADV-6).
        """
        rows = self.rows()
        for n, row in enumerate(rows):
            if row["i"] != n:
                raise LedgerError(f"row {n}: index {row['i']} out of sequence")
            if (row["type"] == "genesis") != (n == 0):
                raise LedgerError(f"row {n}: genesis must appear exactly once, at row 0")
            expected_prev = GENESIS_PREV if n == 0 else rows[n - 1]["h"]
            if row["prev"] != expected_prev:
                raise LedgerError(f"row {n}: prev hash does not match row {n - 1}")
            if row_hash(row) != row["h"]:
                where = "torn or tampered final row" if n == len(rows) - 1 else "tampered row"
                err = TornTailError if n == len(rows) - 1 else LedgerError
                raise err(f"row {n}: h mismatch ({where})")
        if expect_tip is not None and (not rows or rows[-1]["h"] != expect_tip):
            raise LedgerError(
                "chain tip does not match the expected (anchored) tip — "
                "trailing rows are missing or altered"
            )
        return len(rows)

    # -- write serialization ------------------------------------------------------

    @contextmanager
    def _writer_lock(self):
        """Exclusive advisory lock for one read-tip→append (or repair) section.

        Blocking on purpose: contention lasts one append (~ms incl. fsync), so
        even the post-commit hook just waits its turn instead of skipping.
        """
        fd = os.open(
            self.path.with_name(self.path.name + ".lock"),
            os.O_WRONLY | os.O_CREAT,
            _FILE_MODE,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # closing the fd releases the lock

    # -- recovery ---------------------------------------------------------------

    def recover(self) -> int:
        """Repair a torn trailing record: quarantine its bytes, truncate, re-verify.

        Only the TornTailError case is auto-repaired (the documented MYB-2.4
        interrupted-append signature). Any other corruption — a tampered or
        broken row that is NOT the final one — propagates untouched: that is
        evidence, not a crash artifact. Returns total bytes quarantined.
        Quarantined bytes go to ``<ledger>.quarantine`` beside the ledger
        (inside the data dir, 0600 — invariant #2).
        """
        quarantined = 0
        if not self.path.exists():
            return 0  # no ledger yet: nothing to repair, and no dir to put a lock in
        with self._writer_lock():
            while True:
                try:
                    self.verify_chain()
                    return quarantined
                except TornTailError:
                    data = self.path.read_bytes()
                    end = len(data) - 1 if data.endswith(b"\n") else len(data)
                    boundary = data.rfind(b"\n", 0, end) + 1
                    torn = data[boundary:]
                    qfd = os.open(
                        self.path.with_name(self.path.name + ".quarantine"),
                        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                        _FILE_MODE,
                    )
                    try:
                        os.write(qfd, torn)
                        os.fsync(qfd)
                    finally:
                        os.close(qfd)
                    with self.path.open("r+b") as f:
                        f.truncate(boundary)
                        f.flush()
                        os.fsync(f.fileno())
                    quarantined += len(torn)

    # -- writing ---------------------------------------------------------------

    def _append_row(self, row: dict) -> dict:
        row["h"] = row_hash(row)
        self._validate_row(row, "refusing append")
        line = json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, _FILE_MODE)
        try:
            fault_row = os.environ.get("MYBENCH_FAULT_ROW")
            if fault_row is not None and row["i"] == int(fault_row):
                # Test-only fault injection (MYB-2.6): half-write this row,
                # then die as ungracefully as possible. Inert unless the env
                # var is set by the crash-recovery harness.
                import signal

                os.write(fd, line[: max(1, len(line) // 2)])
                os.fsync(fd)
                os.kill(os.getpid(), signal.SIGKILL)
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        return row

    def append_session(
        self,
        *,
        session_id: str,
        session_root: bytes,
        item_count: int,
        source: str,
        ts: str | None = None,
    ) -> dict:
        """Append one session row (creating the genesis row first if needed)."""
        if self.path == paths.ledger_dir() / "ledger.jsonl":
            paths.ensure_data_dir()
        ts = ts if ts is not None else _utc_now()
        with self._writer_lock():
            existing = self.rows()
            if not existing:
                existing = [
                    self._append_row(
                        {"schema_version": SCHEMA_VERSION, "i": 0, "type": "genesis", "ts": ts,
                         "prev": GENESIS_PREV}
                    )
                ]
            return self._append_row(
                {
                    "schema_version": SCHEMA_VERSION,
                    "i": existing[-1]["i"] + 1,
                    "type": "session",
                    "ts": ts,
                    "prev": existing[-1]["h"],
                    "session_id": session_id,
                    "session_root": session_root.hex(),
                    "item_count": item_count,
                    "source": source,
                }
            )

    def append_binding(
        self, *, commit_hash: str, commit_ts: str, repo_id: str, ts: str | None = None
    ) -> dict:
        """Append one commit↔activity binding row (MYB-3.5); genesis-creating like sessions.

        Deliberately narrow: no message, diff, filename, or branch parameter
        exists, so those leak channels cannot reach the ledger even by bug.
        """
        if self.path == paths.ledger_dir() / "ledger.jsonl":
            paths.ensure_data_dir()
        ts = ts if ts is not None else _utc_now()
        with self._writer_lock():
            existing = self.rows()
            if not existing:
                existing = [
                    self._append_row(
                        {"schema_version": SCHEMA_VERSION, "i": 0, "type": "genesis", "ts": ts,
                         "prev": GENESIS_PREV}
                    )
                ]
            return self._append_row(
                {
                    "schema_version": SCHEMA_VERSION,
                    "i": existing[-1]["i"] + 1,
                    "type": "binding",
                    "ts": ts,
                    "prev": existing[-1]["h"],
                    "commit_hash": commit_hash,
                    "commit_ts": commit_ts,
                    "repo_id": repo_id,
                }
            )
