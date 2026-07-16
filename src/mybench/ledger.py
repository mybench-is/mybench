"""Hash-chained append-only ledger — asset A3, the trust root for anchors/scorer/verify.

Storage strategy (MYB-2.4 AC #4, stress-tested by MYB-2.6): one checksummed
JSON row per line in ``ledger/ledger.jsonl`` under the data dir, appended with
a single ``O_APPEND`` write followed by fsync. Every row embeds its own hash
``h = SHA-256("mybench:v1:ledgerrow" || canonical JSON without h)`` and the
previous row's ``h`` (``prev``; the genesis row uses 64 zeros). A torn
trailing write therefore fails JSON parsing or the ``h`` recomputation and is
reported as :class:`TornTailError`, distinct from corruption elsewhere.

Rows are metadata only. The schema (``schemas/ledger_entry.schema.json``,
versions "1" and "2", ``additionalProperties: false``) is enforced on write AND read,
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
import hmac
import json
import os
import stat
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from mybench import paths
from mybench.schemas import load_validator

DOMAIN_ROW = b"mybench:v1:ledgerrow"
GENESIS_PREV = "0" * 64
SCHEMA_VERSION = "1"
EVENT_SCHEMA_VERSION = "2"
SESSION_SCHEMA_VERSION = "2"
ANCHOR_RECEIPT_SCHEMA_VERSION = "2"
ANCHOR_RECEIPT_DOMAIN = b"anchor-receipt:v1:"
ANCHOR_RECEIPT_EVENT_FIELDS = (
    "identity_id",
    "date",
    "row_start",
    "row_end",
    "root",
    "chain_tip",
)
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


def _parse_utc_timestamp(value: object, context: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LedgerError(f"{context} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LedgerError(f"{context} is not a valid UTC timestamp") from exc
    if parsed.tzinfo != UTC:
        raise LedgerError(f"{context} is not a UTC timestamp")
    return parsed


def anchor_receipt_id(staged_event: Mapping[str, object], scope_key: bytes) -> str:
    """Derive ADR-0013's opaque local id from exactly six public event fields."""
    if not isinstance(scope_key, bytes) or len(scope_key) != 32:
        raise LedgerError("anchor receipt requires the existing 32-byte session scope key")
    try:
        identity = {name: staged_event[name] for name in ANCHOR_RECEIPT_EVENT_FIELDS}
    except (KeyError, TypeError) as exc:
        raise LedgerError("anchor receipt event identity is incomplete") from exc
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(scope_key, ANCHOR_RECEIPT_DOMAIN + encoded, hashlib.sha256).hexdigest()[:16]


def _fsync_file(fd: int) -> None:
    os.fsync(fd)


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Ledger:
    def __init__(self, path: Path | None = None):
        self.path = path if path is not None else paths.ledger_dir() / "ledger.jsonl"
        self._schema = load_validator("ledger_entry.schema.json")

    # -- validation ------------------------------------------------------------

    def _validate_row(self, row: dict, context: str) -> None:
        errors = sorted(self._schema.iter_errors(row), key=str)
        if errors:
            raise LedgerError(f"{context}: schema violation: {errors[0].message}")

    def _ensure_storage_durable(self) -> None:
        """Fsync clean A3 bytes and their directory entry before trusting them."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise LedgerError("ledger path is not a regular file")
            _fsync_file(fd)
        finally:
            os.close(fd)
        _fsync_directory(self.path.parent)

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
                    self._ensure_storage_durable()
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
                _fsync_file(fd)
                os.kill(os.getpid(), signal.SIGKILL)
            os.write(fd, line)
            _fsync_file(fd)
        finally:
            os.close(fd)
        _fsync_directory(self.path.parent)
        return row

    def append_session(
        self,
        *,
        session_id: str,
        session_root: bytes,
        item_count: int,
        source: str,
        ts: str | None = None,
        models_seen: Sequence[str] | None = None,
        provider: str | None = None,
        effort: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        cache_creation_input_tokens: int | None = None,
        cache_read_input_tokens: int | None = None,
        harness_version: str | None = None,
    ) -> dict:
        """Append one v2 session observation (creating a frozen-v1 genesis first).

        Metadata parameters are the complete whitelist: there is no content,
        path, filename, or arbitrary metadata mapping that a caller could pass.
        ``None`` means unknown and is omitted; an explicit zero token count is
        retained as a provider observation.
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
            row = {
                "schema_version": SESSION_SCHEMA_VERSION,
                "i": existing[-1]["i"] + 1,
                "type": "session",
                "ts": ts,
                "prev": existing[-1]["h"],
                "session_id": session_id,
                "session_root": session_root.hex(),
                "item_count": item_count,
                "source": source,
            }
            optional = {
                "provider": provider,
                "effort": effort,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_creation_input_tokens": cache_creation_input_tokens,
                "cache_read_input_tokens": cache_read_input_tokens,
                "harness_version": harness_version,
            }
            if models_seen:
                row["models_seen"] = sorted(set(models_seen))
            row.update({name: value for name, value in optional.items() if value is not None})
            return self._append_row(row)

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

    def append_event(
        self,
        *,
        event_kind: str,
        trigger: str,
        session_id: str,
        context_gen: int,
        harness: str,
        ts: str | None = None,
        parent_session_id: str | None = None,
        harness_version: str | None = None,
        model: str | None = None,
        effort: str | None = None,
        repo_id: str | None = None,
        worktree_id: str | None = None,
        head_before: str | None = None,
        head_after: str | None = None,
    ) -> dict | None:
        """Append one capture-time observation, idempotently (ADR-0013).

        The replay key is exactly ``(session_id, event_kind, ts)``.  The
        read-tip, duplicate check, and append share the writer lock, so two
        scan processes cannot race a replay into duplicate rows.
        """
        if self.path == paths.ledger_dir() / "ledger.jsonl":
            paths.ensure_data_dir()
        ts = ts if ts is not None else _utc_now()
        with self._writer_lock():
            existing = self.rows()
            if any(
                row["type"] == "event"
                and row["session_id"] == session_id
                and row["event_kind"] == event_kind
                and row["ts"] == ts
                for row in existing
            ):
                return None
            if not existing:
                existing = [
                    self._append_row(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "i": 0,
                            "type": "genesis",
                            "ts": ts,
                            "prev": GENESIS_PREV,
                        }
                    )
                ]
            row = {
                "schema_version": EVENT_SCHEMA_VERSION,
                "i": existing[-1]["i"] + 1,
                "type": "event",
                "ts": ts,
                "prev": existing[-1]["h"],
                "event_kind": event_kind,
                "trigger": trigger,
                "session_id": session_id,
                "context_gen": context_gen,
                "harness": harness,
            }
            optional = {
                "parent_session_id": parent_session_id,
                "harness_version": harness_version,
                "model": model,
                "effort": effort,
                "repo_id": repo_id,
                "worktree_id": worktree_id,
                "head_before": head_before,
                "head_after": head_after,
            }
            row.update({key: value for key, value in optional.items() if value is not None})
            return self._append_row(row)

    def append_anchor_receipt(
        self,
        *,
        staged_event: dict,
        receipt_ts: str,
        ts: str | None = None,
        scope_key: bytes | None = None,
    ) -> dict | None:
        """Validate and append MYB-9.5's reserved private receipt observation.

        This pins the row shape and semantic boundary only.  MYB-9.5 owns the
        cut-path call site, including sampling the first successful calendar
        response and invoking this method only after event/proof staging.

        The staged event's signature, range, session-root aggregate, chain tip,
        and counts are recomputed against the current ledger.  The private
        receipt time must be no earlier than any covered row and no later than
        the append-time envelope.  Replays of the exact receipt are idempotent;
        a conflicting second receipt for the same range/root fails closed.
        """
        from mybench.anchor.event import EventError, verify_event
        from mybench.commitments import day_root

        if self.path == paths.ledger_dir() / "ledger.jsonl":
            paths.ensure_data_dir()
        scope_key = scope_key if scope_key is not None else paths.ensure_session_scope_key()
        try:
            verify_event(staged_event)
        except EventError as exc:
            raise LedgerError("anchor receipt staged event is invalid") from exc

        ts = ts if ts is not None else _utc_now()
        receipt_time = _parse_utc_timestamp(receipt_ts, "receipt_ts")
        append_time = _parse_utc_timestamp(ts, "anchor receipt append ts")
        receipt_id = anchor_receipt_id(staged_event, scope_key)

        with self._writer_lock():
            self.verify_chain()
            existing = self.rows()
            row_start = staged_event["row_start"]
            row_end = staged_event["row_end"]
            if row_start < 0 or row_end > len(existing) or row_end <= row_start:
                raise LedgerError("anchor receipt event range is outside the ledger")
            covered = existing[row_start:row_end]
            leaves = [bytes.fromhex(row["session_root"]) for row in covered
                      if row["type"] == "session"]
            if not leaves or day_root(leaves).hex() != staged_event["root"]:
                raise LedgerError("anchor receipt root does not match the ledger slice")
            if covered[-1]["h"] != staged_event["chain_tip"]:
                raise LedgerError("anchor receipt chain tip does not match the ledger slice")
            if len(leaves) != staged_event["session_count"]:
                raise LedgerError("anchor receipt session count does not match the ledger slice")
            item_count = sum(
                row["item_count"] for row in covered if row["type"] == "session"
            )
            if item_count != staged_event["item_count"]:
                raise LedgerError("anchor receipt item count does not match the ledger slice")

            newest_covered = max(
                _parse_utc_timestamp(row["ts"], "covered ledger row ts") for row in covered
            )
            if receipt_time < newest_covered:
                raise LedgerError("receipt_ts predates a covered ledger row")
            if append_time < receipt_time:
                raise LedgerError("anchor receipt append ts predates receipt_ts")

            identity = (
                row_start,
                row_end,
                staged_event["root"],
                staged_event["chain_tip"],
            )
            for row in existing:
                if row["type"] != "anchor_receipt":
                    continue
                row_identity = (
                    row["anchor_row_start"],
                    row["anchor_row_end"],
                    row["anchor_root"],
                    row["anchor_chain_tip"],
                )
                if row["receipt_id"] == receipt_id or row_identity == identity:
                    if (
                        row["receipt_id"] == receipt_id
                        and row_identity == identity
                        and row["receipt_ts"] == receipt_ts
                    ):
                        return None
                    raise LedgerError("conflicting anchor receipt already exists")

            return self._append_row(
                {
                    "schema_version": ANCHOR_RECEIPT_SCHEMA_VERSION,
                    "i": existing[-1]["i"] + 1,
                    "type": "anchor_receipt",
                    "ts": ts,
                    "prev": existing[-1]["h"],
                    "anchor_row_start": row_start,
                    "anchor_row_end": row_end,
                    "anchor_root": staged_event["root"],
                    "anchor_chain_tip": staged_event["chain_tip"],
                    "receipt_ts": receipt_ts,
                    "receipt_id": receipt_id,
                }
            )
