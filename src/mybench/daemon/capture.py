"""Capture: watch transcript dirs, commit new items, append ledger rows (MYB-2.5).

Scan-based in v0: each :meth:`Daemon.scan_once` walks the configured dirs,
extracts complete JSONL lines as items (ADR-0002 §2: exact raw bytes, one
line = one item; a partial trailing line is left for the next scan), commits
any items not yet covered by the session's nonce file, and appends one ledger
row carrying the session root over ALL items committed so far.  When A9 is
explicitly enabled, after that capture commit point it extends and
commitment-verifies the session's retention archive.  Archiving defaults off;
archive failure is reported but never rolls back or blocks capture, and a later
enabled no-op re-scan retries it (MYB-12.1 / owner ruling D-B).

Privacy: configuration is always explicit — there is no default watch list in
test mode (``default_config`` refuses under pytest), so tests can only ever
read tmp fixture dirs (invariant #3). Log lines are a first-class leak
surface: they carry event names, counts, and row indices — never transcript
content, session ids, or watched paths/filenames (invariant #1).
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import logging
import os
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from mybench import archive as archive_store
from mybench import commitments, nonces, paths
from mybench.ledger import Ledger

log = logging.getLogger("mybench.daemon")

# Formats wired in v0 — exactly those the MYB-2.2 fixtures cover. All current
# formats are line-delimited, so extraction is shared; a new format plugs in
# here with its own extractor (OPEN_QUESTIONS #6).
#
# Record boundaries (ADR-0002 §2 — adapters define them per tool):
#   claude-code: one complete JSONL line = one item, exact raw bytes;
#     ~/.claude/projects/<project>/…, subagent files nest arbitrarily deep.
#   codex: same per-JSONL-line boundary, verified against the rollout format
#     current as of 2026-07-13 (sessions/YYYY/MM/DD/rollout-*.jsonl, one JSON
#     object per line). The nested date layout needs no special handling:
#     session_id_for HMACs the watch-relative path, so equal stems on
#     different dates stay distinct sessions (MYB-12.2).
# Validity of the bytes is deliberately irrelevant: capture is content-opaque
# and never parses items, so an unknown or binary line is still exactly one
# committed record — malformed input cannot crash or skip capture.
SOURCES = paths.ARCHIVE_SOURCES


class ConfigError(RuntimeError):
    pass


class CaptureIntegrityError(RuntimeError):
    """Existing A2/A3 state cannot safely reconcile with the source snapshot."""


@dataclass(frozen=True)
class WatchSpec:
    path: Path
    source: str  # one of SOURCES


@dataclass(frozen=True)
class DaemonConfig:
    watches: tuple[WatchSpec, ...]
    archive_enabled: bool = False

    def __post_init__(self):
        if type(self.archive_enabled) is not bool:
            raise ConfigError("archive_enabled must be an explicit boolean")
        if not self.watches:
            raise ConfigError("daemon config needs at least one explicit watch dir")
        for w in self.watches:
            if w.source not in SOURCES:
                raise ConfigError(f"unknown source {w.source!r}; wired formats: {SOURCES}")


@dataclass(frozen=True)
class _CaptureResult:
    rows_appended: int = 0
    archive_covered: int = 0
    archive_failed: int = 0
    archive_bytes_appended: int = 0


@contextmanager
def _capture_scan_lock():
    """Serialize the full covered-state → A2 → A3 → A9 scan transaction."""
    paths.ensure_data_dir()
    fd = os.open(
        paths.capture_scan_lock_path(),
        os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise CaptureIntegrityError("capture scan lock is not a regular file")
        if stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
            raise paths.InsecurePermissionsError(
                "capture scan lock is group/other-accessible; expected 0600"
            )
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def production_watches(home: Path) -> tuple[WatchSpec, ...]:
    """Real transcript locations for a production machine (OQ #6: both formats).

    Claude Code is unconditional (a missing dir surfaces loudly per-scan as
    ``missing_dir`` rather than being silently dropped here); the Codex dir is
    exists-guarded because not every machine runs Codex (MYB-12.2). Pure and
    testable against a tmp ``home`` — the pytest guard lives in
    :func:`default_config`, which is the only caller that touches the real
    home directory.
    """
    watches = [WatchSpec(home / ".claude" / "projects", "claude-code")]
    codex = home / ".codex" / "sessions"
    if codex.is_dir():
        watches.append(WatchSpec(codex, "codex"))
    return tuple(watches)


def default_config() -> DaemonConfig:
    """The real transcript locations — owner runs only.

    Refuses under pytest: tests must pass explicit tmp fixture dirs and can
    never fall back to real transcript paths (MYB-2.5 AC #3, invariant #3).
    """
    import os

    if "PYTEST_CURRENT_TEST" in os.environ:
        raise ConfigError("default_config() is forbidden in test mode — pass explicit fixture dirs")
    return DaemonConfig(watches=production_watches(Path.home()))


def session_id_for(f: Path, watch: WatchSpec, scope_key: bytes) -> str:
    """Opaque, per-file-unique session id: truncated stem + keyed path HMAC.

    Real Claude Code layouts nest subagent transcripts that can reuse a stem
    across many files (found during MYB-2.7); the stem alone would merge them
    into one nonce namespace. The HMAC suffix over the watch-relative path
    (ADR-0002 §4 amendment, 2026-07-08) disambiguates every file while
    keeping readable path components out of the id.
    """
    rel = f.relative_to(watch.path).as_posix()
    tag = hmac.new(scope_key, f"{watch.source}:{rel}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"{f.stem[:40]}-{tag}"


def _complete_lines(data: bytes) -> list[bytes]:
    """Items per ADR-0002 §2: complete raw lines; an unterminated tail is not yet an item."""
    lines = data.split(b"\n")
    lines.pop()  # tail: b"" if data ended with \n, else a partial line — skip either way
    return lines


def _read_source_bytes(source_file: Path) -> bytes:
    """Read one regular source without following a final-component symlink."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(source_file, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise CaptureIntegrityError("transcript source is not a regular file")
        chunks = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


class Daemon:
    def __init__(self, config: DaemonConfig, ledger: Ledger | None = None):
        self.config = config
        self.ledger = ledger if ledger is not None else Ledger()

    def scan_once(self) -> int:
        """One full pass over all watches; returns the number of rows appended.

        A global process lock is acquired before rebuilding ledger coverage and
        held through nonce, ledger, and optional archive reconciliation.
        """
        with _capture_scan_lock():
            return self._scan_once_locked()

    def _scan_once_locked(self) -> int:
        """Implementation of :meth:`scan_once`; caller holds the global scan lock.

        Starts by self-healing a torn ledger tail (MYB-2.6): an append
        interrupted by an ungraceful death is quarantined + truncated before
        any new capture work.
        """
        recovered = self.ledger.recover()
        if recovered:
            log.warning("recovered torn ledger tail (event=torn_tail bytes=%d)", recovered)
        scope_key = paths.ensure_session_scope_key()
        # Items covered by an existing row, per session. Capture reconciles
        # against THIS, not the nonce store: a crash between nonce writes and
        # the row append leaves nonces without a row, which must produce a
        # row on the next scan — not silence.
        covered: dict[str, dict] = {}
        for row in self.ledger.rows():
            if row["type"] == "session":
                previous = covered.get(row["session_id"])
                if previous is None or row["item_count"] >= previous["item_count"]:
                    covered[row["session_id"]] = row
        appended = sessions_seen = archive_covered = archive_failed = archive_bytes = 0
        for watch in self.config.watches:
            if watch.path.is_symlink():
                log.error("symlinked watch dir rejected (event=watch_symlink); skipping")
                continue
            if not watch.path.is_dir():
                log.warning("watch dir missing (event=missing_dir); skipping")
                continue
            watch_root = watch.path.resolve()
            for f in sorted(watch.path.rglob("*.jsonl")):
                sessions_seen += 1
                if f.is_symlink():
                    log.error("symlinked transcript rejected (event=source_symlink); skipping")
                    continue
                if not f.resolve().is_relative_to(watch_root):
                    log.error("transcript escaped watch root (event=source_outside); skipping")
                    continue
                try:
                    result = self._capture_file(f, watch, scope_key, covered)
                    appended += result.rows_appended
                    archive_covered += result.archive_covered
                    archive_failed += result.archive_failed
                    archive_bytes += result.archive_bytes_appended
                except Exception as exc:  # noqa: BLE001 — one bad file must not stop capture
                    # Exception CLASS only: messages may embed paths/ids (leak surface).
                    log.error("capture failed (event=capture_error type=%s)", type(exc).__name__)
        if not self.config.archive_enabled:
            log.info(
                "scan complete: sessions=%d rows_appended=%d committed_sessions=%d "
                "archive_enabled=0",
                sessions_seen,
                appended,
                len(covered),
            )
            return appended

        try:
            stats = archive_store.archive_stats()
            log.info(
                "scan complete: sessions=%d rows_appended=%d committed_sessions=%d "
                "archive_enabled=1 archive_covered=%d archive_failed=%d "
                "archive_bytes_appended=%d archive_files=%d archive_bytes=%d "
                "disk_free_bytes=%d",
                sessions_seen,
                appended,
                len(covered),
                archive_covered,
                archive_failed,
                archive_bytes,
                stats.session_files,
                stats.total_bytes,
                stats.free_bytes,
            )
        except Exception as exc:  # noqa: BLE001 — monitoring cannot stop capture
            log.error("archive stats failed (event=archive_stats_error type=%s)", type(exc).__name__)
            log.info(
                "scan complete: sessions=%d rows_appended=%d committed_sessions=%d "
                "archive_enabled=1 archive_covered=%d archive_failed=%d "
                "archive_bytes_appended=%d",
                sessions_seen,
                appended,
                len(covered),
                archive_covered,
                archive_failed,
                archive_bytes,
            )
        return appended

    def _capture_file(
        self, f: Path, watch: WatchSpec, scope_key: bytes, covered: dict[str, dict]
    ) -> _CaptureResult:
        source = watch.source
        session_id = session_id_for(f, watch, scope_key)
        items = _complete_lines(_read_source_bytes(f))
        known = nonces.load_nonces(session_id)
        row = covered.get(session_id)
        if row is not None and len(known) < row["item_count"]:
            raise CaptureIntegrityError(
                "nonce store is shorter than an existing committed session row"
            )
        if len(items) < len(known):
            # Source shrank below what we committed — never rewrite history.
            log.error("session shrank below committed items (event=source_shrunk); skipping")
            if row is None or not self.config.archive_enabled:
                return _CaptureResult()
            return self._archive_file(source, session_id, items, known, row)
        if not items:
            return _CaptureResult()

        row_appended = 0
        if row is None or row["item_count"] < len(items) or len(known) < len(items):
            if row is not None and row["item_count"] < len(items):
                committed_count = row["item_count"]
                committed_leaves = [
                    commitments.leaf_commitment(nonce, item)
                    for nonce, item in zip(
                        known[:committed_count], items[:committed_count]
                    )
                ]
                if commitments.session_root(committed_leaves).hex() != row["session_root"]:
                    raise CaptureIntegrityError(
                        "live source prefix no longer matches its committed session row"
                    )
            fresh = [commitments.generate_nonce() for _ in items[len(known) :]]
            for nonce in fresh:
                nonces.append_nonce(session_id, nonce)
            all_nonces = known + fresh
            leaves = [
                commitments.leaf_commitment(nonce, item)
                for nonce, item in zip(all_nonces, items)
            ]
            # Re-fsync ALL known rows, not only freshly appended nonces: a
            # restart can see a complete orphan row whose prior process died
            # before file/directory fsync. A3 may reference it only afterward.
            nonces.ensure_durable(session_id)
            row = self.ledger.append_session(
                session_id=session_id,
                session_root=commitments.session_root(leaves),
                item_count=len(items),
                source=source,
            )
            covered[session_id] = row
            row_appended = 1
            log.info(
                "session row appended: row_i=%d items=%d new_items=%d",
                row["i"],
                len(items),
                len(fresh),
            )
            known = all_nonces

        if not self.config.archive_enabled:
            return _CaptureResult(rows_appended=row_appended)

        archived = self._archive_file(source, session_id, items, known, row)
        return _CaptureResult(
            rows_appended=row_appended,
            archive_covered=archived.archive_covered,
            archive_failed=archived.archive_failed,
            archive_bytes_appended=archived.archive_bytes_appended,
        )

    @staticmethod
    def _archive_file(
        source: str,
        session_id: str,
        items: list[bytes],
        known: list[bytes],
        row: dict,
    ) -> _CaptureResult:
        """Best-effort A9 step after capture; errors are counts/class only."""
        try:
            result = archive_store.archive_session(
                source=source,
                session_id=session_id,
                source_items=items,
                nonces=known,
                expected_item_count=row["item_count"],
                expected_session_root=row["session_root"],
            )
        except Exception as exc:  # noqa: BLE001 — A9 failure must never block A3 capture
            log.error("archive failed (event=archive_error type=%s)", type(exc).__name__)
            return _CaptureResult(archive_failed=1)
        return _CaptureResult(
            archive_covered=1,
            archive_bytes_appended=result.bytes_appended,
        )

    def run(self, interval: float = 30.0, max_scans: int | None = None) -> None:
        """Poll loop (owner-run); tests drive scan_once() directly."""
        paths.ensure_data_dir()
        scans = 0
        while max_scans is None or scans < max_scans:
            self.scan_once()
            scans += 1
            time.sleep(interval)
