"""Capture: watch transcript dirs, commit new items, append ledger rows (MYB-2.5).

Scan-based in v0: each :meth:`Daemon.scan_once` walks the configured dirs,
extracts complete JSONL lines as items (ADR-0002 §2: exact raw bytes, one
line = one item; a partial trailing line is left for the next scan), commits
any items not yet covered by the session's nonce file, and appends one ledger
row carrying the session root over ALL items committed so far. The nonce
store is the only capture state, so re-scans and restarts are idempotent by
construction: no new items → no new nonces → no new row.

Privacy: configuration is always explicit — there is no default watch list in
test mode (``default_config`` refuses under pytest), so tests can only ever
read tmp fixture dirs (invariant #3). Log lines are a first-class leak
surface: they carry event names, counts, and row indices — never transcript
content, session ids, or watched paths/filenames (invariant #1).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from mybench import commitments, nonces, paths
from mybench.ledger import Ledger

log = logging.getLogger("mybench.daemon")

# Formats wired in v0 — exactly those the MYB-2.2 fixtures cover. All current
# formats are line-delimited, so extraction is shared; a new format plugs in
# here with its own extractor (OPEN_QUESTIONS #6).
SOURCES = ("claude-code", "codex", "synthetic")


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class WatchSpec:
    path: Path
    source: str  # one of SOURCES


@dataclass(frozen=True)
class DaemonConfig:
    watches: tuple[WatchSpec, ...]

    def __post_init__(self):
        if not self.watches:
            raise ConfigError("daemon config needs at least one explicit watch dir")
        for w in self.watches:
            if w.source not in SOURCES:
                raise ConfigError(f"unknown source {w.source!r}; wired formats: {SOURCES}")


def default_config() -> DaemonConfig:
    """The real Claude Code transcript location — owner runs only.

    Refuses under pytest: tests must pass explicit tmp fixture dirs and can
    never fall back to real transcript paths (MYB-2.5 AC #3, invariant #3).
    """
    import os

    if "PYTEST_CURRENT_TEST" in os.environ:
        raise ConfigError("default_config() is forbidden in test mode — pass explicit fixture dirs")
    return DaemonConfig(
        watches=(WatchSpec(Path.home() / ".claude" / "projects", "claude-code"),)
    )


def _complete_lines(data: bytes) -> list[bytes]:
    """Items per ADR-0002 §2: complete raw lines; an unterminated tail is not yet an item."""
    lines = data.split(b"\n")
    lines.pop()  # tail: b"" if data ended with \n, else a partial line — skip either way
    return lines


class Daemon:
    def __init__(self, config: DaemonConfig, ledger: Ledger | None = None):
        self.config = config
        self.ledger = ledger if ledger is not None else Ledger()

    def scan_once(self) -> int:
        """One full pass over all watches; returns the number of rows appended.

        Starts by self-healing a torn ledger tail (MYB-2.6): an append
        interrupted by an ungraceful death is quarantined + truncated before
        any new capture work.
        """
        recovered = self.ledger.recover()
        if recovered:
            log.warning("recovered torn ledger tail (event=torn_tail bytes=%d)", recovered)
        # Items covered by an existing row, per session. Capture reconciles
        # against THIS, not the nonce store: a crash between nonce writes and
        # the row append leaves nonces without a row, which must produce a
        # row on the next scan — not silence.
        covered: dict[str, int] = {}
        for row in self.ledger.rows():
            if row["type"] == "session":
                covered[row["session_id"]] = max(
                    covered.get(row["session_id"], 0), row["item_count"]
                )
        appended = sessions_seen = 0
        for watch in self.config.watches:
            if not watch.path.is_dir():
                log.warning("watch dir missing (event=missing_dir); skipping")
                continue
            for f in sorted(watch.path.rglob("*.jsonl")):
                sessions_seen += 1
                try:
                    appended += self._capture_file(f, watch.source, covered)
                except Exception as exc:  # noqa: BLE001 — one bad file must not stop capture
                    # Exception CLASS only: messages may embed paths/ids (leak surface).
                    log.error("capture failed (event=capture_error type=%s)", type(exc).__name__)
        log.info("scan complete: sessions=%d rows_appended=%d", sessions_seen, appended)
        return appended

    def _capture_file(self, f: Path, source: str, covered: dict[str, int]) -> int:
        session_id = f.stem
        items = _complete_lines(f.read_bytes())
        if not items:
            return 0
        known = nonces.load_nonces(session_id)
        if len(items) < len(known):
            # Source shrank below what we committed — never rewrite history.
            log.error("session shrank below committed items (event=source_shrunk); skipping")
            return 0
        if len(known) == len(items) and covered.get(session_id, 0) >= len(items):
            return 0
        fresh = [commitments.generate_nonce() for _ in items[len(known) :]]
        for nonce in fresh:
            nonces.append_nonce(session_id, nonce)
        leaves = [
            commitments.leaf_commitment(nonce, item)
            for nonce, item in zip(known + fresh, items)
        ]
        row = self.ledger.append_session(
            session_id=session_id,
            session_root=commitments.session_root(leaves),
            item_count=len(items),
            source=source,
        )
        covered[session_id] = len(items)
        log.info("session row appended: row_i=%d items=%d new_items=%d",
                 row["i"], len(items), len(fresh))
        return 1

    def run(self, interval: float = 30.0, max_scans: int | None = None) -> None:
        """Poll loop (owner-run); tests drive scan_once() directly."""
        paths.ensure_data_dir()
        scans = 0
        while max_scans is None or scans < max_scans:
            self.scan_once()
            scans += 1
            time.sleep(interval)
