"""Claude Code lifecycle-hook ingress (MYB-12.4, ADR-0013).

Raw hook JSON is memory-only.  The hook process extracts a closed structural
tuple and appends that one tuple to the private queue; the polling scan later
flushes it into schema-v2 ledger event rows.  Errors are swallowed and counted
without ever logging exception messages, paths, payloads, or session ids.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Callable

from mybench import paths
from mybench.capture_identity import session_id_for_path
from mybench.ledger import Ledger

QUEUE_VERSION = "1"
HOOK_EVENTS = ("SessionStart", "SessionEnd", "PreCompact")
HOOK_ARGS = ("-m", "mybench.hooks", "lifecycle", "run")
HOOK_TIMEOUT_SECONDS = 1
MAX_PAYLOAD_BYTES = 1024 * 1024

_FILE_MODE = 0o600
_LOOSE_BITS = 0o077
_SESSION_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")
_EVENT_KINDS = {"session_start", "session_end", "compact_pre"}
_TRIGGERS = {"startup", "resume", "clear", "compact", "manual", "auto", "unknown"}
_QUEUE_KEYS = {"queue_version", "ts", "event_kind", "trigger", "session_id", "harness"}

log = logging.getLogger("mybench.daemon")


class LifecycleError(RuntimeError):
    """Closed-shape payload, queue, or configuration violation."""


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_string(mapping: dict, key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise LifecycleError("required hook field is absent or invalid")
    return value


def extract_event(
    payload: object,
    *,
    watch_root: Path,
    scope_key: bytes,
    observed_ts: str,
) -> dict:
    """Whitelist one official Claude lifecycle payload into a queue tuple.

    Claude Code 2.1.210 supplies raw ``cwd``, ``transcript_path``, and, for
    PreCompact, prompt-adjacent ``custom_instructions``.  Only the fields read
    below influence output.  Unknown fields and new enum values are tolerated;
    new enum values collapse to the honest structural label ``unknown``.
    """
    if not isinstance(payload, dict) or not _TS_RE.fullmatch(observed_ts):
        raise LifecycleError("invalid hook envelope")
    event_name = _require_string(payload, "hook_event_name")
    transcript_value = _require_string(payload, "transcript_path")
    transcript_path = Path(transcript_value)
    watch_root = watch_root.absolute()
    if not transcript_path.is_absolute() or ".." in transcript_path.parts:
        raise LifecycleError("transcript path is not a normalized absolute path")
    if transcript_path.suffix != ".jsonl":
        raise LifecycleError("transcript path does not name a JSONL session")
    try:
        session_id = session_id_for_path(
            transcript_path,
            watch_root=watch_root,
            source="claude-code",
            scope_key=scope_key,
        )
    except ValueError as exc:
        raise LifecycleError("transcript path is outside the Claude watch root") from exc
    if not _SESSION_ID_RE.fullmatch(session_id):
        raise LifecycleError("derived opaque session id is invalid")

    if event_name == "SessionStart":
        event_kind = "session_start"
        source = payload.get("source")
        trigger = source if source in {"startup", "resume", "clear", "compact"} else "unknown"
    elif event_name == "SessionEnd":
        event_kind = "session_end"
        reason = payload.get("reason")
        trigger = reason if reason in {"clear", "resume"} else "unknown"
    elif event_name == "PreCompact":
        event_kind = "compact_pre"
        compact_trigger = payload.get("trigger")
        trigger = compact_trigger if compact_trigger in {"manual", "auto"} else "unknown"
    else:
        raise LifecycleError("unsupported hook event")

    return {
        "queue_version": QUEUE_VERSION,
        "ts": observed_ts,
        "event_kind": event_kind,
        "trigger": trigger,
        "session_id": session_id,
        "harness": "claude-code",
    }


def _validate_queue_record(record: object) -> dict:
    if not isinstance(record, dict) or set(record) != _QUEUE_KEYS:
        raise LifecycleError("queue record does not match the closed whitelist")
    if record.get("queue_version") != QUEUE_VERSION:
        raise LifecycleError("unknown queue record version")
    if record.get("event_kind") not in _EVENT_KINDS:
        raise LifecycleError("unknown lifecycle event kind")
    if record.get("trigger") not in _TRIGGERS:
        raise LifecycleError("unknown lifecycle trigger")
    if record.get("harness") != "claude-code":
        raise LifecycleError("unknown lifecycle harness")
    if not isinstance(record.get("ts"), str) or not _TS_RE.fullmatch(record["ts"]):
        raise LifecycleError("invalid lifecycle timestamp")
    if not isinstance(record.get("session_id"), str) or not _SESSION_ID_RE.fullmatch(
        record["session_id"]
    ):
        raise LifecycleError("invalid opaque session id")
    return record


def enqueue_event(record: dict) -> None:
    """Append one validated tuple atomically; raw hook data never reaches here."""
    record = _validate_queue_record(record)
    queue_dir = paths.ensure_queue_dir()
    queue_path = paths.claude_lifecycle_queue_path()
    line = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(queue_path, flags, _FILE_MODE)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & _LOOSE_BITS:
            raise LifecycleError("lifecycle queue is not a private regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if os.write(fd, line) != len(line):
            raise LifecycleError("short lifecycle queue append")
        os.fsync(fd)
    finally:
        os.close(fd)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    dfd = os.open(queue_dir, flags)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _record_failure(exc: Exception) -> None:
    """Best-effort count + class-only log; there is no unsafe fallback."""
    try:
        if not paths.data_dir().is_dir():
            return
        paths.ensure_queue_dir()
        counter = paths.claude_lifecycle_failure_path()
        fd = os.open(
            counter,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            _FILE_MODE,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            current_raw = os.read(fd, 64)
            current = int(current_raw.strip() or b"0")
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, f"{current + 1}\n".encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        from mybench.hooks.binding import _log_error

        _log_error(exc, context="claude-lifecycle")
    except Exception:  # noqa: BLE001 — no safe reporting surface remains
        pass


def handle_payload(
    payload: object,
    *,
    watch_root: Path | None = None,
    scope_key: bytes | None = None,
    now: Callable[[], str] = _utc_now,
) -> int:
    """Fail-safe hook entry. Always returns zero and never writes raw input."""
    if not paths.data_dir().is_dir():
        return 0
    try:
        watch_root = watch_root or (Path.home() / ".claude" / "projects")
        scope_key = scope_key if scope_key is not None else paths.ensure_session_scope_key()
        event = extract_event(
            payload,
            watch_root=watch_root,
            scope_key=scope_key,
            observed_ts=now(),
        )
        enqueue_event(event)
    except Exception as exc:  # noqa: BLE001 — lifecycle capture must never block Claude
        _record_failure(exc)
    return 0


def run_from_stdin(stream: BinaryIO | None = None) -> int:
    """Read a bounded in-memory payload and dispatch it without emitting output."""
    if not paths.data_dir().is_dir():
        return 0
    try:
        stream = stream if stream is not None else sys.stdin.buffer
        raw = stream.read(MAX_PAYLOAD_BYTES + 1)
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise LifecycleError("hook payload exceeds the in-memory limit")
        payload = json.loads(raw)
    except Exception as exc:  # noqa: BLE001 — malformed hooks are non-blocking
        _record_failure(exc)
        return 0
    return handle_payload(payload)


def _pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict:
    record = {}
    for key, value in pairs:
        if key in record:
            raise LifecycleError("duplicate key in lifecycle queue record")
        record[key] = value
    return record


def _parse_queue_line(line: bytes) -> dict:
    try:
        record = json.loads(line, object_pairs_hook=_pairs_without_duplicates)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise LifecycleError("invalid lifecycle queue record") from exc
    return _validate_queue_record(record)


def _context_generation(rows: list[dict], record: dict) -> int:
    events = [
        row
        for row in rows
        if row["type"] == "event" and row["session_id"] == record["session_id"]
    ]
    current = max((row["context_gen"] for row in events), default=0)
    if record["event_kind"] == "compact_pre":
        return current + 1
    if record["event_kind"] == "session_start" and record["trigger"] == "compact":
        if events and events[-1]["event_kind"] == "compact_pre":
            return events[-1]["context_gen"]
        return current + 1
    return current


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise LifecycleError("short lifecycle queue rewrite")
        offset += written


def flush_queue(ledger: Ledger | None = None) -> int:
    """Flush complete queue lines into A3; preserve only an incomplete tail.

    Ledger appends happen before queue compaction.  A kill in between therefore
    replays already-appended tuples, which ``Ledger.append_event`` deduplicates;
    it can never drop an acknowledged observation.
    """
    queue_path = paths.claude_lifecycle_queue_path()
    if not queue_path.exists():
        return 0
    ledger = ledger if ledger is not None else Ledger()
    fd = os.open(queue_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & _LOOSE_BITS:
            raise LifecycleError("lifecycle queue is not a private regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        chunks = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        data = b"".join(chunks)
        boundary = data.rfind(b"\n") + 1
        if boundary == 0:
            return 0
        complete, tail = data[:boundary], data[boundary:]
        appended = rejected = 0
        for line in complete.splitlines():
            try:
                record = _parse_queue_line(line)
            except LifecycleError:
                rejected += 1
                continue
            generation = _context_generation(ledger.rows(), record)
            row = ledger.append_event(
                event_kind=record["event_kind"],
                trigger=record["trigger"],
                session_id=record["session_id"],
                context_gen=generation,
                harness=record["harness"],
                ts=record["ts"],
            )
            appended += row is not None
        os.lseek(fd, 0, os.SEEK_SET)
        _write_all(fd, tail)
        os.ftruncate(fd, len(tail))
        os.fsync(fd)
        if rejected:
            log.error(
                "lifecycle queue records rejected (event=lifecycle_queue_rejected count=%d)",
                rejected,
            )
        return appended
    finally:
        os.close(fd)


def default_settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


def _handler(python_executable: str) -> dict:
    return {
        "type": "command",
        "command": python_executable,
        "args": list(HOOK_ARGS),
        "async": True,
        "timeout": HOOK_TIMEOUT_SECONDS,
    }


def _is_lifecycle_handler(handler: object) -> bool:
    return (
        isinstance(handler, dict)
        and handler.get("type") == "command"
        and handler.get("args") == list(HOOK_ARGS)
    )


def _group_has_lifecycle_handler(group: object) -> bool:
    if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
        return False
    return any(_is_lifecycle_handler(handler) for handler in group["hooks"])


def _load_settings(settings_path: Path) -> dict:
    if not settings_path.exists():
        return {}
    if settings_path.is_symlink():
        raise LifecycleError("refusing a symlinked Claude settings file")
    try:
        settings = json.loads(settings_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise LifecycleError("Claude settings are not valid JSON") from exc
    if not isinstance(settings, dict):
        raise LifecycleError("Claude settings root must be an object")
    return settings


def _write_settings(settings_path: Path, settings: dict) -> None:
    settings_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if settings_path.is_symlink():
        raise LifecycleError("refusing a symlinked Claude settings file")
    payload = json.dumps(settings, indent=2, sort_keys=True).encode() + b"\n"
    temp_fd, temp_name = tempfile.mkstemp(prefix=".mybench-settings-", dir=settings_path.parent)
    try:
        os.fchmod(temp_fd, _FILE_MODE)
        _write_all(temp_fd, payload)
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = -1
        os.replace(temp_name, settings_path)
        dfd = os.open(
            settings_path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if temp_fd >= 0:
            os.close(temp_fd)
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def install(
    settings_path: Path | None = None,
    *,
    python_executable: str = sys.executable,
) -> tuple[str, ...]:
    """Add only mybench's three machine-local lifecycle handlers."""
    settings_path = settings_path or default_settings_path()
    settings = _load_settings(settings_path)
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise LifecycleError("Claude settings hooks must be an object")
    changed = []
    for event_name in HOOK_EVENTS:
        groups = hooks.setdefault(event_name, [])
        if not isinstance(groups, list):
            raise LifecycleError("Claude hook event configuration must be an array")
        if any(_group_has_lifecycle_handler(group) for group in groups):
            continue
        groups.append({"matcher": "*", "hooks": [_handler(python_executable)]})
        changed.append(event_name)
    if changed:
        _write_settings(settings_path, settings)
    return tuple(changed)


def uninstall(settings_path: Path | None = None) -> tuple[str, ...]:
    """Remove only handlers identified by the exact mybench exec arguments."""
    settings_path = settings_path or default_settings_path()
    settings = _load_settings(settings_path)
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return ()
    changed = []
    for event_name in HOOK_EVENTS:
        groups = hooks.get(event_name)
        if not isinstance(groups, list):
            continue
        kept_groups = []
        removed = False
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                kept_groups.append(group)
                continue
            kept_handlers = [
                handler for handler in group["hooks"] if not _is_lifecycle_handler(handler)
            ]
            removed = removed or len(kept_handlers) != len(group["hooks"])
            if kept_handlers:
                kept_group = dict(group)
                kept_group["hooks"] = kept_handlers
                kept_groups.append(kept_group)
        if removed:
            changed.append(event_name)
            if kept_groups:
                hooks[event_name] = kept_groups
            else:
                hooks.pop(event_name, None)
    if changed:
        if not hooks:
            settings.pop("hooks", None)
        _write_settings(settings_path, settings)
    return tuple(changed)
