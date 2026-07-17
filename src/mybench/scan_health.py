"""Private successful-scan receipt (MYB-11.6).

The receipt records only UTC completion times and keyed fingerprints of the
locations actually covered.  It never contains a path, repository name, file
content, or key.  Writers replace it atomically under a private advisory lock;
status uses the read-only :func:`load` path and never creates or repairs state.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterable

from mybench import paths
from mybench.schemas import load_validator

_DOMAIN = b"mybench:v1:scan-health-location\x00"
_MAX_BYTES = 1024 * 1024
_MAX_LOCATIONS = 4096


class ScanHealthError(RuntimeError):
    """The private receipt is invalid, insecure, or could not be updated."""


@dataclass(frozen=True)
class ScanHealth:
    capture_completed_at: str | None = None
    full_scan_completed_at: str | None = None
    watches: tuple[tuple[str, str], ...] = ()
    repos: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict:
        return {
            "schema_version": "1",
            "capture_completed_at": self.capture_completed_at,
            "full_scan_completed_at": self.full_scan_completed_at,
            "watches": [
                {"id": location_id, "completed_at": completed_at}
                for location_id, completed_at in self.watches
            ],
            "repos": [
                {"id": location_id, "completed_at": completed_at}
                for location_id, completed_at in self.repos
            ],
        }

    def watch_times(self) -> dict[str, str]:
        return dict(self.watches)

    def repo_times(self) -> dict[str, str]:
        return dict(self.repos)


def _clock_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ScanHealthError("scan completion time must be UTC-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise ScanHealthError("scan completion time is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ScanHealthError("scan completion time is invalid") from exc
    return parsed


def _absolute(path: Path | str) -> str:
    return os.path.abspath(os.path.expanduser(os.fspath(path)))


def location_id(kind: str, path: Path | str, scope_key: bytes) -> str:
    """Keyed fingerprint for matching a private config location to a receipt."""
    if not isinstance(kind, str) or not kind or "\x00" in kind:
        raise ScanHealthError("scan-health location kind is invalid")
    if not isinstance(scope_key, bytes) or len(scope_key) != 32:
        raise ScanHealthError("scan-health location key is invalid")
    message = _DOMAIN + kind.encode() + b"\x00" + os.fsencode(_absolute(path))
    return hmac.new(scope_key, message, hashlib.sha256).hexdigest()


def watch_id(watch, scope_key: bytes) -> str:
    return location_id(f"watch:{watch.source}", watch.path, scope_key)


def repo_id(repo: Path | str, scope_key: bytes) -> str:
    return location_id("repo", repo, scope_key)


def _check_parent(directory: Path) -> None:
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or directory.is_symlink()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ScanHealthError("scan-health parent is insecure")


def _check_fd(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ScanHealthError("scan-health storage is insecure")


def _read_fd(fd: int) -> bytes:
    data = b""
    while len(data) <= _MAX_BYTES:
        chunk = os.read(fd, min(64 * 1024, _MAX_BYTES + 1 - len(data)))
        if not chunk:
            break
        data += chunk
    if len(data) > _MAX_BYTES:
        raise ScanHealthError("scan-health receipt is too large")
    return data


def load_scope_key() -> bytes | None:
    """Read the existing scope key without creating or repairing anything."""
    target = paths.session_scope_key_path()
    if not os.path.lexists(target):
        return None
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        _check_fd(fd)
        key = _read_fd(fd)
    finally:
        os.close(fd)
    if len(key) != 32:
        raise ScanHealthError("session scope key is invalid")
    return key


def _validated(value: object) -> ScanHealth:
    errors = sorted(load_validator("scan_health.schema.json").iter_errors(value), key=str)
    if errors or not isinstance(value, dict):
        raise ScanHealthError("scan-health receipt is invalid")
    for timestamp in (value["capture_completed_at"], value["full_scan_completed_at"]):
        if timestamp is not None:
            parse_timestamp(timestamp)
    watches = tuple((item["id"], item["completed_at"]) for item in value["watches"])
    repos = tuple((item["id"], item["completed_at"]) for item in value["repos"])
    if len({location_id for location_id, _ in watches}) != len(watches) or len(
        {location_id for location_id, _ in repos}
    ) != len(repos):
        raise ScanHealthError("scan-health receipt contains duplicate locations")
    for _location_id, timestamp in (*watches, *repos):
        parse_timestamp(timestamp)
    health = ScanHealth(
        capture_completed_at=value["capture_completed_at"],
        full_scan_completed_at=value["full_scan_completed_at"],
        watches=tuple(sorted(watches)),
        repos=tuple(sorted(repos)),
    )
    if value != health.as_dict():
        raise ScanHealthError("scan-health receipt is not canonical")
    return health


def _load_target(target: Path) -> ScanHealth | None:
    if not os.path.lexists(target):
        return None
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        _check_fd(fd)
        data = _read_fd(fd)
    finally:
        os.close(fd)
    try:
        return _validated(json.loads(data))
    except ScanHealthError:
        raise
    except Exception as exc:
        raise ScanHealthError("scan-health receipt is invalid") from exc


def load() -> ScanHealth | None:
    """Read the existing receipt without creating state; absent means unknown."""
    target = paths.scan_health_path()
    lock = paths.scan_health_lock_path()
    if not os.path.lexists(target) and not os.path.lexists(lock):
        return None
    _check_parent(target.parent)
    if os.path.lexists(lock):
        fd = os.open(lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            _check_fd(fd)
        finally:
            os.close(fd)
    return _load_target(target)


def _trim(values: dict[str, str]) -> tuple[tuple[str, str], ...]:
    if len(values) > _MAX_LOCATIONS:
        newest = sorted(values.items(), key=lambda item: (item[1], item[0]), reverse=True)
        values = dict(newest[:_MAX_LOCATIONS])
    return tuple(sorted(values.items()))


def _write_locked(target: Path, health: ScanHealth) -> None:
    value = health.as_dict()
    _validated(value)
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if os.path.lexists(target):
        existing = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            _check_fd(existing)
        finally:
            os.close(existing)
    temporary = target.parent / f".scan-health.{secrets.token_hex(8)}.tmp"
    fd = -1
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        _check_fd(fd)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ScanHealthError("scan-health receipt write failed")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, target)
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _record(
    *,
    watches: Iterable = (),
    repos: Iterable[Path | str] = (),
    full: bool,
    completed_at: datetime | None,
) -> ScanHealth:
    watches = tuple(watches)
    repos = tuple(repos)
    paths.ensure_data_dir()
    scope_key = paths.ensure_session_scope_key()
    timestamp = _timestamp(completed_at if completed_at is not None else _clock_now())
    target = paths.scan_health_path()
    lock = paths.scan_health_lock_path()
    lock_fd = os.open(
        lock,
        os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _check_fd(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current = _load_target(target) or ScanHealth()
        watch_times = current.watch_times()
        repo_times = current.repo_times()
        for watch in watches:
            identity = watch_id(watch, scope_key)
            watch_times[identity] = max(timestamp, watch_times.get(identity, timestamp))
        for repo in repos:
            identity = repo_id(repo, scope_key)
            repo_times[identity] = max(timestamp, repo_times.get(identity, timestamp))
        health = ScanHealth(
            capture_completed_at=(
                max(timestamp, current.capture_completed_at or timestamp)
                if watches
                else current.capture_completed_at
            ),
            full_scan_completed_at=(
                max(timestamp, current.full_scan_completed_at or timestamp)
                if full
                else current.full_scan_completed_at
            ),
            watches=_trim(watch_times),
            repos=_trim(repo_times),
        )
        _write_locked(target, health)
        return health
    finally:
        os.close(lock_fd)


def record_capture_success(watches: Iterable, *, completed_at: datetime | None = None) -> ScanHealth:
    """Record a completed capture pass over exactly ``watches``."""
    return _record(watches=tuple(watches), full=False, completed_at=completed_at)


def record_full_success(
    watches: Iterable,
    repos: Iterable[Path | str],
    *,
    completed_at: datetime | None = None,
) -> ScanHealth:
    """Record a completed unified capture + repo reconciliation pass."""
    return _record(
        watches=tuple(watches),
        repos=tuple(repos),
        full=True,
        completed_at=completed_at,
    )
