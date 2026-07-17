"""OS-native daily scan registration with no resident mybench process.

The systemd user timer and launchd agent contain only the installed CLI path,
``scan --quiet --scheduled``, and the optional explicitly consented
``--archive`` flag. Backend choice, archive consent, and last scheduled result
live in one canonical private receipt so :mod:`mybench.status` can inspect the
registration without writing or networking.
"""

from __future__ import annotations

import fcntl
import json
import os
import plistlib
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mybench import paths
from mybench.scan_health import parse_timestamp
from mybench.schemas import load_validator

SYSTEMD_SERVICE = "mybench-scan.service"
SYSTEMD_TIMER = "mybench-scan.timer"
LAUNCHD_LABEL = "is.mybench.scan"
_MANAGED_SENTINEL = b"Managed by mybench; do not edit."
_MAX_BYTES = 64 * 1024
_FILE_MODE = 0o600


class SchedulerError(RuntimeError):
    """Scheduler state, platform support, or registration is invalid."""


@dataclass(frozen=True)
class ScheduleState:
    backend: str
    executable: str | None
    xdg_data_home: str | None = None
    archive_enabled: bool = False
    last_attempt_at: str | None = None
    last_success_at: str | None = None
    last_result: str = "never"
    last_exit_code: int | None = None

    def as_dict(self) -> dict:
        return {
            "schema_version": "2",
            "backend": self.backend,
            "executable": self.executable,
            "xdg_data_home": self.xdg_data_home,
            "archive_enabled": self.archive_enabled,
            "last_attempt_at": self.last_attempt_at,
            "last_success_at": self.last_success_at,
            "last_result": self.last_result,
            "last_exit_code": self.last_exit_code,
        }


def _clock_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise SchedulerError("scheduled completion time must be UTC-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validated(value: object) -> ScheduleState:
    if isinstance(value, dict) and value.get("schema_version") == "1":
        legacy_keys = {
            "schema_version",
            "backend",
            "executable",
            "xdg_data_home",
            "last_attempt_at",
            "last_success_at",
            "last_result",
            "last_exit_code",
        }
        if set(value) != legacy_keys:
            raise SchedulerError("schedule state is invalid")
        value = {**value, "schema_version": "2", "archive_enabled": False}
    errors = sorted(load_validator("schedule.schema.json").iter_errors(value), key=str)
    if errors or not isinstance(value, dict):
        raise SchedulerError("schedule state is invalid")
    state = ScheduleState(
        backend=value["backend"],
        executable=value["executable"],
        xdg_data_home=value["xdg_data_home"],
        archive_enabled=value["archive_enabled"],
        last_attempt_at=value["last_attempt_at"],
        last_success_at=value["last_success_at"],
        last_result=value["last_result"],
        last_exit_code=value["last_exit_code"],
    )
    if value != state.as_dict():
        raise SchedulerError("schedule state is not canonical")
    if state.backend == "manual":
        if (
            state.executable is not None
            or state.xdg_data_home is not None
            or state.archive_enabled
        ):
            raise SchedulerError("manual schedule state cannot name execution options")
    elif state.executable is None or not Path(state.executable).is_absolute():
        raise SchedulerError("scheduled backend requires an absolute executable")
    if state.xdg_data_home is not None and not Path(state.xdg_data_home).is_absolute():
        raise SchedulerError("scheduled data-home path must be absolute")
    for timestamp in (state.last_attempt_at, state.last_success_at):
        if timestamp is not None:
            parse_timestamp(timestamp)
    if state.last_result == "never":
        if any(
            value is not None
            for value in (state.last_attempt_at, state.last_success_at, state.last_exit_code)
        ):
            raise SchedulerError("never-run schedule state has result metadata")
    elif state.last_result == "success":
        if (
            state.last_attempt_at is None
            or state.last_success_at != state.last_attempt_at
            or state.last_exit_code != 0
        ):
            raise SchedulerError("successful schedule state is inconsistent")
    elif (
        state.last_attempt_at is None
        or state.last_exit_code is None
        or state.last_exit_code == 0
    ):
        raise SchedulerError("failed schedule state is inconsistent")
    if (
        state.last_attempt_at is not None
        and state.last_success_at is not None
        and state.last_success_at > state.last_attempt_at
    ):
        raise SchedulerError("scheduled success is later than the latest attempt")
    return state


def _check_parent(directory: Path) -> None:
    info = directory.lstat()
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SchedulerError("schedule-state parent is insecure")


def _check_private_fd(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != _FILE_MODE
    ):
        raise SchedulerError("schedule-state storage is insecure")


def _read_fd(fd: int) -> bytes:
    data = b""
    while len(data) <= _MAX_BYTES:
        chunk = os.read(fd, min(16 * 1024, _MAX_BYTES + 1 - len(data)))
        if not chunk:
            break
        data += chunk
    if len(data) > _MAX_BYTES:
        raise SchedulerError("schedule state is too large")
    return data


def _load_target(target: Path) -> ScheduleState | None:
    if not os.path.lexists(target):
        return None
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        _check_private_fd(fd)
        data = _read_fd(fd)
    finally:
        os.close(fd)
    try:
        return _validated(json.loads(data))
    except SchedulerError:
        raise
    except Exception as exc:
        raise SchedulerError("schedule state is invalid") from exc


def load() -> ScheduleState | None:
    """Read schedule state without creating or repairing anything."""
    target = paths.schedule_path()
    lock = paths.schedule_lock_path()
    if not os.path.lexists(target) and not os.path.lexists(lock):
        return None
    _check_parent(target.parent)
    if os.path.lexists(lock):
        fd = os.open(lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            _check_private_fd(fd)
        finally:
            os.close(fd)
    return _load_target(target)


def _write_state_locked(target: Path, state: ScheduleState) -> None:
    content = json.dumps(
        _validated(state.as_dict()).as_dict(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode() + b"\n"
    if os.path.lexists(target):
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            _check_private_fd(fd)
            if _read_fd(fd) == content:
                return
        finally:
            os.close(fd)
    temporary = target.parent / f".schedule.{secrets.token_hex(8)}.tmp"
    fd = -1
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            _FILE_MODE,
        )
        _check_private_fd(fd)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise SchedulerError("schedule-state write failed")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, target)
        directory_fd = os.open(
            target.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
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


def _mutate_state(update) -> ScheduleState:
    paths.ensure_data_dir()
    target = paths.schedule_path()
    lock = paths.schedule_lock_path()
    lock_fd = os.open(
        lock,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        _FILE_MODE,
    )
    try:
        _check_private_fd(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = update(_load_target(target))
        _write_state_locked(target, state)
        return state
    finally:
        os.close(lock_fd)


def _store(state: ScheduleState) -> ScheduleState:
    return _mutate_state(lambda _current: state)


def _clear_state() -> bool:
    target = paths.schedule_path()
    lock = paths.schedule_lock_path()
    if not os.path.lexists(target):
        return False
    _check_parent(target.parent)
    lock_fd = os.open(
        lock,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        _FILE_MODE,
    )
    try:
        _check_private_fd(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if os.path.lexists(target):
            fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                _check_private_fd(fd)
            finally:
                os.close(fd)
            target.unlink()
    finally:
        os.close(lock_fd)
    # Keep the empty lock inode. Removing a lock path after releasing flock can
    # split concurrent writers across old/new inodes; the 0600 file contains
    # no state and lets a late scheduled completion fail safely under one lock.
    return True


def record_run(exit_code: int, *, completed_at: datetime | None = None) -> ScheduleState:
    """Record one OS-scheduled attempt without masking the scan exit code."""
    if not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        raise SchedulerError("scheduled scan exit code is invalid")
    timestamp = _timestamp(completed_at if completed_at is not None else _clock_now())

    def update(current: ScheduleState | None) -> ScheduleState:
        if current is None or current.backend == "manual":
            raise SchedulerError("scheduled scan has no registered backend")
        if current.last_attempt_at is not None:
            if timestamp < current.last_attempt_at:
                return current
            if timestamp == current.last_attempt_at and not (
                exit_code == 0 and current.last_result == "failed"
            ):
                return current
        return ScheduleState(
            backend=current.backend,
            executable=current.executable,
            xdg_data_home=current.xdg_data_home,
            archive_enabled=current.archive_enabled,
            last_attempt_at=timestamp,
            last_success_at=timestamp if exit_code == 0 else current.last_success_at,
            last_result="success" if exit_code == 0 else "failed",
            last_exit_code=exit_code,
        )

    return _mutate_state(update)


def _config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))


def systemd_paths() -> tuple[Path, Path]:
    directory = _config_home() / "systemd" / "user"
    return directory / SYSTEMD_SERVICE, directory / SYSTEMD_TIMER


def launchd_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def _quoted_systemd_path(path: Path) -> str:
    value = str(path)
    if not path.is_absolute() or any(ord(char) < 32 for char in value):
        raise SchedulerError("scheduler executable path is invalid")
    return json.dumps(value.replace("%", "%%"))


def _systemd_environment(xdg_data_home: Path | None) -> str:
    if xdg_data_home is None:
        return ""
    value = str(xdg_data_home)
    if not xdg_data_home.is_absolute() or any(ord(char) < 32 for char in value):
        raise SchedulerError("scheduler data-home path is invalid")
    assignment = paths.data_home_environment_name() + "=" + value.replace("%", "%%")
    return f"Environment={json.dumps(assignment)}\n"


def render_systemd(
    executable: Path,
    *,
    xdg_data_home: Path | None = None,
    archive_enabled: bool = False,
) -> tuple[bytes, bytes]:
    """Return deterministic oneshot service/timer bytes for fixture tests."""
    command = _quoted_systemd_path(executable)
    environment = _systemd_environment(xdg_data_home)
    archive_argument = " --archive" if archive_enabled else ""
    service = f"""# {_MANAGED_SENTINEL.decode()}
[Unit]
Description=Run the private mybench reconciliation scan

[Service]
Type=oneshot
{environment}ExecStart={command} scan --quiet --scheduled{archive_argument}
NoNewPrivileges=true
PrivateTmp=true
""".encode()
    timer = f"""# {_MANAGED_SENTINEL.decode()}
[Unit]
Description=Run mybench scan daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30m
Unit={SYSTEMD_SERVICE}

[Install]
WantedBy=timers.target
""".encode()
    return service, timer


def render_launchd(
    executable: Path,
    *,
    xdg_data_home: Path | None = None,
    archive_enabled: bool = False,
) -> bytes:
    """Return a deterministic non-resident launchd agent plist."""
    value = str(executable)
    if not executable.is_absolute() or any(ord(char) < 32 for char in value):
        raise SchedulerError("scheduler executable path is invalid")
    arguments = [value, "scan", "--quiet", "--scheduled"]
    if archive_enabled:
        arguments.append("--archive")
    value_dict = {
        "KeepAlive": False,
        "Label": LAUNCHD_LABEL,
        "ProcessType": "Background",
        "ProgramArguments": arguments,
        "RunAtLoad": False,
        "StandardErrorPath": "/dev/null",
        "StandardOutPath": "/dev/null",
        "StartCalendarInterval": {"Hour": 3, "Minute": 0},
    }
    if xdg_data_home is not None:
        data_value = str(xdg_data_home)
        if not xdg_data_home.is_absolute() or any(ord(char) < 32 for char in data_value):
            raise SchedulerError("scheduler data-home path is invalid")
        value_dict["EnvironmentVariables"] = {paths.data_home_environment_name(): data_value}
    payload = plistlib.dumps(
        value_dict,
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )
    marker = b"<!-- " + _MANAGED_SENTINEL + b" -->\n"
    insertion = payload.index(b"<plist")
    return payload[:insertion] + marker + payload[insertion:]


def _ensure_external_parent(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    info = directory.lstat()
    if directory.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise SchedulerError("scheduler directory is insecure")


def _external_bytes(path: Path) -> bytes | None:
    if not os.path.lexists(path):
        return None
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SchedulerError("scheduler file is insecure")
        data = _read_fd(fd)
    finally:
        os.close(fd)
    return data


def _write_owned(path: Path, content: bytes) -> None:
    _ensure_external_parent(path.parent)
    current = _external_bytes(path)
    if current is not None and _MANAGED_SENTINEL not in current:
        raise SchedulerError("refusing to overwrite a foreign scheduler file")
    if current == content and stat.S_IMODE(path.lstat().st_mode) == _FILE_MODE:
        return
    fd, temporary = tempfile.mkstemp(prefix=".mybench-schedule-", dir=path.parent)
    try:
        os.fchmod(fd, _FILE_MODE)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise SchedulerError("scheduler file write failed")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _remove_owned(path: Path) -> bool:
    current = _external_bytes(path)
    if current is None:
        return False
    if _MANAGED_SENTINEL not in current:
        raise SchedulerError("refusing to remove a foreign scheduler file")
    path.unlink()
    return True


def _external_valid(path: Path, expected: bytes) -> bool:
    try:
        current = _external_bytes(path)
        if current != expected:
            return False
        info = path.lstat()
        return stat.S_IMODE(info.st_mode) == _FILE_MODE
    except (OSError, SchedulerError):
        return False


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        check=check,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _systemd_binary() -> str | None:
    return shutil.which("systemctl")


def _launchd_binary() -> str | None:
    return shutil.which("launchctl")


def _select_backend() -> str:
    if sys.platform.startswith("linux"):
        binary = _systemd_binary()
        if binary is not None:
            probe = _run([binary, "--user", "show-environment"], check=False)
            if probe.returncode == 0:
                return "systemd"
    elif sys.platform == "darwin":
        binary = _launchd_binary()
        if binary is not None:
            probe = _run([binary, "print", f"gui/{os.getuid()}"], check=False)
            if probe.returncode == 0:
                return "launchd"
    raise SchedulerError("no supported user scheduler is available; use --no-schedule")


def _cli_executable() -> Path:
    candidates = [Path(sys.executable).parent / "mybench"]
    discovered = shutil.which("mybench")
    if discovered is not None:
        candidates.append(Path(discovered))
    for candidate in candidates:
        try:
            info = candidate.lstat()
        except OSError:
            continue
        if (
            not candidate.is_symlink()
            and stat.S_ISREG(info.st_mode)
            and os.access(candidate, os.X_OK)
        ):
            return candidate.absolute()
    raise SchedulerError("the installed mybench CLI executable could not be found")


def _register(backend: str) -> None:
    if backend == "systemd":
        binary = _systemd_binary()
        if binary is None:
            raise SchedulerError("systemd user scheduler is unavailable")
        _run([binary, "--user", "daemon-reload"])
        _run([binary, "--user", "enable", "--now", SYSTEMD_TIMER])
    elif backend == "launchd":
        binary = _launchd_binary()
        if binary is None:
            raise SchedulerError("launchd is unavailable")
        domain = f"gui/{os.getuid()}"
        _run([binary, "bootout", domain, str(launchd_path())], check=False)
        _run([binary, "bootstrap", domain, str(launchd_path())])
        _run([binary, "enable", f"{domain}/{LAUNCHD_LABEL}"])
    else:
        raise SchedulerError("unknown scheduler backend")


def _unregister(backend: str) -> None:
    if backend == "systemd":
        binary = _systemd_binary()
        if binary is not None:
            _run([binary, "--user", "disable", "--now", SYSTEMD_TIMER], check=False)
            _run([binary, "--user", "reset-failed", SYSTEMD_SERVICE], check=False)
            _run([binary, "--user", "daemon-reload"], check=False)
    elif backend == "launchd":
        binary = _launchd_binary()
        if binary is not None:
            domain = f"gui/{os.getuid()}"
            _run([binary, "bootout", domain, str(launchd_path())], check=False)


def _remove_backend_files(backend: str) -> bool:
    removed = False
    if backend == "systemd":
        for path in systemd_paths():
            removed = _remove_owned(path) or removed
    elif backend == "launchd":
        removed = _remove_owned(launchd_path())
    return removed


def _assert_backend_files_owned(backend: str) -> None:
    candidates = systemd_paths() if backend == "systemd" else (launchd_path(),)
    for path in candidates:
        current = _external_bytes(path)
        if current is not None and _MANAGED_SENTINEL not in current:
            raise SchedulerError("scheduler path is occupied by a foreign file")


def _write_backend_files(
    backend: str,
    executable: Path,
    xdg_data_home: Path | None,
    archive_enabled: bool,
) -> None:
    if backend == "systemd":
        service, timer = render_systemd(
            executable,
            xdg_data_home=xdg_data_home,
            archive_enabled=archive_enabled,
        )
        service_path, timer_path = systemd_paths()
        _write_owned(service_path, service)
        _write_owned(timer_path, timer)
    elif backend == "launchd":
        _write_owned(
            launchd_path(),
            render_launchd(
                executable,
                xdg_data_home=xdg_data_home,
                archive_enabled=archive_enabled,
            ),
        )
    else:
        raise SchedulerError("unknown scheduler backend")


def enable(*, schedule: bool = True, archive_enabled: bool = False) -> ScheduleState:
    """Register daily capture or record the explicit manual fallback."""
    if not schedule and archive_enabled:
        raise SchedulerError("scheduled archive retention requires a scheduler")
    current = load()
    if not schedule:
        if current is not None and current.backend != "manual":
            _assert_backend_files_owned(current.backend)
            _unregister(current.backend)
            _remove_backend_files(current.backend)
        state = ScheduleState(
            backend="manual",
            executable=None,
            xdg_data_home=None,
            archive_enabled=False,
            last_attempt_at=current.last_attempt_at if current else None,
            last_success_at=current.last_success_at if current else None,
            last_result=current.last_result if current else "never",
            last_exit_code=current.last_exit_code if current else None,
        )
        return _store(state)

    backend = _select_backend()
    executable = _cli_executable()
    xdg_data_home = paths.configured_data_home()
    _assert_backend_files_owned(backend)
    if current is not None and current.backend not in {"manual", backend}:
        _assert_backend_files_owned(current.backend)
        _unregister(current.backend)
        _remove_backend_files(current.backend)
    try:
        _write_backend_files(backend, executable, xdg_data_home, archive_enabled)
        _register(backend)
        state = ScheduleState(
            backend=backend,
            executable=str(executable),
            xdg_data_home=str(xdg_data_home) if xdg_data_home is not None else None,
            archive_enabled=archive_enabled,
            last_attempt_at=current.last_attempt_at if current else None,
            last_success_at=current.last_success_at if current else None,
            last_result=current.last_result if current else "never",
            last_exit_code=current.last_exit_code if current else None,
        )
        return _store(state)
    except Exception:
        _unregister(backend)
        try:
            _remove_backend_files(backend)
        except Exception:  # noqa: BLE001 - retain the primary registration failure
            pass
        raise


def disable() -> bool:
    """Remove only mybench-owned scheduler state and job files."""
    state = load()
    removed = False
    if state is not None and state.backend != "manual":
        _assert_backend_files_owned(state.backend)
        _unregister(state.backend)
        removed = _remove_backend_files(state.backend) or removed
    removed = _clear_state() or removed
    return removed


def preflight_disable() -> None:
    """Validate removable schedule state and files without changing them."""
    state = load()
    if state is not None and state.backend != "manual":
        _assert_backend_files_owned(state.backend)


def _backend_active(backend: str) -> bool | None:
    if backend == "systemd":
        binary = _systemd_binary()
        if binary is None:
            return None
        enabled = _run(
            [binary, "--user", "is-enabled", "--quiet", SYSTEMD_TIMER],
            check=False,
        ).returncode
        active = _run(
            [binary, "--user", "is-active", "--quiet", SYSTEMD_TIMER],
            check=False,
        ).returncode
        return enabled == 0 and active == 0
    if backend == "launchd":
        binary = _launchd_binary()
        if binary is None:
            return None
        result = _run(
            [binary, "print", f"gui/{os.getuid()}/{LAUNCHD_LABEL}"],
            check=False,
        )
        return result.returncode == 0
    return False


def inspect() -> dict:
    """Return read-only local scheduler health with no path in the result."""
    state = load()
    if state is None:
        orphaned = any(os.path.lexists(path) for path in (*systemd_paths(), launchd_path()))
        if orphaned:
            raise SchedulerError("scheduler files exist without private state")
        return {
            "backend": "none",
            "registration_state": "absent",
            "enabled": None,
            "last_attempt_at": None,
            "last_success_at": None,
            "last_result": "never",
            "last_exit_code": None,
        }
    if state.backend == "manual":
        registration_state = "manual"
        enabled = False
    else:
        executable = Path(state.executable or "")
        xdg_data_home = Path(state.xdg_data_home) if state.xdg_data_home is not None else None
        if state.backend == "systemd":
            service, timer = render_systemd(
                executable,
                xdg_data_home=xdg_data_home,
                archive_enabled=state.archive_enabled,
            )
            service_path, timer_path = systemd_paths()
            files_valid = _external_valid(service_path, service) and _external_valid(
                timer_path, timer
            )
        else:
            files_valid = _external_valid(
                launchd_path(),
                render_launchd(
                    executable,
                    xdg_data_home=xdg_data_home,
                    archive_enabled=state.archive_enabled,
                ),
            )
        if not files_valid:
            raise SchedulerError("installed scheduler files are invalid")
        enabled = _backend_active(state.backend)
        registration_state = "active" if enabled is True else "inactive"
    return {
        "backend": state.backend,
        "registration_state": registration_state,
        "enabled": enabled,
        "last_attempt_at": state.last_attempt_at,
        "last_success_at": state.last_success_at,
        "last_result": state.last_result,
        "last_exit_code": state.last_exit_code,
    }
