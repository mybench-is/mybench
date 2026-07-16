"""Consent-first source discovery and private scan configuration (MYB-11.3).

Discovery reads directory metadata only.  It never opens a transcript or a
git control file, and git traversal has no implicit root.  Confirmed paths
are the one intentional local-path surface and live only in the private
mybench data directory.
"""

from __future__ import annotations

import fnmatch
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from mybench import paths
from mybench.daemon.capture import WatchSpec
from mybench.schemas import load_validator

DETECT_KINDS = ("claude", "codex", "git")
_GLOB_CHARS = "*?["
_MAX_CONFIG_BYTES = 1024 * 1024


class ScanConfigError(RuntimeError):
    """A discovery request or private scan config is invalid or insecure."""


@dataclass(frozen=True)
class Proposal:
    kind: str
    path: Path
    source: str | None = None

    def as_dict(self) -> dict[str, str]:
        value = {"kind": self.kind, "path": str(self.path)}
        if self.source is not None:
            value["source"] = self.source
        return value


@dataclass(frozen=True)
class ScanConfig:
    watches: tuple[WatchSpec, ...] = ()
    repos: tuple[Path, ...] = ()
    exclusions: tuple[str, ...] = ()

    @classmethod
    def from_proposals(
        cls, proposals: tuple[Proposal, ...], exclusions: tuple[str, ...]
    ) -> ScanConfig:
        watches = tuple(
            WatchSpec(proposal.path, proposal.source)
            for proposal in proposals
            if proposal.source is not None
        )
        repos = tuple(proposal.path for proposal in proposals if proposal.kind == "git")
        return cls(
            watches=tuple(sorted(set(watches), key=lambda watch: (str(watch.path), watch.source))),
            repos=tuple(sorted(set(repos), key=str)),
            exclusions=tuple(sorted(set(exclusions))),
        )

    def as_dict(self) -> dict:
        return {
            "schema_version": "1",
            "watches": [
                {"path": str(watch.path), "source": watch.source} for watch in self.watches
            ],
            "repos": [str(repo) for repo in self.repos],
            "exclusions": list(self.exclusions),
        }


def parse_detect_kinds(raw: str) -> tuple[str, ...]:
    kinds = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not kinds or len(kinds) != len(set(kinds)) or any(kind not in DETECT_KINDS for kind in kinds):
        raise ScanConfigError("invalid discovery kind")
    return kinds


def _absolute(path: Path | str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def is_excluded(path: Path, exclusions: tuple[str, ...], *, root: Path | None = None) -> bool:
    """Return whether ``path`` matches an absolute prefix or path glob.

    Relative patterns are evaluated against the active traversal root and
    basename/path suffixes; absolute non-globs are prefix matches.  No path is
    resolved, so matching cannot follow a symlink or enter an excluded tree.
    """
    candidate = _absolute(path)
    relative = None
    if root is not None:
        try:
            relative = candidate.relative_to(_absolute(root))
        except ValueError:
            relative = None
    for raw in exclusions:
        expanded = os.path.expanduser(raw)
        has_glob = any(char in expanded for char in _GLOB_CHARS)
        if os.path.isabs(expanded) and not has_glob:
            prefix = _absolute(expanded)
            if candidate == prefix or candidate.is_relative_to(prefix):
                return True
            continue
        spellings = (str(candidate), candidate.as_posix())
        if relative is not None:
            spellings += (str(relative), relative.as_posix())
        if has_glob and any(fnmatch.fnmatchcase(value, expanded) for value in spellings):
            return True
        if not has_glob and relative is not None:
            prefix = Path(expanded)
            if relative == prefix or relative.is_relative_to(prefix):
                return True
        if not has_glob and expanded in candidate.parts:
            return True
    return False


def _discover_git(root: Path, exclusions: tuple[str, ...]) -> list[Proposal]:
    root = _absolute(root)
    if is_excluded(root, exclusions, root=root):
        return []
    if root.is_symlink() or not root.is_dir():
        raise ScanConfigError("invalid git discovery root")
    proposals = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name != ".git"
            and not (current / name).is_symlink()
            and not is_excluded(current / name, exclusions, root=root)
        )
        if ".git" in filenames or (current / ".git").is_dir():
            proposals.append(Proposal("git", _absolute(current)))
            dirnames[:] = []
    return proposals


def discover(
    kinds: tuple[str, ...],
    *,
    home: Path,
    git_roots: tuple[Path, ...],
    exclusions: tuple[str, ...],
) -> tuple[Proposal, ...]:
    """Discover only requested, non-excluded sources without reading files."""
    if any(kind not in DETECT_KINDS for kind in kinds):
        raise ScanConfigError("invalid discovery kind")
    if "git" in kinds and not git_roots:
        raise ScanConfigError("git discovery requires an explicit root")
    proposals: list[Proposal] = []
    known = {
        "claude": (_absolute(home / ".claude" / "projects"), "claude-code"),
        "codex": (_absolute(home / ".codex" / "sessions"), "codex"),
    }
    for kind in kinds:
        if kind in known:
            location, source = known[kind]
            if not is_excluded(location, exclusions) and location.is_dir():
                proposals.append(Proposal(kind, location, source))
        elif kind == "git":
            for root in git_roots:
                proposals.extend(_discover_git(root, exclusions))
    unique = {(proposal.kind, str(proposal.path), proposal.source): proposal for proposal in proposals}
    return tuple(unique[key] for key in sorted(unique))


def _validate_dict(value: object) -> dict:
    load_validator("scan_config.schema.json").validate(value)
    if not isinstance(value, dict):  # schema already enforces this; keeps typing honest
        raise ScanConfigError("invalid scan config")
    watches = tuple(
        WatchSpec(_absolute(item["path"]), item["source"]) for item in value["watches"]
    )
    repos = tuple(_absolute(repo) for repo in value["repos"])
    exclusions = tuple(value["exclusions"])
    config = ScanConfig(
        watches=tuple(sorted(watches, key=lambda watch: (str(watch.path), watch.source))),
        repos=tuple(sorted(repos, key=str)),
        exclusions=tuple(sorted(exclusions)),
    )
    if value != config.as_dict():
        raise ScanConfigError("scan config is not canonical")
    return value


def _check_fd(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ScanConfigError("scan config storage is insecure")


def _check_parent(directory: Path) -> None:
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or directory.is_symlink()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ScanConfigError("scan config parent is insecure")


def load() -> ScanConfig | None:
    """Load the private config, returning ``None`` when it has not been accepted."""
    target = paths.scan_config_path()
    if not os.path.lexists(target):
        return None
    _check_parent(target.parent)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags)
    try:
        _check_fd(fd)
        data = b""
        while len(data) <= _MAX_CONFIG_BYTES:
            chunk = os.read(fd, min(64 * 1024, _MAX_CONFIG_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) > _MAX_CONFIG_BYTES:
            raise ScanConfigError("scan config is too large")
    finally:
        os.close(fd)
    try:
        value = json.loads(data)
        _validate_dict(value)
    except ScanConfigError:
        raise
    except Exception as exc:  # validation/parser details can contain private values
        raise ScanConfigError("scan config is invalid") from exc
    return ScanConfig(
        watches=tuple(WatchSpec(Path(item["path"]), item["source"]) for item in value["watches"]),
        repos=tuple(Path(repo) for repo in value["repos"]),
        exclusions=tuple(value["exclusions"]),
    )


def store(config: ScanConfig) -> Path:
    """Atomically persist one canonical, owner-only confirmed configuration."""
    value = config.as_dict()
    try:
        _validate_dict(value)
    except ScanConfigError:
        raise
    except Exception as exc:
        raise ScanConfigError("scan config is invalid") from exc
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    directory = paths.ensure_data_dir()
    target = paths.scan_config_path()
    if os.path.lexists(target):
        existing = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            _check_fd(existing)
        finally:
            os.close(existing)
    temporary = directory / f".scan-config.{secrets.token_hex(8)}.tmp"
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
                raise ScanConfigError("scan config write failed")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, target)
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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
    return target
