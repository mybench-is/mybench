"""Read-only orchestration-file structure inventory (MYB-13.7).

The scanner deliberately uses only no-follow directory descriptors, directory
enumeration, and ``stat``. It never opens an orchestration file, follows a
symlink, reads ambient time, or logs a path. Names remain in the private local
view; the registry-validated public view is a closed aggregate of fixed
category ids, coarse bands, and presence booleans after k-suppression.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from mybench import paths
from mybench.registry import Registry, RegistryError

TOPOLOGY_SCHEMA_VERSION = "1"
TOPOLOGY_REGISTRY_ID = "fingerprint.topology.file_structure"
TOPOLOGY_CATEGORIES = (
    "custom_agents",
    "hooks",
    "instruction_files",
    "lanes",
    "plan_task_directories",
    "skills",
    "validation_scripts",
    "worktrees",
)
_COUNT_EXACT = re.compile(r"([0-9]+)\Z")
_COUNT_RANGE = re.compile(r"([0-9]+)-([0-9]+)\Z")
_COUNT_PLUS = re.compile(r"([0-9]+)\+\Z")
_INSTRUCTION_FILES = {"agents.md", "claude.md", "copilot.md", "gemini.md"}
_ORCHESTRATION_ROOTS = {".claude", ".codex"}
_NAMED_CONTAINERS = {
    "agents",
    "hooks",
    "lanes",
    "plans",
    "skills",
    "tasks",
    "worktrees",
}
_PLAN_TASK_DIRS = {".plans", ".tasks", "plan", "plans", "task", "tasks"}
_WORKTREE_DIRS = {".worktrees", "worktree", "worktrees"}
_VALIDATION_SCRIPT = re.compile(r"(?:check|lint|validate|verify)[a-z0-9_.-]*\.(?:py|sh|bash)\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")


class TopologyScanError(ValueError):
    """The consented scan root or explicit metadata input is invalid."""


def _scan_times(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise TopologyScanError("scan time must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise TopologyScanError("scan time must be canonical UTC") from None
    if parsed.tzinfo != timezone.utc:
        raise TopologyScanError("scan time must be canonical UTC")
    iso_year, iso_week, _iso_weekday = parsed.isocalendar()
    return value, f"{iso_year:04d}-W{iso_week:02d}"


def _coverage(value: int | str) -> int | str:
    if value == "UNKNOWN":
        return value
    if type(value) is not int or not 0 <= value <= 10000:
        raise TopologyScanError("transcript-delegation coverage is invalid")
    return value


def _directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise TopologyScanError("safe descriptor-relative directory walking is unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_root(root: str | Path) -> int:
    """Open every caller-spelled root component without following symlinks.

    Relative roots are anchored at the current working-directory descriptor;
    absolute roots are anchored at ``/``. ``.`` is a no-op and ``..`` is
    rejected rather than giving consent an ambiguous traversal meaning.
    """

    try:
        raw = os.fspath(root)
    except TypeError:
        raise TopologyScanError("consented orchestration root is invalid") from None
    if not isinstance(raw, str) or not raw:
        raise TopologyScanError("consented orchestration root is invalid")
    parsed = Path(raw)
    parts = parsed.parts
    if ".." in parts:
        raise TopologyScanError("consented orchestration root may not contain dot-dot")
    flags = _directory_flags()
    if parsed.is_absolute():
        if parsed.anchor != os.sep:
            raise TopologyScanError("consented orchestration root has an unsupported anchor")
        components = parts[1:]
        anchor = os.sep
    else:
        components = tuple(part for part in parts if part != ".")
        anchor = "."

    current = -1
    try:
        current = os.open(anchor, flags)
        for component in components:
            following = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = following
        return current
    except OSError:
        if current >= 0:
            os.close(current)
        raise TopologyScanError("consented orchestration root could not be opened safely") from None


def _open_relative_directory(root_fd: int, relative: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    try:
        for component in relative:
            following = os.open(component, _directory_flags(), dir_fd=current)
            os.close(current)
            current = following
        return current
    except OSError:
        os.close(current)
        raise


def _bands(entry: dict, field: str) -> list[str]:
    for definition in entry["band_definitions"]:
        if definition["field"] == field:
            return list(definition["bands"])
    raise TopologyScanError("topology registry contract is incomplete")


def _const(entry: dict, field: str):
    try:
        return entry["output_schema"]["properties"][field]["const"]
    except (KeyError, TypeError):
        raise TopologyScanError("topology registry contract is incomplete") from None


def _count_band(value: int, bands: list[str]) -> str:
    for label in bands:
        exact = _COUNT_EXACT.fullmatch(label)
        if exact and value == int(exact.group(1)):
            return label
        interval = _COUNT_RANGE.fullmatch(label)
        if interval and int(interval.group(1)) <= value <= int(interval.group(2)):
            return label
        top = _COUNT_PLUS.fullmatch(label)
        if top and value >= int(top.group(1)):
            return label
    raise TopologyScanError("topology registry bands do not cover the value")


def _classifications(relative: tuple[str, ...], node_type: str) -> tuple[str, ...]:
    lowered = tuple(part.casefold() for part in relative)
    name = lowered[-1]
    parent = lowered[-2] if len(lowered) > 1 else ""
    categories: set[str] = set()

    if node_type == "file" and name in _INSTRUCTION_FILES:
        categories.add("instruction_files")
    if parent == "skills":
        categories.add("skills")
    if parent == "hooks":
        categories.add("hooks")
    if parent == "agents":
        categories.add("custom_agents")
    if parent == "lanes":
        categories.add("lanes")
    if parent in _WORKTREE_DIRS:
        categories.add("worktrees")
    if node_type == "directory" and name in _PLAN_TASK_DIRS:
        categories.add("plan_task_directories")
    if node_type == "file" and _VALIDATION_SCRIPT.fullmatch(name):
        categories.add("validation_scripts")
    return tuple(sorted(categories))


def _is_relevant(relative: tuple[str, ...], categories: tuple[str, ...]) -> bool:
    lowered = {part.casefold() for part in relative}
    return bool(categories or lowered & (_ORCHESTRATION_ROOTS | _NAMED_CONTAINERS))


def _walk(root_fd: int) -> tuple[dict[tuple[str, ...], dict], dict[str, int], list[int]]:
    metadata: dict[tuple[str, ...], dict] = {}
    counts = {category: 0 for category in TOPOLOGY_CATEGORIES}
    instruction_depths: list[int] = []
    pending = [()]

    try:
        while pending:
            prefix = pending.pop()
            directory_fd = _open_relative_directory(root_fd, prefix)
            try:
                child_directories = []
                with os.scandir(directory_fd) as iterator:
                    for entry in sorted(iterator, key=lambda item: item.name):
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            node_type = "directory"
                        elif stat.S_ISREG(info.st_mode):
                            node_type = "file"
                        elif stat.S_ISLNK(info.st_mode):
                            node_type = "symlink"
                        else:
                            node_type = "other"
                        relative = (*prefix, entry.name)
                        categories = _classifications(relative, node_type)
                        metadata[relative] = {
                            "entry_type": node_type,
                            "categories": list(categories),
                            "relevant": _is_relevant(relative, categories),
                        }
                        for category in categories:
                            counts[category] += 1
                        if "instruction_files" in categories:
                            instruction_depths.append(len(relative))
                        if node_type == "directory":
                            child_directories.append(relative)
                # Reverse the push order so the lexicographically first
                # directory is visited first. Output is sorted when frozen.
                pending.extend(reversed(child_directories))
            finally:
                os.close(directory_fd)
    except OSError:
        # A path-bearing exception or log would leak the very local names this
        # scanner protects.  Fail closed with a path-free error instead.
        raise TopologyScanError("consented orchestration root could not be scanned") from None
    return metadata, counts, instruction_depths


def _named_hierarchy(metadata: dict[tuple[str, ...], dict]) -> dict:
    root = {"name": ".", "entry_type": "directory", "categories": [], "children": {}}
    relevant = [relative for relative, details in metadata.items() if details["relevant"]]
    for relative in sorted(relevant):
        cursor = root
        for depth, name in enumerate(relative, start=1):
            prefix = relative[:depth]
            details = metadata[prefix]
            cursor = cursor["children"].setdefault(
                name,
                {
                    "name": name,
                    "entry_type": details["entry_type"],
                    "categories": details["categories"],
                    "children": {},
                },
            )

    def freeze(node: dict) -> dict:
        children = [freeze(child) for _name, child in sorted(node["children"].items())]
        return {
            "name": node["name"],
            "entry_type": node["entry_type"],
            "categories": node["categories"],
            "children": children,
        }

    return freeze(root)


def _public_aggregate(
    counts: dict[str, int],
    instruction_depths: list[int],
    *,
    observed_week: str,
    transcript_coverage: int | str,
    registry: Registry,
) -> dict:
    entry = registry.entry(TOPOLOGY_REGISTRY_ID)
    if entry["status"] != "active":
        raise TopologyScanError("topology descriptor is not active")
    support = registry.min_support(TOPOLOGY_REGISTRY_ID)
    if support != {"roots": 1}:
        raise TopologyScanError("topology root-support contract is invalid")
    floor = _const(entry, "k_suppression_floor")
    if type(floor) is not int or floor < 5:
        raise TopologyScanError("topology k-suppression contract is invalid")
    aggregate = {
        "schema_version": _const(entry, "schema_version"),
        "kind": _const(entry, "kind"),
        "file_structure_coverage_basis_points": _const(
            entry, "file_structure_coverage_basis_points"
        ),
        "transcript_delegation_coverage_basis_points": transcript_coverage,
        "state_basis": _const(entry, "state_basis"),
        "observed_week": observed_week,
        "k_suppression_floor": floor,
        "trust_tier": _const(entry, "trust_tier"),
        "caveats": _const(entry, "caveats"),
    }
    if aggregate["trust_tier"] != "ANCHORED":
        raise TopologyScanError("topology trust ceiling must remain ANCHORED")
    for category, count in sorted(counts.items()):
        if count < floor:
            continue
        field = f"{category}_count_band"
        aggregate[field] = _count_band(count, _bands(entry, field))
        aggregate[f"{category}_present"] = True
    if len(instruction_depths) >= floor:
        aggregate["instruction_depth_band"] = _count_band(
            max(instruction_depths), _bands(entry, "instruction_depth_band")
        )
    try:
        registry.check_claim(
            {
                "registry_id": TOPOLOGY_REGISTRY_ID,
                "registry_version": entry["version"],
                "derivation_class": entry["class"],
                "output": aggregate,
            }
        )
    except RegistryError as exc:
        raise TopologyScanError("publishable topology failed registry conformance") from exc
    return aggregate


def scan_orchestration_topology(
    root: str | Path,
    *,
    observed_at: str,
    transcript_delegation_coverage_basis_points: int | str = "UNKNOWN",
    registry: Registry | None = None,
) -> dict:
    """Inventory one explicitly consented root without reading file bytes.

    ``observed_at`` and transcript-derived coverage are explicit caller inputs;
    the function reads no clock or transcript data.  A successful root walk has
    100% coverage of that consented root, not a claim about the whole machine.
    """

    scanned_at, observed_week = _scan_times(observed_at)
    transcript_coverage = _coverage(transcript_delegation_coverage_basis_points)
    registry = registry or Registry.load()
    root_fd = _open_root(root)
    try:
        metadata, counts, instruction_depths = _walk(root_fd)
    finally:
        os.close(root_fd)

    local = {
        "schema_version": TOPOLOGY_SCHEMA_VERSION,
        "kind": "orchestration-topology-local",
        "trust_tier": "ANCHORED",
        "scan": {
            "source": "file-structure",
            "coverage_basis_points": 10000,
            "coverage_basis": "complete-consented-root-walk",
            "scanned_at": scanned_at,
            "state_basis": "scan-time-state-not-evidence-period",
        },
        "transcript_delegation": {
            "source": "transcript-delegation",
            "coverage_basis_points": transcript_coverage,
            "state_basis": "evidence-period-aggregate",
        },
        "named_hierarchy": _named_hierarchy(metadata),
        "structure_counts": dict(sorted(counts.items())),
        "instruction_depth": max(instruction_depths, default=0),
        "presence_flags": {category: count > 0 for category, count in sorted(counts.items())},
    }
    return {
        "local": local,
        "publishable": _public_aggregate(
            counts,
            instruction_depths,
            observed_week=observed_week,
            transcript_coverage=transcript_coverage,
            registry=registry,
        ),
    }


def store_local_topology(local_inventory: dict) -> Path:
    """Store one private inventory as a mode-0600 A10 report artifact.

    The content digest names its mode-0700 report directory.  An identical
    inventory is idempotent; a conflicting pre-existing file fails closed.
    """

    if not isinstance(local_inventory, dict) or local_inventory.get("kind") != (
        "orchestration-topology-local"
    ):
        raise TopologyScanError("local topology inventory is invalid")
    content = (
        json.dumps(
            local_inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        + b"\n"
    )
    report_id = hashlib.sha256(content).hexdigest()
    directory = paths.ensure_report_dir(report_id)
    target = directory / "orchestration-topology.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError:
        try:
            info = target.lstat()
            existing = target.read_bytes()
        except OSError:
            raise TopologyScanError("local topology storage refused") from None
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or existing != content
        ):
            raise TopologyScanError("local topology storage refused")
        return target
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise TopologyScanError("local topology storage refused")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return target


__all__ = [
    "TOPOLOGY_CATEGORIES",
    "TOPOLOGY_REGISTRY_ID",
    "TOPOLOGY_SCHEMA_VERSION",
    "TopologyScanError",
    "scan_orchestration_topology",
    "store_local_topology",
]
