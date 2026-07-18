"""Read-only orchestration-file structure inventory (MYB-13.7).

The scanner deliberately uses only directory enumeration and ``stat``.  It
never opens an orchestration file, follows a symlink, reads ambient time, or
logs a path.  Names remain in the private local view; the separately validated
public view is a closed aggregate of fixed category ids, coarse bands, and
presence booleans after k-suppression.
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
from mybench.schemas import load_validator

TOPOLOGY_SCHEMA_VERSION = "1"
TOPOLOGY_K = 5
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

_COUNT_BANDS = (
    ("0", 0, 0),
    ("1-4", 1, 4),
    ("5-19", 5, 19),
    ("20-99", 20, 99),
    ("100-999", 100, 999),
    ("1000+", 1000, None),
)
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


def _observed_at(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise TopologyScanError("scan time must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise TopologyScanError("scan time must be canonical UTC") from None
    if parsed.tzinfo != timezone.utc:
        raise TopologyScanError("scan time must be canonical UTC")
    return value, value[:10]


def _coverage(value: int | str) -> int | str:
    if value == "UNKNOWN":
        return value
    if type(value) is not int or not 0 <= value <= 10000:
        raise TopologyScanError("transcript-delegation coverage is invalid")
    return value


def _count_band(value: int) -> str:
    for label, lower, upper in _COUNT_BANDS:
        if value >= lower and (upper is None or value <= upper):
            return label
    raise TopologyScanError("topology count is invalid")


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


def _walk(root: Path) -> tuple[dict[tuple[str, ...], dict], dict[str, int], list[int]]:
    metadata: dict[tuple[str, ...], dict] = {}
    counts = {category: 0 for category in TOPOLOGY_CATEGORIES}
    instruction_depths: list[int] = []
    pending = [(root, ())]

    try:
        while pending:
            directory, prefix = pending.pop()
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
            child_directories = []
            for entry in entries:
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
                    child_directories.append((Path(entry.path), relative))
            # Reverse the push order so the lexicographically first directory
            # is visited first.  Output is sorted again when the trie freezes.
            pending.extend(reversed(child_directories))
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
    observed_on: str,
    transcript_coverage: int | str,
) -> dict:
    supported = {
        category: _count_band(count)
        for category, count in sorted(counts.items())
        if count >= TOPOLOGY_K
    }
    aggregate = {
        "schema_version": TOPOLOGY_SCHEMA_VERSION,
        "kind": "orchestration-topology-aggregate",
        "trust_tier": "ANCHORED",
        "state_basis": "scan-time-state-not-evidence-period",
        "observed_on": observed_on,
        "evidence_sources": [
            {"source": "file-structure", "coverage_basis_points": 10000},
            {
                "source": "transcript-delegation",
                "coverage_basis_points": transcript_coverage,
            },
        ],
        "structure_count_bands": supported,
        "presence_flags": {category: True for category in supported},
    }
    if len(instruction_depths) >= TOPOLOGY_K:
        aggregate["instruction_depth_band"] = _count_band(max(instruction_depths))
    errors = sorted(
        load_validator("orchestration_topology.schema.json").iter_errors(aggregate), key=str
    )
    if errors:
        raise TopologyScanError("publishable topology shape is invalid")
    return aggregate


def scan_orchestration_topology(
    root: str | Path,
    *,
    observed_at: str,
    transcript_delegation_coverage_basis_points: int | str = "UNKNOWN",
) -> dict:
    """Inventory one explicitly consented root without reading file bytes.

    ``observed_at`` and transcript-derived coverage are explicit caller inputs;
    the function reads no clock or transcript data.  A successful root walk has
    100% coverage of that consented root, not a claim about the whole machine.
    """

    scanned_at, observed_on = _observed_at(observed_at)
    transcript_coverage = _coverage(transcript_delegation_coverage_basis_points)
    root = Path(root).absolute()
    try:
        root_info = root.lstat()
    except OSError:
        raise TopologyScanError("consented orchestration root is unavailable") from None
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise TopologyScanError("consented orchestration root must be a non-symlink directory")

    metadata, counts, instruction_depths = _walk(root)
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
            observed_on=observed_on,
            transcript_coverage=transcript_coverage,
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
    "TOPOLOGY_K",
    "TOPOLOGY_SCHEMA_VERSION",
    "TopologyScanError",
    "scan_orchestration_topology",
    "store_local_topology",
]
