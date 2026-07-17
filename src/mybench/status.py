"""Read-only, offline local capture-health summary (MYB-11.6)."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mybench import paths
from mybench.anchor.batch import verify_batch
from mybench.anchor.event import verify_event
from mybench.anchor.ots import proof_info
from mybench.hooks import binding
from mybench.ledger import Ledger
from mybench.scan_config import ScanConfig, load as load_scan_config
from mybench.scan_health import (
    ScanHealth,
    load as load_scan_health,
    load_scope_key,
    parse_timestamp,
    repo_id as health_repo_id,
    watch_id as health_watch_id,
)
from mybench.schemas import load_validator

STALE_AFTER_DAYS = 7
_LOOSE_BITS = 0o077
_MAX_PRIVATE_JSON = 1024 * 1024
_ERROR_ISSUES = {
    "data_tree_insecure",
    "enrollment_invalid",
    "internal_error",
    "ledger_invalid",
    "proof_invalid",
    "scan_config_invalid",
    "scan_receipt_invalid",
    "schedule_invalid",
}
_PRIVATE_KEY_PATHS = {
    "commit_signing": paths.commit_signing_key_path,
    "device": paths.device_key_path,
    "identity": paths.identity_key_path,
    "session_scope": paths.session_scope_key_path,
}
_MANAGED_DIRS = (
    paths.nonces_dir,
    paths.ledger_dir,
    paths.archive_dir,
    paths.reports_dir,
    paths.queue_dir,
    paths.keys_dir,
    paths.anchors_dir,
    paths.enrollments_dir,
)


class StatusError(RuntimeError):
    pass


def _clock_now() -> datetime:
    return datetime.now(UTC)


def _regular_private_state(path: Path) -> str:
    if not os.path.lexists(path):
        return "missing"
    try:
        info = path.lstat()
    except OSError:
        return "insecure"
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & _LOOSE_BITS
    ):
        return "insecure"
    return "present"


def _private_directory(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        not path.is_symlink()
        and stat.S_ISDIR(info.st_mode)
        and not (stat.S_IMODE(info.st_mode) & _LOOSE_BITS)
    )


def _data_state() -> str:
    root = paths.data_dir()
    if not os.path.lexists(root):
        return "absent"
    if not _private_directory(root):
        return "insecure"
    try:
        paths._assert_not_in_repo(root)
    except Exception:
        return "insecure"
    for path_fn in _MANAGED_DIRS:
        candidate = path_fn()
        if os.path.lexists(candidate) and not _private_directory(candidate):
            return "insecure"
    return "private"


def _read_private_json(path: Path) -> dict:
    if _regular_private_state(path) != "present":
        raise StatusError("private JSON storage is insecure")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        data = b""
        while len(data) <= _MAX_PRIVATE_JSON:
            chunk = os.read(fd, min(64 * 1024, _MAX_PRIVATE_JSON + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) > _MAX_PRIVATE_JSON:
            raise StatusError("private JSON storage is too large")
    finally:
        os.close(fd)
    value = json.loads(data)
    if not isinstance(value, dict):
        raise StatusError("private JSON value is invalid")
    return value


def _ledger_summary(issues: set[str]) -> tuple[dict, list[dict]]:
    target = paths.ledger_dir() / "ledger.jsonl"
    if not os.path.lexists(target):
        return {"state": "absent", "rows": 0}, []
    if _regular_private_state(target) != "present":
        issues.add("ledger_invalid")
        return {"state": "invalid", "rows": None}, []
    try:
        ledger = Ledger(target)
        count = ledger.verify_chain()
        rows = ledger.rows()
        if count != len(rows):
            raise StatusError("ledger count changed while status was reading")
    except Exception:
        issues.add("ledger_invalid")
        return {"state": "invalid", "rows": None}, []
    return {"state": "valid", "rows": count}, rows


def _load_config(issues: set[str]) -> tuple[str, ScanConfig | None]:
    try:
        config = load_scan_config()
    except Exception:
        issues.add("scan_config_invalid")
        return "invalid", None
    return ("valid", config) if config is not None else ("absent", None)


def _load_receipt(issues: set[str]) -> tuple[str, ScanHealth | None]:
    try:
        receipt = load_scan_health()
    except Exception:
        issues.add("scan_receipt_invalid")
        return "invalid", None
    return ("valid", receipt) if receipt is not None else ("absent", None)


def _schedule_summary(issues: set[str]) -> dict:
    from mybench.scheduler import inspect

    try:
        result = inspect()
    except Exception:
        issues.add("schedule_invalid")
        return {
            "backend": "none",
            "registration_state": "invalid",
            "enabled": None,
            "last_attempt_at": None,
            "last_success_at": None,
            "last_result": "never",
            "last_exit_code": None,
        }
    if result["registration_state"] == "inactive":
        issues.add("schedule_inactive")
    if result["last_result"] == "failed":
        issues.add("scheduled_scan_failed")
    return result


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _enrollment_ids(issues: set[str]) -> set[str]:
    directory = paths.enrollments_dir()
    if not directory.is_dir():
        return set()
    ids = set()
    for path in sorted(directory.glob("*.json")):
        try:
            value = _read_private_json(path)
            if set(value) != {"repo_id", "enroll_commit", "enroll_ts"}:
                raise StatusError("enrollment fields are invalid")
            repo_id = value["repo_id"]
            commit = value["enroll_commit"]
            if (
                not isinstance(repo_id, str)
                or not re.fullmatch(r"[0-9a-f]{16}", repo_id)
                or path.stem != repo_id
                or not isinstance(commit, str)
                or (commit and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit))
            ):
                raise StatusError("enrollment identity is invalid")
            parse_timestamp(value["enroll_ts"])
            ids.add(repo_id)
        except Exception:
            issues.add("enrollment_invalid")
    return ids


def _repo_summary(
    repo: Path,
    *,
    scope_key: bytes | None,
    receipt: ScanHealth | None,
    enrollment_ids: set[str],
    rows: list[dict],
    ledger_valid: bool,
    issues: set[str],
) -> tuple[dict, str | None]:
    last_scanned_at = None
    if scope_key is not None and receipt is not None:
        last_scanned_at = receipt.repo_times().get(health_repo_id(repo, scope_key))
    result = {
        "path": str(repo),
        "state": "missing",
        "last_scanned_at": last_scanned_at,
        "unbound_commits": None,
    }
    if not repo.is_dir():
        issues.add("repo_unavailable")
        return result, None
    try:
        top = Path(_git(repo, "rev-parse", "--show-toplevel"))
        if top.resolve() != repo.resolve():
            raise StatusError("configured repo is not its worktree root")
    except Exception:
        result["state"] = "not_repo"
        issues.add("repo_unavailable")
        return result, None
    if scope_key is None:
        result["state"] = "invalid"
        issues.add("keys_missing")
        return result, None
    try:
        binding_id = binding.repo_identity_for_worktree(top, scope_key=scope_key)
    except Exception:
        result["state"] = "invalid"
        issues.add("repo_unavailable")
        return result, None
    if not (top / binding.MARKER_RELPATH).is_file() or binding_id not in enrollment_ids:
        result["state"] = "not_enrolled"
        issues.add("repo_not_enrolled")
        return result, binding_id
    if not ledger_valid:
        result["state"] = "invalid"
        return result, binding_id
    try:
        record = _read_private_json(paths.enrollment_path(binding_id))
        enroll_commit = record["enroll_commit"]
        rev_range = f"{enroll_commit}..HEAD" if enroll_commit else "HEAD"
        reachable = set(_git(top, "rev-list", rev_range).split())
        bound = {
            row["commit_hash"]
            for row in rows
            if row["type"] == "binding" and row["repo_id"] == binding_id
        }
    except Exception:
        result["state"] = "invalid"
        issues.add("enrollment_invalid")
        return result, binding_id
    result["state"] = "ready"
    result["unbound_commits"] = len(reachable - bound)
    if result["unbound_commits"]:
        issues.add("unbound_commits")
    return result, binding_id


def _watch_summary(watch, scope_key: bytes | None, receipt: ScanHealth | None) -> dict:
    if watch.path.is_symlink():
        state = "symlink"
    elif watch.path.is_dir():
        state = "present"
    else:
        state = "missing"
    last_scanned_at = None
    if scope_key is not None and receipt is not None:
        last_scanned_at = receipt.watch_times().get(health_watch_id(watch, scope_key))
    return {
        "path": str(watch.path),
        "source": watch.source,
        "state": state,
        "last_scanned_at": last_scanned_at,
    }


def _candidate_files(base: Path, suffix: str) -> dict[str, Path]:
    if not base.is_dir():
        return {}
    found = {}
    for directory, dirnames, filenames in os.walk(base, topdown=True, followlinks=False):
        dirnames[:] = sorted(
            name for name in dirnames if name != ".git" and not name.startswith("archive")
        )
        current = Path(directory)
        for name in sorted(filenames):
            if name.endswith(suffix):
                path = current / name
                found[path.relative_to(base).as_posix()] = path
    return found


def _anchor_summary(issues: set[str]) -> dict:
    bases = (paths.anchors_dir(), paths.data_dir() / "anchors-repo")
    json_files: dict[str, Path] = {}
    proof_files: dict[str, Path] = {}
    for base in bases:
        for relative, path in _candidate_files(base, ".json").items():
            if relative in json_files and json_files[relative].read_bytes() != path.read_bytes():
                issues.add("proof_invalid")
            else:
                json_files[relative] = path
        for relative, path in _candidate_files(base, ".ots").items():
            if relative in proof_files and proof_files[relative].read_bytes() != path.read_bytes():
                issues.add("proof_invalid")
            else:
                proof_files[relative] = path
    dates = []
    artifact_roots: dict[str, bytes] = {}
    for relative, path in sorted(json_files.items()):
        is_event = re.fullmatch(
            r"anchors/[0-9a-f]{64}/[0-9]{4}/[0-9]{2}/[0-9]{2}\.json",
            relative,
        )
        is_flat_batch = re.fullmatch(r"anchor-[0-9]{8}-[0-9]{8}\.json", relative)
        if not is_event and not is_flat_batch:
            continue
        try:
            value = json.loads(path.read_bytes())
            if is_event:
                verify_event(value)
                date = value["date"]
                datetime.strptime(date, "%Y-%m-%d")
                expected = f"anchors/{value['identity_id']}/{date.replace('-', '/')}.json"
                if relative != expected:
                    raise StatusError("anchor event path does not match its identity/date")
                dates.append(date)
            else:
                verify_batch(value)
            root = bytes.fromhex(value["root"])
            if len(root) != 32:
                raise StatusError("anchor root is invalid")
            artifact_roots[relative] = root
        except Exception:
            issues.add("proof_invalid")
    confirmed = pending = invalid = 0
    for relative, path in sorted(proof_files.items()):
        if relative.endswith(".json.ots"):
            artifact_relative = relative[: -len(".ots")]
        elif relative.endswith(".root.ots"):
            artifact_relative = relative[: -len(".root.ots")] + ".json"
        else:
            invalid += 1
            continue
        try:
            root = artifact_roots.get(artifact_relative)
            if root is None:
                raise StatusError("proof has no matching artifact")
            info = proof_info(root, path.read_bytes())
            if not info["digest_matches"]:
                raise StatusError("proof does not bind its artifact")
            if info["confirmed"]:
                confirmed += 1
            else:
                pending += 1
        except Exception:
            invalid += 1
    if pending:
        issues.add("proof_pending")
    if invalid:
        issues.add("proof_invalid")
    return {
        "anchored_through": max(dates) if dates else None,
        "proofs": {"confirmed": confirmed, "pending": pending, "invalid": invalid},
    }


def _last_success(receipt: ScanHealth | None) -> str | None:
    if receipt is None:
        return None
    values = [
        value
        for value in (receipt.capture_completed_at, receipt.full_scan_completed_at)
        if value is not None
    ]
    return max(values) if values else None


def collect(*, now: datetime | None = None) -> dict:
    """Collect one status snapshot without writing, repairing, or networking."""
    now = now if now is not None else _clock_now()
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise StatusError("status clock must be UTC-aware")
    issues: set[str] = set()
    data_state = _data_state()
    if data_state == "absent":
        issues.add("not_initialized")
    elif data_state == "insecure":
        issues.add("data_tree_insecure")

    roles = {name: "missing" for name in _PRIVATE_KEY_PATHS}
    if data_state == "private":
        roles = {name: _regular_private_state(path_fn()) for name, path_fn in _PRIVATE_KEY_PATHS.items()}
        if any(state == "insecure" for state in roles.values()):
            issues.add("data_tree_insecure")
        elif any(state != "present" for state in roles.values()):
            issues.add("keys_missing")
    keys = {"expected": 4, "ready": sum(state == "present" for state in roles.values()), "roles": roles}

    config_state, config = ("absent", None)
    receipt_state, receipt = ("absent", None)
    scope_key = None
    ledger, rows = ({"state": "absent", "rows": 0}, [])
    anchors = {"anchored_through": None, "proofs": {"confirmed": 0, "pending": 0, "invalid": 0}}
    schedule = {
        "backend": "none",
        "registration_state": "absent",
        "enabled": None,
        "last_attempt_at": None,
        "last_success_at": None,
        "last_result": "never",
        "last_exit_code": None,
    }
    enrollment_ids: set[str] = set()
    if data_state == "private":
        config_state, config = _load_config(issues)
        receipt_state, receipt = _load_receipt(issues)
        try:
            scope_key = load_scope_key()
        except Exception:
            issues.add("keys_missing")
        ledger, rows = _ledger_summary(issues)
        enrollment_ids = _enrollment_ids(issues)
        anchors = _anchor_summary(issues)
    schedule = _schedule_summary(issues)

    watches = []
    repos = []
    mapped_enrollments: set[str] = set()
    if config is not None:
        watches = [_watch_summary(watch, scope_key, receipt) for watch in config.watches]
        if any(watch["state"] != "present" for watch in watches):
            issues.add("source_missing")
        for repo in config.repos:
            summary, binding_id = _repo_summary(
                repo,
                scope_key=scope_key,
                receipt=receipt,
                enrollment_ids=enrollment_ids,
                rows=rows,
                ledger_valid=ledger["state"] != "invalid",
                issues=issues,
            )
            repos.append(summary)
            if binding_id in enrollment_ids:
                mapped_enrollments.add(binding_id)
    unmapped = len(enrollment_ids - mapped_enrollments)
    if unmapped:
        issues.add("enrollment_unmapped")

    source_times = [item["last_scanned_at"] for item in (*watches, *repos)]
    stale = False
    if source_times:
        if any(value is None for value in source_times):
            stale = True
            issues.add("scan_never_completed")
        elif any(now - parse_timestamp(value) > timedelta(days=STALE_AFTER_DAYS) for value in source_times):
            stale = True
            issues.add("scan_stale")

    health = "healthy"
    if issues:
        health = "error" if issues & _ERROR_ISSUES else "attention"
    result = {
        "schema_version": "2",
        "command": "status",
        "health": health,
        "exit_code": 0 if health == "healthy" else 1,
        "data_dir": {"state": data_state},
        "keys": keys,
        "ledger": ledger,
        "scan": {
            "config_state": config_state,
            "receipt_state": receipt_state,
            "last_successful_at": _last_success(receipt),
            "stale": stale,
            "stale_after_days": STALE_AFTER_DAYS,
            "watches": watches,
            "repos": repos,
            "exclusions": list(config.exclusions) if config is not None else [],
            "unmapped_enrollments": unmapped,
        },
        "schedule": schedule,
        "anchors": anchors,
        "issues": sorted(issues),
    }
    errors = sorted(load_validator("status.schema.json").iter_errors(result), key=str)
    if errors:
        raise StatusError("status result violated its closed schema")
    return result


def failure() -> dict:
    """Closed, path-free fallback for an unexpected collector failure."""
    return {
        "schema_version": "2",
        "command": "status",
        "health": "error",
        "exit_code": 1,
        "data_dir": {"state": "insecure"},
        "keys": {
            "expected": 4,
            "ready": 0,
            "roles": {name: "insecure" for name in sorted(_PRIVATE_KEY_PATHS)},
        },
        "ledger": {"state": "invalid", "rows": None},
        "scan": {
            "config_state": "invalid",
            "receipt_state": "invalid",
            "last_successful_at": None,
            "stale": False,
            "stale_after_days": STALE_AFTER_DAYS,
            "watches": [],
            "repos": [],
            "exclusions": [],
            "unmapped_enrollments": 0,
        },
        "schedule": {
            "backend": "none",
            "registration_state": "invalid",
            "enabled": None,
            "last_attempt_at": None,
            "last_success_at": None,
            "last_result": "never",
            "last_exit_code": None,
        },
        "anchors": {
            "anchored_through": None,
            "proofs": {"confirmed": 0, "pending": 0, "invalid": 0},
        },
        "issues": ["internal_error"],
    }


def render(result: dict) -> str:
    """Human-readable local output; paths are shown only on this explicit surface."""
    lines = [f"mybench status: {result['health'].upper()}"]
    lines.append(
        f"data: {result['data_dir']['state']} · keys {result['keys']['ready']}/4 · "
        f"ledger {result['ledger']['state']} ({result['ledger']['rows']} rows)"
    )
    scan = result["scan"]
    last = scan["last_successful_at"] or "unknown"
    lines.append(
        f"scan: last successful {last} · watches {len(scan['watches'])} · "
        f"repos {len(scan['repos'])} · exclusions {len(scan['exclusions'])}"
    )
    for watch in scan["watches"]:
        lines.append(
            f"  watch {watch['source']} {watch['path']} · {watch['state']} · "
            f"last {watch['last_scanned_at'] or 'unknown'}"
        )
    for repo in scan["repos"]:
        unbound = "unknown" if repo["unbound_commits"] is None else str(repo["unbound_commits"])
        lines.append(
            f"  repo {repo['path']} · {repo['state']} · unbound {unbound} · "
            f"last {repo['last_scanned_at'] or 'unknown'}"
        )
    schedule = result["schedule"]
    lines.append(
        f"schedule: {schedule['registration_state']} ({schedule['backend']}) · "
        f"last {schedule['last_attempt_at'] or 'unknown'} · "
        f"result {schedule['last_result']}"
    )
    proofs = result["anchors"]["proofs"]
    lines.append(
        f"anchors: through {result['anchors']['anchored_through'] or 'unknown'} · "
        f"proofs {proofs['confirmed']} confirmed, {proofs['pending']} pending, "
        f"{proofs['invalid']} invalid"
    )
    if scan["stale"]:
        lines.append("history scan is stale; run mybench scan")
    if result["issues"]:
        lines.append("issues: " + ", ".join(result["issues"]))
    return "\n".join(lines)
