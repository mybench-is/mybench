"""Unified local-first command surface (MYB-11.2).

Imports from the product modules stay inside command handlers.  Besides
keeping command startup small, this means an installed wheel can always show
``mybench --help`` before dependency diagnostics run.

Exit codes are stable across the command tree:

* 0: operation completed (or verification passed)
* 1: operation failed (or verification failed)
* 2: invalid command-line usage (argparse)
* 3: reserved surface is honestly unavailable in this version

No command publishes anything.  Network access exists only behind the
explicit ``scan --upgrade`` and online ``verify`` flags.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3

_REPORT_DOMAIN = b"mybench:v1:local-report\x00"
_REPORT_FILES = {"html": "index.html", "json": "report.json"}


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit one machine-readable JSON object")


def _parser() -> argparse.ArgumentParser:
    from mybench import __version__

    parser = argparse.ArgumentParser(
        prog="mybench",
        description="Private-by-default developer evidence and local reports.",
    )
    parser.add_argument("--version", action="version", version=f"mybench {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create the private data directory and local keys")
    init.add_argument(
        "--local-first",
        action="store_true",
        help="explicitly select the current local-only mode (already the default)",
    )
    init.add_argument(
        "--detect",
        nargs="?",
        const="claude,codex",
        metavar="KINDS",
        help="propose comma-separated sources: claude,codex,git",
    )
    init.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="PATH",
        help="explicit git discovery root (repeatable; required for git)",
    )
    decision = init.add_mutually_exclusive_group()
    decision.add_argument(
        "--accept-all", action="store_true", help="confirm every non-excluded proposal"
    )
    decision.add_argument(
        "--decline", action="store_true", help="decline every proposal and write nothing"
    )
    init.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="exclude an absolute path prefix or glob (repeatable)",
    )
    _add_json(init)

    scan = sub.add_parser("scan", help="capture once, flush queued events, and reconcile repos")
    scan.add_argument(
        "--watch",
        action="append",
        default=[],
        metavar="DIR:SOURCE",
        help="explicit transcript directory and source kind (repeatable)",
    )
    scan.add_argument(
        "--repo",
        action="append",
        default=[],
        metavar="PATH",
        help="enrolled repo to reconcile (repeatable; default: current directory)",
    )
    scan.add_argument(
        "--archive",
        action="store_true",
        help="retain exact private transcript preimages (off unless explicit)",
    )
    scan.add_argument(
        "--upgrade",
        action="store_true",
        help="explicitly use the network to upgrade staged OpenTimestamps proofs",
    )
    _add_json(scan)

    report = sub.add_parser("report", help="build a deterministic private local report")
    report.add_argument(
        "--format",
        default="html,json",
        metavar="html,json",
        help="comma-separated output formats: html, json (default: html,json)",
    )
    report.add_argument(
        "--generated-at",
        help="UTC RFC3339 scorer time (default: current UTC; provide for reproducible builds)",
    )
    report.add_argument("--report-version", default="v0")
    report.add_argument(
        "--enrolled-repo",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="public named repo scorer input (repeatable)",
    )
    report.add_argument(
        "--public",
        action="append",
        default=[],
        metavar="NAME",
        help="assert that an enrolled named repo is public (repeatable)",
    )
    report.add_argument("--handle", help="public handle rendered into the local page")
    report.add_argument(
        "--anchors-url",
        default="https://mybench.is/anchors",
        help="public anchors URL rendered into the page",
    )
    report.add_argument("--open", action="store_true", help="reserved browser opener")
    report.add_argument("--serve", action="store_true", help="reserved local report server")
    _add_json(report)

    capture = sub.add_parser("capture", help="manage explicit evidence capture")
    capture_sub = capture.add_subparsers(dest="capture_command", required=True)
    enable = capture_sub.add_parser("enable", help="opt repos into local commit binding")
    enable.add_argument(
        "--repo", action="append", required=True, metavar="PATH", help="repo to enroll (repeatable)"
    )
    _add_json(enable)

    status = sub.add_parser("status", help="reserved local health summary")
    _add_json(status)

    publish = sub.add_parser("publish", help="reserved publication surface")
    publish.add_argument(
        "--preview", action="store_true", help="reserved publication preview (still unavailable)"
    )
    _add_json(publish)

    verify = sub.add_parser("verify", help="verify a public anchors log")
    verify.add_argument("source", help="anchors directory or git/https URL")
    verify.add_argument(
        "--offline",
        action="store_true",
        help="skip network Bitcoin-header cross-checks",
    )
    _add_json(verify)
    return parser


def _emit(payload: dict, *, as_json: bool, human: str, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    if as_json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=stream)
    else:
        print(human, file=stream)


def _unavailable(command: str, *, as_json: bool) -> int:
    payload = {
        "command": command,
        "error": "not_yet_available",
        "exit_code": EXIT_UNAVAILABLE,
        "status": "unavailable",
    }
    publication = command.startswith("publish")
    if publication:
        payload["published"] = False
    _emit(
        payload,
        as_json=as_json,
        human=(
            f"{command}: not yet available; nothing published"
            if publication
            else f"{command}: not yet available"
        ),
        error=True,
    )
    return EXIT_UNAVAILABLE


def _failed(command: str, *, as_json: bool, error: str = "operation_failed") -> int:
    payload = {
        "command": command,
        "error": error,
        "exit_code": EXIT_FAILED,
        "status": "error",
    }
    _emit(
        payload,
        as_json=as_json,
        human=f"{command}: operation failed ({error})",
        error=True,
    )
    return EXIT_FAILED


def _init(args: argparse.Namespace) -> int:
    if args.detect is not None:
        return _init_detect(args)
    try:
        from mybench import paths

        paths.ensure_data_dir()
        paths.ensure_session_scope_key()
        paths.ensure_device_key()
        paths.ensure_identity_key()
        paths.ensure_commit_signing_key()
    except Exception:  # noqa: BLE001 - never relay a path or key-bearing exception
        return _failed("init", as_json=args.json)
    payload = {"command": "init", "keys_ready": 4, "status": "ok"}
    _emit(payload, as_json=args.json, human="mybench initialized locally (4 key roles ready)")
    return EXIT_OK


def _proposal_payload(proposals, exclusions: tuple[str, ...]) -> dict:
    return {
        "command": "init --detect",
        "configured": False,
        "exclusions": list(exclusions),
        "proposals": [proposal.as_dict() for proposal in proposals],
        "status": "proposed",
    }


def _emit_proposals(payload: dict, *, as_json: bool) -> None:
    if as_json:
        _emit(payload, as_json=True, human="")
        return
    print("Proposed local scan locations (no capture data has been read):")
    if not payload["proposals"]:
        print("  (none)")
    for proposal in payload["proposals"]:
        print(f"  {proposal['kind']}: {proposal['path']}")
    if payload["exclusions"]:
        print("Exclusions:")
        for exclusion in payload["exclusions"]:
            print(f"  {exclusion}")
    print("Nothing has been configured.")


def _init_detect(args: argparse.Namespace) -> int:
    try:
        from mybench import paths
        from mybench.scan_config import (
            ScanConfig,
            discover,
            parse_detect_kinds,
            store,
        )

        kinds = parse_detect_kinds(args.detect)
        exclusions = tuple(sorted(set(args.exclude)))
        if any(not exclusion or "\x00" in exclusion for exclusion in exclusions):
            raise ValueError("invalid exclusion")
        proposals = discover(
            kinds,
            home=Path.home(),
            git_roots=tuple(Path(root) for root in args.root),
            exclusions=exclusions,
        )
    except Exception:  # noqa: BLE001 - discovery paths stay out of closed errors
        return _failed("init --detect", as_json=args.json, error="discovery_failed")

    payload = _proposal_payload(proposals, exclusions)
    if args.decline:
        payload.update({"status": "declined"})
        _emit(
            payload,
            as_json=args.json,
            human="Source proposals declined; nothing was configured.",
        )
        return EXIT_OK
    if not args.accept_all:
        _emit_proposals(payload, as_json=args.json)
        if args.json or not sys.stdin.isatty():
            return EXIT_OK
        try:
            confirmed = input("Confirm all non-excluded locations? [y/N] ").strip().lower()
        except EOFError:
            confirmed = ""
        if confirmed not in {"y", "yes"}:
            print("Source proposals declined; nothing was configured.")
            return EXIT_OK

    try:
        paths.ensure_data_dir()
        paths.ensure_session_scope_key()
        paths.ensure_device_key()
        paths.ensure_identity_key()
        paths.ensure_commit_signing_key()
        store(ScanConfig.from_proposals(proposals, exclusions))
    except Exception:  # noqa: BLE001 - never relay a confirmed local path or key detail
        return _failed("init --detect", as_json=args.json)
    accepted = {
        "command": "init --detect",
        "configured": True,
        "exclusions": len(exclusions),
        "keys_ready": 4,
        "repos": sum(proposal.kind == "git" for proposal in proposals),
        "status": "ok",
        "watches": sum(proposal.source is not None for proposal in proposals),
    }
    _emit(
        accepted,
        as_json=args.json,
        human=(
            f"Configured {accepted['watches']} watch(es), {accepted['repos']} repo(s), "
            f"and {accepted['exclusions']} exclusion(s) locally."
        ),
    )
    return EXIT_OK


def _watch_specs(raw_specs: list[str]):
    from mybench.daemon.capture import ConfigError, WatchSpec

    watches = []
    for raw in raw_specs:
        directory, separator, source = raw.rpartition(":")
        if not separator or not directory or not source:
            raise ConfigError("invalid watch")
        watches.append(WatchSpec(Path(directory), source))
    return tuple(watches)


def _upgrade_proofs() -> tuple[int, int]:
    from mybench import paths
    from mybench.anchor import ots

    proofs = sorted(paths.anchors_dir().rglob("*.json.ots"))
    return len(proofs), sum(ots.upgrade_batch_proof(path) for path in proofs)


def _scan(args: argparse.Namespace) -> int:
    try:
        from mybench.daemon.capture import Daemon, DaemonConfig, default_config
        from mybench.hooks.binding import reconcile
        from mybench.scan_config import load

        stored = load()
        if args.watch:
            watches = _watch_specs(args.watch)
        elif stored is not None:
            watches = stored.watches
        else:
            watches = default_config().watches
        exclusions = stored.exclusions if stored is not None else ()
        logging.basicConfig(
            stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(message)s"
        )
        if watches:
            config = DaemonConfig(
                watches=watches,
                archive_enabled=args.archive,
                exclusions=exclusions,
            )
            rows = Daemon(config).scan_once()
        else:
            config = None
            rows = 0
        repos = args.repo or ([str(repo) for repo in stored.repos] if stored else [str(Path.cwd())])
        bindings = sum(reconcile(Path(repo)) for repo in repos)
        proofs, confirmed = _upgrade_proofs() if args.upgrade else (0, 0)
    except Exception:  # noqa: BLE001 - source paths and internals are a leak surface
        return _failed("scan", as_json=args.json)
    payload = {
        "bindings_appended": bindings,
        "command": "scan",
        "proofs_confirmed": confirmed,
        "proofs_staged": proofs,
        "rows_appended": rows,
        "status": "ok",
        "upgrade_requested": args.upgrade,
        "watches": len(watches),
    }
    _emit(
        payload,
        as_json=args.json,
        human=(
            f"scan complete: watches={len(watches)} rows_appended={rows} "
            f"bindings_appended={bindings} proofs_confirmed={confirmed}/{proofs}"
        ),
    )
    return EXIT_OK


def _formats(raw: str) -> tuple[str, ...]:
    values = tuple(part.strip() for part in raw.split(",") if part.strip())
    if (
        not values
        or len(set(values)) != len(values)
        or any(value not in _REPORT_FILES for value in values)
    ):
        raise ValueError("invalid report format")
    return values


def _generated_at(raw: str | None) -> str:
    if raw is None:
        return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.now(UTC).utcoffset():
        raise ValueError("generated-at must be UTC")
    return parsed.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _report_id(report_bytes: bytes, page_bytes: bytes) -> str:
    framed = (
        _REPORT_DOMAIN
        + len(report_bytes).to_bytes(8, "big")
        + report_bytes
        + len(page_bytes).to_bytes(8, "big")
        + page_bytes
    )
    return hashlib.sha256(framed).hexdigest()


def _private_file(directory: Path, name: str, content: bytes) -> None:
    """Idempotently install one fixed-name 0600 report file without symlink following."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        try:
            fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            try:
                info = os.fstat(fd)
                existing = b""
                while chunk := os.read(fd, 1024 * 1024):
                    existing += chunk
            finally:
                os.close(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or existing != content
            ):
                raise RuntimeError("local report storage refused")
            return
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise RuntimeError("local report storage refused")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _report(args: argparse.Namespace) -> int:
    if args.open or args.serve:
        surface = "report --open" if args.open else "report --serve"
        return _unavailable(surface, as_json=args.json)
    try:
        from mybench import paths
        from mybench.report.page import render_page
        from mybench.scorer.__main__ import build_report

        formats = _formats(args.format)
        report_bytes = build_report(
            generated_at=_generated_at(args.generated_at),
            report_version=args.report_version,
            enrolled_specs=args.enrolled_repo,
            public_names=args.public,
        )
        report = json.loads(report_bytes)
        page_bytes = render_page(
            report,
            anchors_url=args.anchors_url,
            handle=args.handle,
            report_json_href="report.json",
        )
        report_id = _report_id(report_bytes, page_bytes)
        directory = paths.ensure_report_dir(report_id)
        artifacts = {"html": page_bytes, "json": report_bytes}
        for selected in formats:
            _private_file(directory, _REPORT_FILES[selected], artifacts[selected])
    except Exception:  # noqa: BLE001 - scorer inputs and local paths stay out of CLI errors
        return _failed("report", as_json=args.json)
    payload = {
        "command": "report",
        "formats": list(formats),
        "report_id": report_id,
        "status": "ok",
    }
    _emit(
        payload,
        as_json=args.json,
        human=f"report ready: id={report_id} formats={','.join(formats)} (private, local only)",
    )
    return EXIT_OK


def _capture_enable(args: argparse.Namespace) -> int:
    try:
        from mybench.hooks.binding import enroll

        records = [enroll(repo) for repo in args.repo]
    except Exception:  # noqa: BLE001 - repo paths must never reach command output
        return _failed("capture enable", as_json=args.json)
    payload = {"command": "capture enable", "repos_enrolled": len(records), "status": "ok"}
    _emit(
        payload,
        as_json=args.json,
        human=f"capture enabled for {len(records)} repo(s); no scheduler was installed",
    )
    return EXIT_OK


def _verify(args: argparse.Namespace) -> int:
    try:
        from mybench.verify.cli import verify_anchors

        result = verify_anchors(args.source, check_bitcoin=not args.offline)
    except Exception:  # noqa: BLE001 - keep unified failures stable and closed
        return _failed("verify", as_json=args.json, error="verification_failed")
    code = EXIT_OK if result["verdict"] == "PASS" else EXIT_FAILED
    if args.json:
        _emit(
            {"command": "verify", "exit_code": code, "status": "ok", **result},
            as_json=True,
            human="",
            error=code != EXIT_OK,
        )
    else:
        from mybench.verify.cli import render

        print(render(result))
    return code


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "init":
        return _init(args)
    if args.command == "scan":
        return _scan(args)
    if args.command == "report":
        return _report(args)
    if args.command == "capture":
        return _capture_enable(args)
    if args.command == "status":
        return _unavailable("status", as_json=args.json)
    if args.command == "publish":
        return _unavailable("publish --preview" if args.preview else "publish", as_json=args.json)
    return _verify(args)
