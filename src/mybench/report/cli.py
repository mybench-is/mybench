"""Stateful local report bundle assembly and viewing boundary (MYB-13.9).

The bundle is private A10 state.  It is assembled only below the mode-0700
mybench data directory and is never a publication or upload surface.
"""

from __future__ import annotations

import hashlib
import functools
import http.server
import json
import os
import stat
import tempfile
import webbrowser
from collections.abc import Iterable, Sequence
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mybench import paths
from mybench.claims.canonical import canonical_bytes
from mybench.report.page import render_page
from mybench.schemas import load_validator

REPORT_ID_DOMAIN = b"mybench:v1:local-report-id\x00"
BUNDLE_FILES = ("index.html", "report.json", "report.sig", "evidence-manifest.json")


class BundleError(RuntimeError):
    """A local report could not be assembled without weakening its invariants."""


def canonical_report_bytes(report: dict) -> bytes:
    """Validate and serialize a report into the exact bytes signed and stored.

    Schema v1 contains finite decimal ratios, so it cannot use the claims
    module's no-float check.  It otherwise uses the same sorted, compact,
    ASCII-safe JSON convention and rejects NaN/infinity.
    """
    if not isinstance(report, dict):
        raise BundleError("report must be a JSON object")
    schema_version = report.get("schema_version")
    schema_name = {"1": "report.schema.json", "2": "report-v2.schema.json"}.get(
        schema_version
    )
    if schema_name is None:
        raise BundleError("unsupported report schema version")
    errors = sorted(load_validator(schema_name).iter_errors(report), key=str)
    if errors:
        raise BundleError(f"report failed schema validation: {errors[0].message}")
    try:
        return json.dumps(
            report,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BundleError("report is not canonical-JSON-safe") from exc


def content_address(report_bytes: bytes) -> str:
    """Return the stable report id for canonical ``report.json`` bytes."""
    if not isinstance(report_bytes, bytes):
        raise BundleError("report bytes must be bytes")
    return hashlib.sha256(REPORT_ID_DOMAIN + report_bytes).hexdigest()


def validate_evidence_manifest(manifest: dict) -> None:
    """Enforce the closed local-only evidence reference schema."""
    errors = sorted(
        load_validator("evidence-manifest.schema.json").iter_errors(manifest), key=str
    )
    if errors:
        raise BundleError(f"evidence manifest failed schema validation: {errors[0].message}")
    for row_range in manifest["ledger"]["row_ranges"]:
        if row_range["end"] <= row_range["start"]:
            raise BundleError("evidence manifest ledger ranges must be non-empty")


def canonical_manifest_bytes(manifest: dict) -> bytes:
    validate_evidence_manifest(manifest)
    return canonical_bytes(manifest)


def _report_fields(report: dict) -> Iterable[dict]:
    for field in report.get("catalog_metrics", ()):
        yield field
    for section in report.get("fingerprint", {}).values():
        yield from section.get("fields", ())


def evidence_manifest(
    report: dict,
    rows: Sequence[dict],
    anchor_dates: Sequence[str],
) -> dict:
    """Derive only whitelisted commitments and references from scorer inputs."""
    row_ranges = []
    ledger: dict[str, object] = {"row_ranges": row_ranges}
    if rows:
        indexes = [row["i"] for row in rows]
        if indexes != list(range(indexes[0], indexes[-1] + 1)):
            raise BundleError("ledger references are not one contiguous range")
        row_ranges.append({"start": indexes[0], "end": indexes[-1] + 1})
        ledger["chain_tip"] = rows[-1]["h"]

    input_versions = report.get("input_schema_versions", {})
    fields = list(_report_fields(report))
    formulas = sorted(
        {
            (field["registry_id"], field["registry_version"])
            for field in fields
            if "registry_id" in field and "registry_version" in field
        }
    )
    versions: dict[str, object] = {
        "scorer": report["scorer_version"],
        "classifiers": sorted(input_versions.get("phase_classifier", ())),
        "schemas": {
            "report": report["schema_version"],
            "ledger": sorted(input_versions.get("ledger", ())),
            "anchor": sorted(input_versions.get("anchor", ())),
            "normalized_events": sorted(input_versions.get("normalized_events", ())),
            "evidence_manifest": "1",
        },
        "formulas": [
            {"registry_id": registry_id, "registry_version": registry_version}
            for registry_id, registry_version in formulas
        ],
    }
    if "registry" in report:
        versions["registry"] = dict(report["registry"])
    if "pricing_snapshot" in report:
        versions["pricing"] = {
            "version": report["pricing_snapshot"]["version"],
            "digest": report["pricing_snapshot"]["digest"],
        }
    manifest = {
        "schema_version": "1",
        "ledger": ledger,
        "anchors": {"event_dates": sorted(set(anchor_dates))},
        "corpora": {
            "commitments": sorted(
                {row["session_root"] for row in rows if "session_root" in row}
            )
        },
        "claims": {
            "digests": sorted(
                {field["claim_digest"] for field in fields if "claim_digest" in field}
            )
        },
        "versions": versions,
    }
    validate_evidence_manifest(manifest)
    return manifest


def local_evidence_manifest(report: dict) -> dict:
    """Gather the same private ledger/anchor reference classes used by scoring."""
    from mybench.ledger import Ledger
    from mybench.scorer.__main__ import _anchor_events

    ledger = Ledger()
    ledger.verify_chain()
    return evidence_manifest(report, ledger.rows(), [event["date"] for event in _anchor_events()])


def signature_bytes(report_bytes: bytes, private_key: Ed25519PrivateKey) -> bytes:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise BundleError("report signing requires an Ed25519 private key")
    return private_key.sign(report_bytes).hex().encode("ascii") + b"\n"


def verify_signature(
    report_bytes: bytes, encoded_signature: bytes, public_key: Ed25519PublicKey
) -> None:
    """Raise :class:`BundleError` unless ``report.sig`` covers exact report bytes."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise BundleError("report verification requires an Ed25519 public key")
    try:
        signature = bytes.fromhex(encoded_signature.decode("ascii").strip())
        if len(signature) != 64:
            raise ValueError
        public_key.verify(signature, report_bytes)
    except (InvalidSignature, UnicodeDecodeError, ValueError) as exc:
        raise BundleError("report signature does not verify") from exc


def _write_private(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise BundleError("local report storage refused")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _check_file(path: Path, content: bytes) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or path.read_bytes() != content
    ):
        raise BundleError("immutable local report bundle differs from requested bytes")


def _check_existing(directory: Path, artifacts: dict[str, bytes]) -> None:
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise BundleError("local report bundle directory is not private")
    names = {entry.name for entry in directory.iterdir()}
    if names != {*BUNDLE_FILES, "assets"}:
        raise BundleError("immutable local report bundle has an unexpected layout")
    assets = directory / "assets"
    asset_info = assets.lstat()
    if (
        not stat.S_ISDIR(asset_info.st_mode)
        or stat.S_IMODE(asset_info.st_mode) != 0o700
        or any(assets.iterdir())
    ):
        raise BundleError("local report assets directory is not the empty v0 asset set")
    for name, content in artifacts.items():
        _check_file(directory / name, content)


def _remove_staging(directory: Path) -> None:
    for name in BUNDLE_FILES:
        candidate = directory / name
        if candidate.exists():
            candidate.unlink()
    assets = directory / "assets"
    if assets.exists():
        assets.rmdir()
    directory.rmdir()


def assemble_bundle(
    report: dict,
    manifest: dict,
    *,
    private_key: Ed25519PrivateKey | None = None,
    bundle_dir: Path | None = None,
    anchors_url: str = "https://mybench.is/anchors",
    handle: str | None = None,
) -> Path:
    """Build or byte-verify one immutable bundle below the private data dir."""
    report_bytes = canonical_report_bytes(report)
    if report.get("schema_version") != "1":
        raise BundleError("the v0 bundle renderer currently accepts report schema 1")
    manifest_bytes = canonical_manifest_bytes(manifest)
    page_bytes = render_page(
        report,
        anchors_url=anchors_url,
        handle=handle,
        report_json_href="report.json",
    )
    report_id = content_address(report_bytes)
    expected = paths.report_dir(report_id).absolute()
    directory = (bundle_dir or expected).absolute()
    data_root = paths.data_dir().resolve(strict=False)
    try:
        directory.resolve(strict=False).relative_to(data_root)
    except ValueError as exc:
        raise BundleError("report bundle path is outside the private data directory") from exc
    if directory != expected:
        raise BundleError("report bundle path must match its content address")
    if directory.is_symlink():
        raise BundleError("report bundle path must not be a symlink")

    signing_key = private_key or paths.load_device_key()
    artifacts = {
        "index.html": page_bytes,
        "report.json": report_bytes,
        "report.sig": signature_bytes(report_bytes, signing_key),
        "evidence-manifest.json": manifest_bytes,
    }
    reports_root = paths.ensure_reports_dir()
    if directory.exists():
        _check_existing(directory, artifacts)
        return directory

    staging = Path(tempfile.mkdtemp(prefix=".assembling-", dir=reports_root))
    os.chmod(staging, 0o700)
    try:
        (staging / "assets").mkdir(mode=0o700)
        for name, content in artifacts.items():
            _write_private(staging / name, content)
        _fsync_directory(staging)
        try:
            staging.rename(directory)
            _fsync_directory(reports_root)
        except OSError:
            if not directory.exists():
                raise
            _check_existing(directory, artifacts)
            _remove_staging(staging)
    except Exception:
        if staging.exists():
            _remove_staging(staging)
        raise
    return directory


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *args: object) -> None:
        """Do not put private local paths or request details into logs."""


def _validated_bundle(directory: Path) -> Path:
    try:
        candidate = directory.resolve(strict=True)
        expected = paths.report_dir(candidate.name).resolve(strict=True)
    except (OSError, paths.PathsError) as exc:
        raise BundleError("refusing to view an invalid private report bundle") from exc
    if candidate != expected or not (candidate / "index.html").is_file():
        raise BundleError("refusing to view a path outside the private reports directory")
    return candidate


def create_server(directory: Path, *, port: int = 0) -> http.server.ThreadingHTTPServer:
    """Create an IPv4 server whose bind host is structurally fixed to loopback."""
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise BundleError("serve port must be an integer from 0 through 65535")
    bundle = _validated_bundle(directory)
    handler = functools.partial(_QuietHandler, directory=str(bundle))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    return server


def report_url(server: http.server.ThreadingHTTPServer) -> str:
    host, port = server.server_address[:2]
    if host != "127.0.0.1":
        raise BundleError("report server is not bound to IPv4 loopback")
    return f"http://127.0.0.1:{port}/index.html"


def open_report(location: Path | str) -> bool:
    """Best-effort browser opening; headless failures never fail bundle creation."""
    try:
        target = location.resolve(strict=True).as_uri() if isinstance(location, Path) else location
        return bool(webbrowser.open(target, new=2))
    except Exception:  # noqa: BLE001 - browser discovery is intentionally best-effort
        return False
