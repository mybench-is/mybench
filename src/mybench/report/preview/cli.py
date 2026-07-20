"""Deterministic, local-only publication-preview bundle (MYB-14.1).

The builder projects one immutable private report-v2 bundle into exactly four
candidate-publication files below that report's mode-0700 directory.  It has no
network, upload, hosted-id, publication-record, or publication-state path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TextIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mybench import paths
from mybench.claims import canonical_bytes, signed_bytes
from mybench.identity import (
    IdentityError,
    identity_id_for,
    load_local_identity_chain,
    local_identity_id,
    verify_record,
)
from mybench.leakscan import (
    CanaryLeakError,
    assert_no_canaries_in_directory,
    local_secret_corpus,
)
from mybench.registry import Registry
from mybench.report.cli import (
    BUNDLE_FILES,
    BundleError,
    _fsync_directory,
    _write_private,
    canonical_manifest_bytes,
    canonical_report_bytes,
    content_address,
    verify_signature,
)
from mybench.report.page import (
    PUBLIC_EXCLUSION_CATEGORIES,
    PageError,
    derive_public_projection,
    render_public_page,
)
from mybench.schemas import load_validator

PREVIEW_DIRECTORY = "publication-preview"
PREVIEW_FILES = (
    "index.html",
    "public-report.json",
    "public-report.sig",
    "redaction-manifest.json",
)
EXCLUSION_CATEGORIES = PUBLIC_EXCLUSION_CATEGORIES


class PreviewError(RuntimeError):
    """A publication preview could not be built without weakening its boundary."""


def _validate_schema(value: dict, schema_name: str, context: str) -> None:
    errors = sorted(load_validator(schema_name).iter_errors(value), key=str)
    if errors:
        # Candidate values can contain private source bytes. Validator messages
        # may quote them, so the public error is intentionally value-free.
        raise PreviewError(f"{context} violates its closed schema")


def derive_public_report(
    source_report: dict,
    *,
    registry: Registry | None = None,
    preset: str = "employer-safe",
) -> tuple[dict, dict]:
    """Return the closed public projection and its categorical manifest."""
    try:
        return derive_public_projection(source_report, registry=registry, preset=preset)
    except PageError as exc:
        raise PreviewError(str(exc)) from exc


def _public_key_hex(private_key: Ed25519PrivateKey) -> str:
    return (
        private_key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def _verify_identity_binding(
    identity_records: Sequence[dict], *, identity_id: str, device_pub: str
) -> None:
    if isinstance(identity_records, str | bytes | bytearray) or any(
        not isinstance(record, dict) for record in identity_records
    ):
        raise PreviewError("identity chain records must be a sequence of objects")
    try:
        if len(bytes.fromhex(identity_id)) != 32 or identity_id != identity_id.lower():
            raise ValueError
        if len(bytes.fromhex(device_pub)) != 32 or device_pub != device_pub.lower():
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise PreviewError("identity chain uses an invalid identifier or device key") from exc
    genesis_records = [
        record
        for record in identity_records
        if record.get("type") == "genesis" and record.get("identity_id") == identity_id
    ]
    if len(genesis_records) != 1:
        raise PreviewError("identity chain requires exactly one matching genesis record")
    genesis = genesis_records[0]
    try:
        verify_record(genesis, genesis["identity_pub"])
        if identity_id_for(bytes.fromhex(genesis["identity_pub"])) != identity_id:
            raise PreviewError("identity genesis does not self-certify its id")
        bindings = [
            record
            for record in identity_records
            if record.get("type") == "device-binding"
            and record.get("identity_id") == identity_id
            and record.get("device_pub") == device_pub
            and record.get("scope") in {"active", "retroactive"}
        ]
        if not bindings:
            raise PreviewError("preview signer is not bound to the claimed identity")
        for binding in bindings:
            verify_record(binding, genesis["identity_pub"])
    except (IdentityError, KeyError, TypeError, ValueError) as exc:
        raise PreviewError("identity chain verification failed") from exc


def _signature_envelope(
    artifacts: dict[str, bytes], *, private_key: Ed25519PrivateKey, identity_id: str
) -> dict:
    body = {
        "schema_version": "1",
        "identity_id": identity_id,
        "signer": {"kind": "device", "pub": _public_key_hex(private_key)},
        "artifacts": {
            name: hashlib.sha256(content).hexdigest() for name, content in sorted(artifacts.items())
        },
    }
    envelope = {**body, "signature": private_key.sign(signed_bytes(body)).hex()}
    _validate_schema(envelope, "public-report-signature.schema.json", "preview signature")
    return envelope


def _safe_source_directory(directory: Path) -> None:
    try:
        directory_info = directory.lstat()
        reports_root = paths.reports_dir().resolve(strict=True)
        candidate = directory.resolve(strict=True)
        paths.report_dir(directory.name)
    except (OSError, paths.PathsError) as exc:
        raise PreviewError("source is not an immutable local report directory") from exc
    if (
        not stat.S_ISDIR(directory_info.st_mode)
        or stat.S_ISLNK(directory_info.st_mode)
        or stat.S_IMODE(directory_info.st_mode) != 0o700
        or candidate != reports_root / directory.name
    ):
        raise PreviewError("source is not an immutable local report directory")
    names = {entry.name for entry in directory.iterdir()}
    allowed = {*BUNDLE_FILES, "assets", PREVIEW_DIRECTORY}
    if not names.issubset(allowed) or not {*BUNDLE_FILES, "assets"}.issubset(names):
        raise PreviewError("source report directory has an unexpected layout")
    assets = directory / "assets"
    assets_info = assets.lstat()
    if (
        not stat.S_ISDIR(assets_info.st_mode)
        or stat.S_ISLNK(assets_info.st_mode)
        or stat.S_IMODE(assets_info.st_mode) != 0o700
        or any(assets.iterdir())
    ):
        raise PreviewError("source report assets directory is invalid")
    for name in BUNDLE_FILES:
        info = (directory / name).lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise PreviewError("source report file permissions are invalid")


def _load_source_bundle(
    directory: Path, *, signing_key: Ed25519PrivateKey, registry: Registry
) -> tuple[dict, bytes, dict]:
    _safe_source_directory(directory)
    report_bytes = (directory / "report.json").read_bytes()
    if content_address(report_bytes) != directory.name:
        raise PreviewError("source report directory does not match its content address")
    try:
        report = json.loads(report_bytes)
        if canonical_report_bytes(report) != report_bytes:
            raise PreviewError("source report is not stored in canonical byte form")
        verify_signature(
            report_bytes,
            (directory / "report.sig").read_bytes(),
            signing_key.public_key(),
        )
        manifest_bytes = (directory / "evidence-manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        if canonical_manifest_bytes(manifest) != manifest_bytes:
            raise PreviewError("source evidence manifest is not canonical")
    except (BundleError, OSError, TypeError, ValueError) as exc:
        raise PreviewError("source local report bundle verification failed") from exc
    return report, manifest_bytes, manifest


def _manifest_secret_needles(manifest_bytes: bytes, manifest: dict) -> list[bytes]:
    needles = [manifest_bytes]
    values = [
        manifest.get("ledger", {}).get("chain_tip"),
        *manifest.get("corpora", {}).get("commitments", []),
    ]
    needles.extend(value.encode("ascii") for value in values if isinstance(value, str))
    return needles


def _deduplicate_canaries(canaries: Iterable[bytes]) -> list[bytes]:
    unique = []
    seen = set()
    for canary in canaries:
        if not isinstance(canary, bytes) or not canary:
            raise PreviewError("leak-gate corpus contains an invalid item")
        if canary not in seen:
            seen.add(canary)
            unique.append(canary)
    if not unique:
        raise PreviewError("empty secret corpus would make the leak gate vacuous")
    return unique


def _check_preview(directory: Path, artifacts: dict[str, bytes]) -> None:
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or {entry.name for entry in directory.iterdir()} != set(PREVIEW_FILES)
    ):
        raise PreviewError("existing publication preview has an unexpected layout")
    for name, content in artifacts.items():
        path = directory / name
        file_info = path.lstat()
        if (
            not stat.S_ISREG(file_info.st_mode)
            or stat.S_ISLNK(file_info.st_mode)
            or file_info.st_nlink != 1
            or stat.S_IMODE(file_info.st_mode) != 0o600
            or path.read_bytes() != content
        ):
            raise PreviewError("existing publication preview differs from requested bytes")


def _remove_staging(directory: Path) -> None:
    for name in PREVIEW_FILES:
        path = directory / name
        if path.exists():
            path.unlink()
    directory.rmdir()


def _print_listing(manifest: dict, stream: TextIO) -> None:
    stream.write("Publication preview is local only; no bytes were uploaded.\n")
    stream.write("WILL BE INCLUDED\n")
    included = manifest["field_selection"]["included"]
    if included:
        for registry_id in included:
            stream.write(f"  registry field: {registry_id}\n")
    else:
        stream.write("  no eligible fields present in this source report\n")
    stream.write("WILL NOT BE INCLUDED\n")
    for item in manifest["categories"]:
        stream.write(f"  category: {item['category']} ({item['status']})\n")
    for item in manifest["field_selection"]["excluded_from_source"]:
        stream.write(f"  registry field: {item['registry_id']} ({item['reason']})\n")
    for registry_id in manifest["field_selection"]["eligible_but_absent"]:
        stream.write(f"  registry field: {registry_id} (not present in source report)\n")
    stream.flush()


def build_publication_preview(
    report_directory: Path,
    *,
    registry: Registry | None = None,
    preset: str = "employer-safe",
    private_key: Ed25519PrivateKey | None = None,
    identity_id: str | None = None,
    identity_records: Sequence[dict] | None = None,
    extra_canaries: Sequence[bytes] = (),
    listing_stream: TextIO | None = None,
) -> Path:
    """Build or byte-verify one exact local publication-preview directory."""

    registry = registry or Registry.load()
    signing_key = private_key or paths.load_device_key()
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise PreviewError("preview signing requires an Ed25519 device key")
    if identity_records is not None and (
        isinstance(identity_records, str | bytes | bytearray)
        or any(not isinstance(record, dict) for record in identity_records)
    ):
        raise PreviewError("identity chain records must be a sequence of objects")
    if identity_records is None:
        try:
            local_id = local_identity_id()
            records = list(load_local_identity_chain())
        except IdentityError as exc:
            raise PreviewError("local identity state is invalid") from exc
        if identity_id is not None and identity_id != local_id:
            raise PreviewError("requested identity does not match local identity state")
        identity_id = local_id
    else:
        records = list(identity_records)
        if identity_id is None:
            genesis_ids = {
                record.get("identity_id") for record in records if record.get("type") == "genesis"
            }
            if len(genesis_ids) != 1:
                raise PreviewError("identity records do not name one identity")
            identity_id = genesis_ids.pop()
    _verify_identity_binding(
        records, identity_id=identity_id, device_pub=_public_key_hex(signing_key)
    )

    report, manifest_bytes, evidence_manifest = _load_source_bundle(
        Path(report_directory), signing_key=signing_key, registry=registry
    )
    public_report, redaction_manifest = derive_public_report(
        report, registry=registry, preset=preset
    )
    public_report_bytes = canonical_bytes(public_report)
    redaction_bytes = canonical_bytes(redaction_manifest)
    try:
        page_bytes = render_public_page(public_report, registry=registry)
    except PageError as exc:
        raise PreviewError("public report failed validate-then-render") from exc
    unsigned_artifacts = {
        "index.html": page_bytes,
        "public-report.json": public_report_bytes,
        "redaction-manifest.json": redaction_bytes,
    }
    signature = _signature_envelope(
        unsigned_artifacts, private_key=signing_key, identity_id=identity_id
    )
    artifacts = {
        **unsigned_artifacts,
        "public-report.sig": canonical_bytes(signature),
    }

    private_seed = signing_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    canaries = _deduplicate_canaries(
        [
            *local_secret_corpus(),
            private_seed,
            *_manifest_secret_needles(manifest_bytes, evidence_manifest),
            *extra_canaries,
        ]
    )
    destination = Path(report_directory) / PREVIEW_DIRECTORY
    if destination.is_symlink():
        raise PreviewError("publication preview path must not be a symlink")
    if destination.exists():
        _check_preview(destination, artifacts)
        try:
            assert_no_canaries_in_directory(destination, canaries)
        except (CanaryLeakError, ValueError) as exc:
            raise PreviewError("LEAK GATE FIRED; preview was not accepted") from exc
        _print_listing(redaction_manifest, listing_stream or sys.stdout)
        return destination

    staging = Path(tempfile.mkdtemp(prefix=".previewing-", dir=report_directory))
    os.chmod(staging, 0o700)
    try:
        for name, content in artifacts.items():
            _write_private(staging / name, content)
        _fsync_directory(staging)
        try:
            assert_no_canaries_in_directory(staging, canaries)
        except (CanaryLeakError, ValueError) as exc:
            raise PreviewError("LEAK GATE FIRED; preview was not finalized") from exc
        _print_listing(redaction_manifest, listing_stream or sys.stdout)
        staging.rename(destination)
        _fsync_directory(Path(report_directory))
    except Exception:
        if staging.exists():
            _remove_staging(staging)
        raise
    return destination


def verify_publication_preview(directory: Path, *, identity_records: Sequence[dict]) -> dict:
    """Verify exact preview bytes and bind the signer through an identity chain."""

    directory = Path(directory)
    try:
        if not directory.is_dir() or {entry.name for entry in directory.iterdir()} != set(
            PREVIEW_FILES
        ):
            raise PreviewError("publication preview has an unexpected layout")
        signature_bytes = (directory / "public-report.sig").read_bytes()
        envelope = json.loads(signature_bytes)
        if canonical_bytes(envelope) != signature_bytes:
            raise PreviewError("preview signature is not canonical")
        _validate_schema(envelope, "public-report-signature.schema.json", "preview signature")
        unsigned = {
            name: (directory / name).read_bytes()
            for name in PREVIEW_FILES
            if name != "public-report.sig"
        }
        expected_hashes = {
            name: hashlib.sha256(content).hexdigest() for name, content in sorted(unsigned.items())
        }
        if envelope["artifacts"] != expected_hashes:
            raise PreviewError("preview artifact bytes do not match the signature envelope")
        public_report = json.loads(unsigned["public-report.json"])
        if canonical_bytes(public_report) != unsigned["public-report.json"]:
            raise PreviewError("public report is not canonical")
        _validate_schema(public_report, "public-report.schema.json", "public report")
        redaction_manifest = json.loads(unsigned["redaction-manifest.json"])
        if canonical_bytes(redaction_manifest) != unsigned["redaction-manifest.json"]:
            raise PreviewError("redaction manifest is not canonical")
        _validate_schema(
            redaction_manifest,
            "redaction-manifest.schema.json",
            "redaction manifest",
        )
        if b"<script" in unsigned["index.html"].lower():
            raise PreviewError("publication preview HTML is not zero-JavaScript")
        _verify_identity_binding(
            identity_records,
            identity_id=envelope["identity_id"],
            device_pub=envelope["signer"]["pub"],
        )
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(envelope["signer"]["pub"]))
        public_key.verify(bytes.fromhex(envelope["signature"]), signed_bytes(envelope))
    except (InvalidSignature, KeyError, OSError, TypeError, ValueError) as exc:
        raise PreviewError("publication preview signature does not verify") from exc
    return {
        "identity_id": envelope["identity_id"],
        "device_pub": envelope["signer"]["pub"],
        "files": list(PREVIEW_FILES),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic local publication preview; never upload it."
    )
    parser.add_argument("report_id", help="existing local report content address")
    parser.add_argument(
        "--preset",
        choices=("employer-safe", "full"),
        default="employer-safe",
        help="registry publication preset (default: employer-safe)",
    )
    args = parser.parse_args(argv)
    try:
        directory = build_publication_preview(paths.report_dir(args.report_id), preset=args.preset)
    except (PreviewError, paths.PathsError) as exc:
        parser.error(str(exc))
    print(f"preview ready locally: reports/{args.report_id}/{directory.name}")
    return 0
