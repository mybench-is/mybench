"""MYB-14.1 publication preview: projection, signing, exact leak gate, no egress."""

from __future__ import annotations

import base64
import copy
import gzip
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mybench import cli, identity, nonces, paths
from mybench.identity import identity_id_for
from mybench.report.cli import assemble_bundle, canonical_manifest_bytes, evidence_manifest
from mybench.report.page import PageError, render_public_page
from mybench.report.preview import (
    EXCLUSION_CATEGORIES,
    PREVIEW_FILES,
    PreviewError,
    build_publication_preview,
    derive_public_report,
    verify_publication_preview,
)
from mybench.report.preview.cli import main as preview_main
from mybench.schemas import load_validator
from tests.fixtures import assert_no_canaries_in_directory
from tests.report.test_bundle import _token_cost_report_claims
from tests.report.test_page import v2_claims, v2_report

DEVICE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
IDENTITY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))


def _raw_pub(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _identity_signed(body: dict) -> dict:
    signature = IDENTITY_KEY.sign(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hex()
    return {**body, "sig": signature}


def _identity_records() -> tuple[str, list[dict]]:
    identity_pub = _raw_pub(IDENTITY_KEY)
    identity_id = identity_id_for(identity_pub)
    records = [
        _identity_signed(
            {
                "schema_version": "1",
                "type": "genesis",
                "identity_id": identity_id,
                "identity_pub": identity_pub.hex(),
                "date": "2026-07-19",
            }
        ),
        _identity_signed(
            {
                "schema_version": "1",
                "type": "device-binding",
                "identity_id": identity_id,
                "device_pub": _raw_pub(DEVICE_KEY).hex(),
                "scope": "active",
                "date": "2026-07-19",
            }
        ),
    ]
    return identity_id, records


def _source_bundle(*, token_cost: bool = False) -> Path:
    if token_cost:
        report, claims = _token_cost_report_claims()
    else:
        report, claims = v2_report(), v2_claims()
    return assemble_bundle(
        report,
        evidence_manifest(report, [], []),
        private_key=DEVICE_KEY,
        signed_claims=claims,
    )


def _build(source: Path, **kwargs) -> Path:
    identity_id, records = _identity_records()
    return build_publication_preview(
        source,
        preset="full",
        private_key=DEVICE_KEY,
        identity_id=identity_id,
        identity_records=records,
        listing_stream=io.StringIO(),
        **kwargs,
    )


def _bytes(directory: Path) -> dict[str, bytes]:
    return {name: (directory / name).read_bytes() for name in PREVIEW_FILES}


def test_two_runs_are_byte_identical_and_every_tampered_file_fails_identity_chain_verification():
    source = _source_bundle()
    identity_id, records = _identity_records()
    first = _build(source)
    first_bytes = _bytes(first)
    result = verify_publication_preview(first, identity_records=records)
    assert result["identity_id"] == identity_id
    assert result["device_pub"] == _raw_pub(DEVICE_KEY).hex()
    assert result["files"] == list(PREVIEW_FILES)

    public_report = json.loads(first_bytes["public-report.json"])
    assert "generated_at" not in public_report
    assert "metrics" not in public_report
    assert "binding_tips" not in public_report
    assert public_report["evidence_period"] == {
        "start_week": "2026-W27",
        "end_week": "2026-W29",
    }
    assert b"<script" not in first_bytes["index.html"].lower()
    assert b"2026-07-18T00:00:00Z" not in b"".join(first_bytes.values())

    shutil.rmtree(first)
    second = _build(source)
    assert _bytes(second) == first_bytes

    for name, original in first_bytes.items():
        target = second / name
        target.write_bytes(original + b" ")
        with pytest.raises(PreviewError, match="verify|match|canonical"):
            verify_publication_preview(second, identity_records=records)
        target.write_bytes(original)
    verify_publication_preview(second, identity_records=records)


def test_manifest_has_exact_eleven_categories_and_listing_precedes_finalization(monkeypatch):
    source = _source_bundle()
    identity_id, records = _identity_records()
    listing = io.StringIO()
    original_rename = Path.rename

    def checked_rename(path, target):
        if path.name.startswith(".previewing-"):
            text = listing.getvalue()
            assert "WILL BE INCLUDED" in text
            assert "WILL NOT BE INCLUDED" in text
            assert all(category in text for category in EXCLUSION_CATEGORIES)
        return original_rename(path, target)

    monkeypatch.setattr(Path, "rename", checked_rename)
    preview = build_publication_preview(
        source,
        preset="full",
        private_key=DEVICE_KEY,
        identity_id=identity_id,
        identity_records=records,
        listing_stream=listing,
    )
    manifest = json.loads((preview / "redaction-manifest.json").read_bytes())
    assert manifest["categories"] == [
        {"category": category, "status": "excluded"} for category in EXCLUSION_CATEGORIES
    ]
    assert manifest["field_selection"]["included"] == ["transcript.agent_hours"]
    assert not list(load_validator("redaction-manifest.schema.json").iter_errors(manifest))

    poisoned = copy.deepcopy(manifest)
    poisoned["categories"][0]["toggle"] = True
    assert list(load_validator("redaction-manifest.schema.json").iter_errors(poisoned))


def test_public_projection_excludes_local_fields_and_renderer_rejects_preset_escape():
    source = _source_bundle(token_cost=True)
    preview = _build(source)
    public_report = json.loads((preview / "public-report.json").read_bytes())
    ids = {
        field["registry_id"]
        for section in public_report["fingerprint"].values()
        for field in section["fields"]
    }
    assert "fingerprint.token_cost.cost_by_model.exact" not in ids
    assert "fingerprint.token_cost.cost_per_episode.exact" not in ids
    assert ids
    assert all(
        field["disclosure"] == "PUBLISHABLE"
        for section in public_report["fingerprint"].values()
        for field in section["fields"]
    )

    poisoned = copy.deepcopy(public_report)
    field = next(
        field for section in poisoned["fingerprint"].values() for field in section["fields"]
    )
    field["disclosure"] = "LOCAL_ONLY"
    with pytest.raises(PageError, match="non-conforming public report"):
        render_public_page(poisoned)


def test_unknown_source_field_fails_before_public_projection_or_render(monkeypatch):
    report = v2_report()
    marker = "MYBENCH-CANARY-synthetic-prompt-unknown-field"
    report["prompt"] = marker
    rendered = []
    monkeypatch.setattr(
        "mybench.report.preview.cli.render_public_page",
        lambda *_args, **_kwargs: rendered.append(True) or b"forbidden",
    )
    with pytest.raises(PreviewError, match="closed schema") as raised:
        derive_public_report(report, preset="full")
    assert marker not in str(raised.value)
    assert rendered == []


CANARY_CLASSES = {
    "transcript-content": b"MYBENCH-CANARY-synthetic-transcript-content-14-1",
    "repository-name": b"MYBENCH-CANARY-synthetic-repository-name-14-1",
    "filename": b"MYBENCH-CANARY-synthetic-filename-14-1.jsonl",
    "local-path": b"/synthetic/private/path/MYBENCH-CANARY-14-1",
    "nonce": bytes(range(0x40, 0x60)),
    "key-material": bytes(range(0x80, 0xA0)),
}

ENCODERS = (
    pytest.param(lambda value: value, id="raw"),
    pytest.param(lambda value: value.hex().encode(), id="hex"),
    pytest.param(lambda value: value.hex().upper().encode(), id="HEX"),
    pytest.param(lambda value: base64.b64encode(value), id="base64"),
    pytest.param(lambda value: base64.b64encode(b"x" + value), id="base64-phase-1"),
    pytest.param(lambda value: gzip.compress(value, mtime=0), id="gzip-raw"),
    pytest.param(lambda value: gzip.compress(value.hex().encode(), mtime=0), id="gzip-hex"),
)


@pytest.mark.parametrize("class_name", CANARY_CLASSES)
@pytest.mark.parametrize("encode", ENCODERS)
def test_exact_staged_byte_gate_fires_for_every_canary_class_and_encoding(
    class_name, encode, monkeypatch
):
    source = _source_bundle()
    canary = CANARY_CLASSES[class_name]
    planted = b"synthetic header " + encode(canary) + b" synthetic trailer"
    monkeypatch.setattr("mybench.report.preview.cli.render_public_page", lambda *_a, **_k: planted)
    with pytest.raises(PreviewError, match="LEAK GATE FIRED") as raised:
        _build(source, extra_canaries=[canary])
    readable_prefix = canary[:12].decode("ascii", errors="ignore")
    if readable_prefix:
        assert readable_prefix not in str(raised.value)
    assert not (source / "publication-preview").exists()
    assert not list(source.glob(".previewing-*"))


def test_nonce_private_key_and_evidence_manifest_bytes_never_enter_preview():
    source = _source_bundle()
    nonce = bytes(range(0xA0, 0xC0))
    private_marker = bytes(range(0xC0, 0xE0))
    evidence_marker = "a7" * 32
    nonces.append_nonce("synthetic-preview", nonce)
    key_path = paths.keys_dir() / "synthetic-preview.key"
    key_path.write_bytes(private_marker)
    key_path.chmod(0o600)

    manifest_path = source / "evidence-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["corpora"]["commitments"] = [evidence_marker]
    manifest_path.write_bytes(canonical_manifest_bytes(manifest))

    listing = io.StringIO()
    identity_id, records = _identity_records()
    preview = build_publication_preview(
        source,
        preset="full",
        private_key=DEVICE_KEY,
        identity_id=identity_id,
        identity_records=records,
        listing_stream=listing,
    )
    assert assert_no_canaries_in_directory(
        preview, [nonce, private_marker, evidence_marker.encode()]
    ) == len(PREVIEW_FILES)
    assert assert_no_canaries_in_directory(preview, [canonical_manifest_bytes(manifest)]) == len(
        PREVIEW_FILES
    )
    assert all(
        marker not in listing.getvalue()
        for marker in (evidence_marker, nonce.hex(), private_marker.hex())
    )


def test_preview_writes_only_four_private_files_below_data_dir_and_never_networks(
    tmp_path, monkeypatch
):
    source = _source_bundle()

    def forbidden_network(*_args, **_kwargs):
        raise AssertionError("publication preview attempted network access")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden_network)
    preview = _build(source)
    assert preview == source / "publication-preview"
    assert preview.resolve().is_relative_to(paths.data_dir().resolve())
    assert {entry.name for entry in preview.iterdir()} == set(PREVIEW_FILES)
    assert stat.S_IMODE(preview.stat().st_mode) == 0o700
    assert all(stat.S_IMODE((preview / name).stat().st_mode) == 0o600 for name in PREVIEW_FILES)
    assert not (tmp_path / "home").exists()
    assert not (tmp_path / "xdg-config").exists()
    assert not any(name in os.environ for name in ("MYBENCH_UPLOAD_URL", "MYBENCH_HOSTED_ID"))


def test_signature_rejects_unbound_device_even_when_cryptographically_valid():
    source = _source_bundle()
    preview = _build(source)
    identity_id, records = _identity_records()
    forged_device = Ed25519PrivateKey.from_private_bytes(b"z" * 32)
    forged_records = [records[0], copy.deepcopy(records[1])]
    forged_records[1]["device_pub"] = _raw_pub(forged_device).hex()
    forged_records[1].pop("sig")
    forged_records[1] = _identity_signed(forged_records[1])
    assert forged_records[0]["identity_id"] == identity_id
    with pytest.raises(PreviewError, match="not bound"):
        verify_publication_preview(preview, identity_records=forged_records)


def test_fresh_init_report_v2_to_preview_cli_uses_canonical_local_chain_without_git_or_network(
    capsys, monkeypatch
):
    external_calls = []

    def forbidden_external(*args, **kwargs):
        external_calls.append((args, kwargs))
        raise AssertionError("local init-to-preview flow attempted an external operation")

    monkeypatch.setattr(socket.socket, "connect", forbidden_external)
    monkeypatch.setattr(subprocess, "run", forbidden_external)

    assert cli.main(["init", "--local-first", "--json"]) == 0
    init_result = json.loads(capsys.readouterr().out)
    assert init_result["identity_ready"] is True
    assert init_result["local_only"] is True
    assert init_result["registered"] is False
    assert init_result["published"] is False

    report = v2_report()
    source = assemble_bundle(
        report,
        evidence_manifest(report, [], []),
        signed_claims=v2_claims(),
    )
    assert preview_main([source.name, "--preset", "full"]) == 0
    output = capsys.readouterr()
    assert "Publication preview is local only; no bytes were uploaded." in output.out
    preview = source / "publication-preview"
    result = verify_publication_preview(
        preview,
        identity_records=identity.load_local_identity_chain(),
    )
    assert result["files"] == list(PREVIEW_FILES)
    assert external_calls == []


@pytest.mark.parametrize("state", ("malformed", "unbound"))
def test_canonical_local_identity_failure_prevents_preview_finalization(state, capsys):
    assert cli.main(["init", "--json"]) == 0
    capsys.readouterr()
    report = v2_report()
    source = assemble_bundle(
        report,
        evidence_manifest(report, [], []),
        signed_claims=v2_claims(),
    )
    identity_directory = paths.identity_record_dir(identity.local_identity_id())
    genesis_path = identity_directory / "genesis.json"
    if state == "malformed":
        genesis_path.write_bytes(b"{}\n")
        genesis_path.chmod(0o600)
    else:
        bound_path = next(identity_directory.glob("device-*.json"))
        bound_path.unlink()
        other_device = Ed25519PrivateKey.from_private_bytes(b"u" * 32)
        other_pub = _raw_pub(other_device).hex()
        genesis = json.loads(genesis_path.read_bytes())
        record = identity.device_binding_record(other_pub, genesis["date"])
        replacement = identity_directory / f"device-{other_pub[:8]}.json"
        replacement.write_bytes(identity.record_bytes(record))
        replacement.chmod(0o600)

    with pytest.raises(PreviewError, match="local identity state is invalid"):
        build_publication_preview(source, preset="full", listing_stream=io.StringIO())
    assert not (source / "publication-preview").exists()
    assert not list(source.glob(".previewing-*"))
