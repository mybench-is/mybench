"""Trusted A2/A3/A9 loader and aggregate-only supervised CLI."""

from __future__ import annotations

import json
import os

import pytest

from mybench import paths
from mybench.daemon.capture import Daemon, DaemonConfig, WatchSpec
from mybench.normalizer import normalize_claude, validate_corpus_artifact
from mybench.normalizer import loader
from mybench.normalizer.__main__ import main

CANARY = "MYBENCH-OWNER-LOADER-CONTENT-CANARY-41ad"
PATH_CANARY = "/synthetic/private/MYBENCH-OWNER-LOADER-PATH-CANARY-92c0"


@pytest.fixture
def captured_archive(tmp_path):
    watch_dir = tmp_path / "fixture-watch"
    watch_dir.mkdir()
    records = [
        {
            "cwd": PATH_CANARY,
            "message": {"role": "user", "content": CANARY},
            "parentUuid": None,
            "sessionId": "synthetic-raw-session",
            "timestamp": "2026-01-01T00:00:00.000Z",
            "type": "user",
            "uuid": "synthetic-uuid-0",
        },
        {
            "parentUuid": "synthetic-uuid-0",
            "sessionId": "synthetic-raw-session",
            "subtype": "compact_boundary",
            "timestamp": "2026-01-01T00:00:01.000Z",
            "type": "system",
            "uuid": "synthetic-uuid-1",
        },
        {
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": CANARY}],
            },
            "parentUuid": "synthetic-uuid-1",
            "sessionId": "synthetic-raw-session",
            "timestamp": "2026-01-01T00:00:02.000Z",
            "type": "assistant",
            "uuid": "synthetic-uuid-2",
        },
    ]
    session = watch_dir / "synthetic.jsonl"
    session.write_bytes(
        b"".join(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            for value in records
        )
    )
    config = DaemonConfig(
        watches=(WatchSpec(watch_dir, "claude-code"),), archive_enabled=True
    )
    assert Daemon(config).scan_once() == 1
    return session


def test_loader_requires_explicit_owner_confirmation(captured_archive):
    with pytest.raises(loader.NormalizerLoaderError, match="owner subject confirmation"):
        loader.load_owner_claude_sessions(confirm_subject_owned=False)


def test_loader_authenticates_archive_and_observes_context_boundary(captured_archive):
    sessions = loader.load_owner_claude_sessions(confirm_subject_owned=True)
    assert len(sessions) == 1
    assert sessions[0].subject_owned is True
    assert [record.attribution for record in sessions[0].records] == ["subject"] * 3
    assert [record.context_generation_id for record in sessions[0].records] == [None, 1, None]

    artifact = normalize_claude(sessions)
    assert validate_corpus_artifact(artifact) == json.loads(artifact)["corpus_commitment"]
    assert CANARY.encode() not in artifact
    assert PATH_CANARY.encode() not in artifact


def test_loader_refuses_a_missing_archive_without_exposing_private_fields(captured_archive):
    archive_file = next(paths.archive_source_dir("claude-code").iterdir())
    private_name = archive_file.name
    archive_file.unlink()
    with pytest.raises(loader.NormalizerLoaderError) as exc:
        loader.load_owner_claude_sessions(confirm_subject_owned=True)
    assert str(exc.value) == "owner corpus loading failed"
    assert private_name not in str(exc.value)
    assert str(paths.data_dir()) not in str(exc.value)


def test_loader_refuses_hardlinked_archive(captured_archive, tmp_path):
    archive_file = next(paths.archive_source_dir("claude-code").iterdir())
    os.link(archive_file, tmp_path / "synthetic-hardlink")
    with pytest.raises(loader.NormalizerLoaderError, match="owner corpus loading failed"):
        loader.load_owner_claude_sessions(confirm_subject_owned=True)


def test_supervised_cli_prints_aggregates_and_stores_content_opaque_artifact(
    captured_archive, capsys
):
    assert main(["--owner-dogfood", "--confirm-subject-owned"]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert "normalization=pass source=claude-code store=pass" in output.out
    assert "sessions_admitted=1 records_seen=3 records_parsed=3" in output.out
    assert "corpus_commitment=" in output.out
    assert "artifact_sha256=" in output.out
    assert CANARY not in output.out
    assert PATH_CANARY not in output.out
    assert str(paths.data_dir()) not in output.out
    artifacts = list(paths.normalized_dir().glob("*/corpus.json"))
    assert len(artifacts) == 1
    assert CANARY.encode() not in artifacts[0].read_bytes()
    assert PATH_CANARY.encode() not in artifacts[0].read_bytes()


def test_supervised_cli_failure_reports_type_only(captured_archive, capsys, monkeypatch):
    def fail(**_kwargs):
        raise RuntimeError(f"private {PATH_CANARY} {CANARY}")

    monkeypatch.setattr(
        "mybench.normalizer.__main__.load_owner_claude_sessions", fail
    )
    assert main(["--owner-dogfood", "--confirm-subject-owned"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "normalization=fail type=RuntimeError\n"
    assert PATH_CANARY not in output.err
    assert CANARY not in output.err
