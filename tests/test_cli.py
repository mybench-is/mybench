"""MYB-11.2 unified CLI: synthetic E2E, privacy, and honest boundaries."""

from __future__ import annotations

import json
import logging
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from mybench import cli, nonces, paths
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

ROOT = Path(__file__).parents[1]


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def test_init_scan_report_synthetic_e2e_is_deterministic_and_leak_free(
    tmp_path, capsys, caplog, monkeypatch
):
    fx = generate_fixtures(tmp_path / "synthetic-fixtures")
    synthetic_repo = tmp_path / "synthetic-repo"
    synthetic_repo.mkdir()
    caplog.set_level(logging.INFO, logger="mybench.daemon")

    def forbidden_upgrade():
        raise AssertionError("plain scan must not enter the network-capable upgrade path")

    monkeypatch.setattr(cli, "_upgrade_proofs", forbidden_upgrade)

    assert cli.main(["init", "--local-first", "--json"]) == 0
    init_output = capsys.readouterr()
    assert json.loads(init_output.out) == {"command": "init", "keys_ready": 4, "status": "ok"}
    for directory in (paths.data_dir(), paths.reports_dir()):
        assert _mode(directory) == 0o700
    for key in (
        paths.session_scope_key_path(),
        paths.device_key_path(),
        paths.identity_key_path(),
        paths.commit_signing_key_path(),
    ):
        assert _mode(key) == 0o600

    scan_args = [
        "scan",
        "--watch",
        f"{fx.root / 'claude' / 'projects'}:claude-code",
        "--watch",
        f"{fx.root / 'codex' / 'sessions'}:codex",
        "--repo",
        str(synthetic_repo),
        "--json",
    ]
    assert cli.main(scan_args) == 0
    scan_output = capsys.readouterr()
    scan_summary = json.loads(scan_output.out)
    assert scan_summary == {
        "bindings_appended": 0,
        "command": "scan",
        "proofs_confirmed": 0,
        "proofs_staged": 0,
        "rows_appended": 3,
        "status": "ok",
        "upgrade_requested": False,
        "watches": 2,
    }

    report_args = [
        "report",
        "--format",
        "html,json",
        "--generated-at",
        "2026-01-08T12:34:56Z",
        "--json",
    ]
    assert cli.main(report_args) == 0
    first_report_output = capsys.readouterr()
    first_summary = json.loads(first_report_output.out)
    report_dir = paths.report_dir(first_summary["report_id"])
    artifacts = (report_dir / "report.json", report_dir / "index.html")
    first_bytes = tuple(path.read_bytes() for path in artifacts)
    assert first_summary == {
        "command": "report",
        "formats": ["html", "json"],
        "report_id": report_dir.name,
        "status": "ok",
    }
    assert all(_mode(path) == 0o600 for path in artifacts)

    assert cli.main(report_args) == 0
    second_report_output = capsys.readouterr()
    second_summary = json.loads(second_report_output.out)
    assert second_summary == first_summary
    assert tuple(path.read_bytes() for path in artifacts) == first_bytes

    used_nonces = [
        nonce
        for nonce_file in paths.nonces_dir().glob("*.jsonl")
        for nonce in nonces.load_nonces(nonce_file.stem)
    ]
    assert used_nonces
    canaries = fx.all_canaries() + used_nonces + [str(fx.root).encode()]
    cli_surface = tmp_path / "cli-surface.log"
    cli_surface.write_text(
        init_output.out
        + init_output.err
        + scan_output.out
        + scan_output.err
        + first_report_output.out
        + first_report_output.err
        + second_report_output.out
        + second_report_output.err
        + caplog.text
    )
    assert assert_no_canaries([*artifacts, cli_surface], canaries) == 3

    planted = tmp_path / "planted-cli-output.log"
    planted.write_text(fx.content_canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], canaries)


def test_capture_enable_is_explicit_idempotent_and_counts_only(tmp_path, capsys):
    repo = tmp_path / "CANARY-private-repo-path"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Synthetic Test")
    _git(repo, "config", "user.email", "synthetic@example.invalid")
    (repo / "README.md").write_text("synthetic\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "synthetic root")

    command = ["capture", "enable", "--repo", str(repo), "--json"]
    assert cli.main(command) == 0
    first = capsys.readouterr()
    assert json.loads(first.out) == {
        "command": "capture enable",
        "repos_enrolled": 1,
        "status": "ok",
    }
    assert str(repo) not in first.out + first.err
    hook = repo / ".git" / "hooks" / "post-commit"
    marker = repo / ".mybench" / "commit-binding-enabled"
    assert hook.is_file() and marker.is_file()
    assert len(list(paths.enrollments_dir().glob("*.json"))) == 1

    assert cli.main(command) == 0
    second = capsys.readouterr()
    assert json.loads(second.out)["repos_enrolled"] == 1
    assert len(list(paths.enrollments_dir().glob("*.json"))) == 1
    assert not any("scheduler" in path.name for path in paths.data_dir().rglob("*"))


def test_reserved_surfaces_are_side_effect_free_and_publish_never_networks(capsys, monkeypatch):
    network_calls = []

    def attempted_network(*args, **kwargs):
        network_calls.append((args, kwargs))
        raise AssertionError("reserved commands must not use the network")

    monkeypatch.setattr(socket.socket, "connect", attempted_network)
    commands = (
        (["publish", "--json"], "publish", True),
        (["publish", "--preview", "--json"], "publish --preview", True),
        (["status", "--json"], "status", False),
        (["init", "--detect", "--json"], "init --detect", False),
        (["report", "--open", "--json"], "report --open", False),
        (["report", "--serve", "--json"], "report --serve", False),
    )
    for argv, command, publication in commands:
        assert cli.main(argv) == 3
        output = capsys.readouterr()
        assert output.out == ""
        payload = json.loads(output.err)
        expected = {
            "command": command,
            "error": "not_yet_available",
            "exit_code": 3,
            "status": "unavailable",
        }
        if publication:
            expected["published"] = False
        assert payload == expected
    assert cli.main(["publish"]) == 3
    human = capsys.readouterr()
    assert "not yet available; nothing published" in human.err
    assert network_calls == []
    assert not paths.data_dir().exists()


@pytest.mark.parametrize(
    "module",
    ("daemon", "hooks", "anchor", "scorer", "report", "verify", "normalizer"),
)
def test_component_python_m_entry_points_remain_available(module):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", f"mybench.{module}", "--help"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "usage:" in proc.stdout
