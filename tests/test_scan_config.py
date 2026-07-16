"""MYB-11.3 consent-first source discovery and persistent exclusions."""

from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path

import pytest

from mybench import cli, paths, scan_config
from mybench.daemon import capture
from mybench.daemon.__main__ import main as daemon_main
from mybench.ledger import Ledger
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _home_fixtures(tmp_path: Path, monkeypatch) -> tuple[object, Path]:
    home = tmp_path / "CANARY-explicit-local-home"
    home.mkdir()
    fx = generate_fixtures(home / "staged")
    (home / "staged" / "claude").rename(home / ".claude")
    (home / "staged" / "codex").rename(home / ".codex")
    monkeypatch.setenv("HOME", str(home))
    return fx, home


def _fixture_canaries(home: Path) -> list[bytes]:
    return [
        line.encode()
        for line in (
            "MYBENCH-CANARY-",
            "synthetic user prompt",
            "synthetic base",
        )
    ]


def test_proposals_are_complete_consent_output_and_proposal_or_decline_writes_nothing(
    tmp_path, monkeypatch, capsys
):
    _, home = _home_fixtures(tmp_path, monkeypatch)
    git_root = tmp_path / "explicit-git-root"
    git_repo = git_root / "synthetic-repo"
    (git_repo / ".git").mkdir(parents=True)

    assert (
        cli.main(
            [
                "init",
                "--detect",
                "claude,codex,git",
                "--root",
                str(git_root),
                "--json",
            ]
        )
        == 0
    )
    proposed = capsys.readouterr()
    payload = json.loads(proposed.out)
    assert payload == {
        "command": "init --detect",
        "configured": False,
        "exclusions": [],
        "proposals": [
            {
                "kind": "claude",
                "path": str(home / ".claude" / "projects"),
                "source": "claude-code",
            },
            {
                "kind": "codex",
                "path": str(home / ".codex" / "sessions"),
                "source": "codex",
            },
            {"kind": "git", "path": str(git_repo)},
        ],
        "status": "proposed",
    }
    assert not paths.data_dir().exists()
    assert all(canary not in proposed.out.encode() for canary in _fixture_canaries(home))

    assert cli.main(["init", "--detect", "claude,codex", "--decline", "--json"]) == 0
    declined = json.loads(capsys.readouterr().out)
    assert declined["status"] == "declined"
    assert declined["configured"] is False
    assert not paths.data_dir().exists()


def test_accept_persists_private_config_and_codex_capture_honors_exclusion_everywhere(
    tmp_path, monkeypatch, capsys, caplog
):
    fx, home = _home_fixtures(tmp_path, monkeypatch)
    excluded = home / ".claude" / "projects" / "-synthetic-project"
    excluded_canary = next(excluded.glob("*.jsonl")).read_bytes()

    command = [
        "init",
        "--detect",
        "claude,codex",
        "--exclude",
        str(excluded),
        "--accept-all",
        "--json",
    ]
    assert cli.main(command) == 0
    accepted = capsys.readouterr()
    assert json.loads(accepted.out) == {
        "command": "init --detect",
        "configured": True,
        "exclusions": 1,
        "keys_ready": 4,
        "repos": 0,
        "status": "ok",
        "watches": 2,
    }
    assert _mode(paths.data_dir()) == 0o700
    assert paths.scan_config_path().parent == paths.data_dir()
    assert _mode(paths.scan_config_path()) == 0o600
    stored_bytes = paths.scan_config_path().read_bytes()
    stored = scan_config.load()
    assert stored is not None
    assert stored.exclusions == (str(excluded),)
    assert [watch.source for watch in stored.watches] == ["claude-code", "codex"]
    assert scan_config.store(stored).read_bytes() == stored_bytes

    real_scandir = os.scandir

    def reject_excluded(path):
        if Path(path) == excluded:
            raise AssertionError("excluded directory was opened")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", reject_excluded)
    caplog.set_level(logging.INFO, logger="mybench.daemon")
    assert cli.main(["scan", "--json"]) == 0
    scan_output = capsys.readouterr()
    summary = json.loads(scan_output.out)
    assert summary["rows_appended"] == 1
    assert summary["watches"] == 2
    rows = [row for row in Ledger().rows() if row["type"] == "session"]
    assert len(rows) == 1 and rows[0]["source"] == "codex"

    assert daemon_main(["--once"]) == 0
    assert len([row for row in Ledger().rows() if row["type"] == "session"]) == 1

    local_surface = tmp_path / "discovery-and-scan-output.log"
    local_surface.write_text(accepted.out + accepted.err + scan_output.out + scan_output.err + caplog.text)
    content_canaries = fx.all_canaries() + [excluded_canary]
    assert assert_no_canaries([local_surface], content_canaries) == 1


def test_git_discovery_has_no_implicit_root_and_never_traverses_outside_explicit_root(
    tmp_path, monkeypatch, capsys
):
    root = tmp_path / "explicit-root"
    repo = root / "nested" / "repo"
    outside = tmp_path / "outside" / "repo"
    (repo / ".git").mkdir(parents=True)
    (outside / ".git").mkdir(parents=True)
    real_walk = os.walk
    walked = []

    def bounded_walk(top, *args, **kwargs):
        walked.append(Path(top))
        return real_walk(top, *args, **kwargs)

    monkeypatch.setattr(os, "walk", bounded_walk)
    proposals = scan_config.discover(
        ("git",), home=tmp_path, git_roots=(root,), exclusions=()
    )
    assert [(proposal.kind, proposal.path) for proposal in proposals] == [("git", repo)]
    assert walked == [root]
    assert outside not in [proposal.path for proposal in proposals]

    assert cli.main(["init", "--detect", "git", "--json"]) == 1
    failure = capsys.readouterr()
    assert json.loads(failure.err)["error"] == "discovery_failed"
    assert str(root) not in failure.err and str(outside) not in failure.err
    assert not paths.data_dir().exists()


def test_discovery_prunes_excluded_git_tree_before_opening_it(tmp_path, monkeypatch):
    root = tmp_path / "root"
    excluded = root / "excluded"
    included = root / "included"
    (excluded / "repo" / ".git").mkdir(parents=True)
    (included / ".git").mkdir(parents=True)
    real_scandir = os.scandir

    def reject_excluded(path):
        if Path(path) == excluded:
            raise AssertionError("excluded git tree was opened")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", reject_excluded)
    proposals = scan_config.discover(
        ("git",), home=tmp_path, git_roots=(root,), exclusions=(str(excluded),)
    )
    assert [proposal.path for proposal in proposals] == [included]


@pytest.mark.parametrize("attack", ("loose", "loose_parent", "symlink", "hardlink"))
def test_scan_config_loader_refuses_insecure_storage(tmp_path, attack):
    watch = tmp_path / "watch"
    watch.mkdir()
    config = scan_config.ScanConfig(
        watches=(capture.WatchSpec(watch, "codex"),),
    )
    target = scan_config.store(config)
    if attack == "loose":
        target.chmod(0o644)
    elif attack == "loose_parent":
        target.parent.chmod(0o755)
    elif attack == "symlink":
        original = target.with_suffix(".original")
        target.rename(original)
        target.symlink_to(original)
    else:
        target.with_suffix(".hardlink").hardlink_to(target)
    with pytest.raises((scan_config.ScanConfigError, OSError)):
        scan_config.load()


def test_config_schema_is_closed_and_leak_scanner_fires_on_repo_copy(tmp_path):
    repo = tmp_path / "synthetic-repo"
    repo.mkdir()
    path_canary = str(tmp_path / "CANARY-private-location")
    planted = repo / "scan-config.json"
    planted.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "watches": [{"path": path_canary, "source": "codex"}],
                "repos": [],
                "exclusions": [],
            }
        )
    )
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([repo], [path_canary.encode()])

    malformed = json.loads(planted.read_text())
    malformed["transcript_content"] = "must never fit"
    with pytest.raises(Exception):
        scan_config._validate_dict(malformed)

    noncanonical = json.loads(planted.read_text())
    second = str(tmp_path / "CANARY-second-private-location")
    noncanonical["watches"].insert(0, {"path": second, "source": "codex"})
    with pytest.raises(scan_config.ScanConfigError, match="canonical"):
        scan_config._validate_dict(noncanonical)
