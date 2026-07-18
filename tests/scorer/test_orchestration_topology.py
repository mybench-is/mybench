"""MYB-13.7 orchestration topology inventory; synthetic structures only."""

from __future__ import annotations

import base64
import builtins
import json
import os
import stat
from pathlib import Path

import pytest

from mybench import paths
from mybench.registry import Registry, RegistryError
from mybench.scorer.topology import (
    TOPOLOGY_CATEGORIES,
    TOPOLOGY_REGISTRY_ID,
    TopologyScanError,
    scan_orchestration_topology,
    store_local_topology,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries

OBSERVED_AT = "2026-07-18T12:34:56Z"
CANARY_SKILL = "MYBENCH-CANARY-SKILL-7b2f"
CANARY_AGENT = "MYBENCH-CANARY-AGENT-93ac.md"
CANARY_PLAN = "MYBENCH-CANARY-PLAN-a441"


def _write(path: Path, content: str = "CONTENT-BYTES-MUST-NEVER-BE-READ") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _fixture_tree(root: Path, *, large: bool = True) -> Path:
    # Every byte is synthetic.  Distinctive names exercise the local/public split.
    _write(root / "CLAUDE.md")
    _write(root / ".claude" / "agents" / CANARY_AGENT)
    _write(root / ".claude" / "skills" / CANARY_SKILL / "SKILL.md")
    (root / "plans" / CANARY_PLAN).mkdir(parents=True)
    _write(root / "plans" / CANARY_PLAN / "task.md")
    _write(root / "scripts" / "validate-canary.sh")
    if large:
        for index in range(6):
            _write(root / ".claude" / "agents" / f"agent-{index}.md")
            _write(root / ".claude" / "hooks" / f"hook-{index}.sh")
            _write(root / ".claude" / "skills" / f"skill-{index}" / "SKILL.md")
            (root / "worktrees" / f"lane-{index}").mkdir(parents=True)
            _write(root / "checks" / f"verify-{index}.py")
            _write(root / f"level-{index}" / "AGENTS.md")
    return root


def _bytes_surface(tmp_path: Path, value: object, logs: str = "") -> list[Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    public = tmp_path / "publishable.json"
    public.write_text(json.dumps(value, sort_keys=True))
    log = tmp_path / "scanner.log"
    log.write_text(logs)
    return [public, log]


def test_dirwalk_stat_only_is_deterministic_and_never_reads_content(tmp_path, monkeypatch):
    root = _fixture_tree(tmp_path / "consented")
    # Warm the packaged registry before making ordinary content-read APIs fire.
    registry = Registry.load()
    real_os_open = os.open

    def forbidden(*_args, **_kwargs):
        raise AssertionError("scanner attempted to read file content")

    def directory_open(path, flags, mode=0o777, *, dir_fd=None):
        assert flags & os.O_DIRECTORY
        assert flags & os.O_NOFOLLOW
        assert not flags & (os.O_WRONLY | os.O_RDWR)
        return real_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(os, "open", directory_open)

    first = scan_orchestration_topology(
        root,
        observed_at=OBSERVED_AT,
        transcript_delegation_coverage_basis_points=6250,
        registry=registry,
    )
    second = scan_orchestration_topology(
        root,
        observed_at=OBSERVED_AT,
        transcript_delegation_coverage_basis_points=6250,
        registry=registry,
    )
    assert first == second
    assert CANARY_SKILL in json.dumps(first["local"])
    assert CANARY_AGENT in json.dumps(first["local"])
    assert CANARY_PLAN in json.dumps(first["local"])


def test_public_shape_is_fixed_banded_and_k_suppressed(tmp_path):
    inventory = scan_orchestration_topology(
        _fixture_tree(tmp_path / "consented"),
        observed_at=OBSERVED_AT,
        transcript_delegation_coverage_basis_points=6250,
    )
    public = inventory["publishable"]
    supported = {
        "custom_agents",
        "hooks",
        "instruction_files",
        "skills",
        "validation_scripts",
        "worktrees",
    }
    for category in supported:
        assert public[f"{category}_count_band"] == "5-19"
        assert public[f"{category}_present"] is True
    assert public["instruction_depth_band"] == "1-4"
    for category in set(TOPOLOGY_CATEGORIES) - supported:
        assert f"{category}_count_band" not in public
        assert f"{category}_present" not in public
    registry = Registry.load()
    entry = registry.entry(TOPOLOGY_REGISTRY_ID)
    registry.check_claim(
        {
            "registry_id": TOPOLOGY_REGISTRY_ID,
            "registry_version": entry["version"],
            "derivation_class": entry["class"],
            "output": public,
        }
    )
    encoded = json.dumps(public, sort_keys=True)
    assert CANARY_SKILL not in encoded
    assert CANARY_AGENT not in encoded
    assert CANARY_PLAN not in encoded
    assert "consented" not in encoded


def test_rare_distinctive_structure_is_absent_not_zero(tmp_path):
    inventory = scan_orchestration_topology(
        _fixture_tree(tmp_path / "rare", large=False), observed_at=OBSERVED_AT
    )
    public = inventory["publishable"]
    assert not any(key.endswith("_count_band") for key in public)
    assert not any(key.endswith("_present") for key in public)
    assert "instruction_depth_band" not in public
    assert inventory["local"]["structure_counts"]["skills"] == 1


def test_evidence_sources_and_scan_time_semantics_are_distinct(tmp_path):
    inventory = scan_orchestration_topology(
        _fixture_tree(tmp_path / "consented"),
        observed_at=OBSERVED_AT,
        transcript_delegation_coverage_basis_points="UNKNOWN",
    )
    local = inventory["local"]
    public = inventory["publishable"]
    assert local["scan"] == {
        "source": "file-structure",
        "coverage_basis_points": 10000,
        "coverage_basis": "complete-consented-root-walk",
        "scanned_at": OBSERVED_AT,
        "state_basis": "scan-time-state-not-evidence-period",
    }
    assert local["transcript_delegation"]["state_basis"] == "evidence-period-aggregate"
    assert public["observed_on"] == "2026-07-18"
    assert public["state_basis"] == "scan-time-state-not-evidence-period"
    assert public["file_structure_coverage_basis_points"] == 10000
    assert public["transcript_delegation_coverage_basis_points"] == "UNKNOWN"
    assert public["k_suppression_floor"] == 5
    assert public["caveats"] == ["scan-time-state-not-evidence-period"]


def test_canary_names_and_paths_never_reach_public_or_logs(tmp_path, caplog):
    inventory = scan_orchestration_topology(
        _fixture_tree(tmp_path / "consented"), observed_at=OBSERVED_AT
    )
    canaries = [CANARY_SKILL.encode(), CANARY_AGENT.encode(), CANARY_PLAN.encode()]
    surfaces = _bytes_surface(tmp_path / "surface", inventory["publishable"], caplog.text)
    assert assert_no_canaries(surfaces, canaries) == 2
    serialized = b"\n".join(path.read_bytes() for path in surfaces)
    for canary in canaries:
        assert canary not in serialized
        assert canary.hex().encode() not in serialized
        assert base64.b64encode(canary) not in serialized


def test_canary_leakscan_firing_test_detects_planted_public_name(tmp_path):
    inventory = scan_orchestration_topology(
        _fixture_tree(tmp_path / "consented"), observed_at=OBSERVED_AT
    )
    planted = dict(inventory["publishable"])
    planted["planted_name"] = CANARY_SKILL
    surfaces = _bytes_surface(tmp_path / "surface", planted)
    with pytest.raises(CanaryLeakError):
        assert_no_canaries(surfaces, [CANARY_SKILL.encode()])
    registry = Registry.load()
    entry = registry.entry(TOPOLOGY_REGISTRY_ID)
    with pytest.raises(RegistryError):
        registry.check_claim(
            {
                "registry_id": TOPOLOGY_REGISTRY_ID,
                "registry_version": entry["version"],
                "derivation_class": entry["class"],
                "output": planted,
            }
        )


def test_private_artifact_is_content_addressed_under_mode_0700_data_dir(tmp_path, monkeypatch):
    data_home = tmp_path / "private-data-home"
    monkeypatch.setenv(paths.XDG_DATA_HOME_ENV, str(data_home))
    inventory = scan_orchestration_topology(
        _fixture_tree(tmp_path / "consented"), observed_at=OBSERVED_AT
    )
    first = store_local_topology(inventory["local"])
    second = store_local_topology(inventory["local"])
    assert first == second
    assert first.is_relative_to(paths.data_dir())
    assert stat.S_IMODE(paths.data_dir().stat().st_mode) == 0o700
    assert stat.S_IMODE(first.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(first.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "kwargs",
    [
        {"observed_at": "2026-07-18"},
        {"observed_at": OBSERVED_AT, "transcript_delegation_coverage_basis_points": True},
        {"observed_at": OBSERVED_AT, "transcript_delegation_coverage_basis_points": 10001},
    ],
)
def test_invalid_explicit_metadata_fails_closed(tmp_path, kwargs):
    root = _fixture_tree(tmp_path / "consented")
    with pytest.raises(TopologyScanError):
        scan_orchestration_topology(root, **kwargs)


def test_symlink_root_and_symlinked_subtree_are_never_followed(tmp_path):
    outside = _fixture_tree(tmp_path / "outside")
    root = tmp_path / "consented"
    root.mkdir()
    (root / ".claude").symlink_to(outside / ".claude", target_is_directory=True)
    inventory = scan_orchestration_topology(root, observed_at=OBSERVED_AT)
    assert inventory["local"]["structure_counts"] == {
        category: 0 for category in TOPOLOGY_CATEGORIES
    }
    root_link = tmp_path / "root-link"
    root_link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(TopologyScanError, match="opened safely"):
        scan_orchestration_topology(root_link, observed_at=OBSERVED_AT)


def test_intermediate_directory_symlink_swap_fails_without_escaping(tmp_path, monkeypatch):
    root = _fixture_tree(tmp_path / "consented")
    outside = _fixture_tree(tmp_path / "outside")
    outside_canary = outside / ".claude" / "skills" / "OUTSIDE-CANARY" / "SKILL.md"
    _write(outside_canary)
    real_open = os.open
    swapped = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == ".claude" and dir_fd is not None and not swapped:
            (root / ".claude").rename(root / ".claude-before-race")
            (root / ".claude").symlink_to(outside / ".claude", target_is_directory=True)
            swapped = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)
    with pytest.raises(TopologyScanError, match="could not be scanned"):
        scan_orchestration_topology(root, observed_at=OBSERVED_AT)
    assert swapped


def test_root_components_are_no_follow_and_dot_root_is_supported(tmp_path, monkeypatch):
    root = _fixture_tree(tmp_path / "real-parent" / "consented")
    alias = tmp_path / "alias-parent"
    alias.symlink_to(root.parent, target_is_directory=True)
    with pytest.raises(TopologyScanError, match="opened safely"):
        scan_orchestration_topology(alias / root.name, observed_at=OBSERVED_AT)

    with pytest.raises(TopologyScanError, match="dot-dot"):
        scan_orchestration_topology(
            Path(os.fspath(root)) / ".." / root.name, observed_at=OBSERVED_AT
        )

    expected = scan_orchestration_topology(root, observed_at=OBSERVED_AT)
    monkeypatch.chdir(root)
    assert scan_orchestration_topology(Path("."), observed_at=OBSERVED_AT) == expected
