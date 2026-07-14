"""MYB-10.3 gate integration and companion firing tests."""

from __future__ import annotations

import re
from importlib import metadata
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from tests.determinism.gate import (
    GateError,
    assert_byte_identical,
    audit_source,
    run_gate,
)
from tests.determinism.stages import STAGES

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_all_landed_stages_are_byte_identical_across_perturbed_processes():
    results = run_gate()
    assert [result.name for result in results] == [stage.name for stage in STAGES]
    assert all(result.size > 0 and len(result.sha256) == 64 for result in results)


def test_byte_compare_fires_on_divergence_without_logging_artifact_bytes():
    with pytest.raises(GateError, match="run 1=14 bytes.*run 2=16 bytes") as caught:
        assert_byte_identical("synthetic-divergence", b"private-first!", b"private-second!!")
    assert "private-first" not in str(caught.value)
    assert "private-second" not in str(caught.value)


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("import os as operating_system\nvalue = operating_system.environ['X']\n", "environment"),
        ("from time import monotonic as tick\nvalue = tick()\n", "clock"),
        ("import urllib.request as client\nvalue = client.urlopen('https://invalid')\n", "network"),
        ("import socket\nvalue = socket.socket()\n", "network"),
        ("import subprocess\nvalue = subprocess.run(['git'])\n", "subprocess"),
        ("import random\nvalue = random.random()\n", "ambient randomness"),
        ("from datetime import datetime as instant\nvalue = instant.now()\n", "wall clock"),
        ("from datetime import date\nvalue = date.today()\n", "wall clock"),
        ("from pathlib import Path\nvalue = Path.home()\n", "environment home"),
    ],
)
def test_ambient_state_audit_fires_for_aliases(tmp_path, source, reason):
    candidate = tmp_path / "candidate.py"
    candidate.write_text(source)
    issues = audit_source(candidate)
    assert issues and any(reason in issue.message for issue in issues)


def test_ambient_state_audit_allows_explicit_time_input_and_date_math(tmp_path):
    candidate = tmp_path / "candidate.py"
    candidate.write_text(
        "from datetime import date, timedelta\n"
        "def derive_day(timestamp):\n"
        "    return date.fromisoformat(timestamp[:10]) + timedelta(days=1)\n"
    )
    assert audit_source(candidate) == []


def _direct_requirements(path: Path) -> set[str]:
    found = set()
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-r "):
            found |= _direct_requirements(path.with_name(line.removeprefix("-r ")))
            continue
        found.add(re.split(r"[<>=!~\[]", line, maxsplit=1)[0].lower())
    return found


def test_ci_lockfile_is_exact_and_covers_direct_dependencies():
    lock = REPO_ROOT / "requirements-ci.lock"
    pins = {}
    for raw_line in lock.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        assert line.count("==") == 1, f"unlocked requirement: {line}"
        name, version = line.split("==")
        normalized = name.lower().replace("_", "-")
        assert normalized not in pins, f"duplicate lock entry: {name}"
        assert version, f"empty lock version: {name}"
        pins[normalized] = version

    direct = {
        name.replace("_", "-")
        for name in _direct_requirements(REPO_ROOT / "requirements-ci.txt")
    }
    assert direct <= pins.keys(), f"direct dependencies absent from lock: {sorted(direct - pins.keys())}"

    missing_transitive = set()
    for package in pins:
        for requirement_text in metadata.requires(package) or ():
            requirement = Requirement(requirement_text)
            if requirement.marker and not requirement.marker.evaluate({"extra": ""}):
                continue
            dependency = requirement.name.lower().replace("_", "-")
            if dependency not in pins:
                missing_transitive.add(dependency)
    assert not missing_transitive, f"active transitive dependencies absent from lock: {sorted(missing_transitive)}"
