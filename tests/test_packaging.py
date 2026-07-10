"""MYB-5.9: packaging invariants — version lockstep, wrapper discipline."""

import tomllib
from pathlib import Path

import mybench

ROOT = Path(__file__).parents[1]


def _project(path):
    with open(path, "rb") as f:
        return tomllib.load(f)["project"]


def test_versions_in_lockstep():
    main = _project(ROOT / "pyproject.toml")
    wrapper = _project(ROOT / "packaging" / "mybench-verify" / "pyproject.toml")
    assert main["version"] == mybench.__version__ == wrapper["version"]
    assert wrapper["dependencies"] == [f"mybench=={main['version']}"]


def test_console_script_lives_only_in_the_wrapper():
    main = _project(ROOT / "pyproject.toml")
    wrapper = _project(ROOT / "packaging" / "mybench-verify" / "pyproject.toml")
    assert "scripts" not in main  # avoids entry-point collisions
    assert wrapper["scripts"]["mybench-verify"] == "mybench.verify.__main__:main"


def test_wrapper_entry_point_is_importable_and_callable():
    from mybench.verify.__main__ import main

    assert callable(main)
