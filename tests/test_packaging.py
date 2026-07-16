"""Packaging invariants — version lockstep, entry points, installable wheel."""

import os
import shutil
import subprocess
import sys
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


def test_console_scripts_are_distinct_and_explicit():
    main = _project(ROOT / "pyproject.toml")
    wrapper = _project(ROOT / "packaging" / "mybench-verify" / "pyproject.toml")
    assert main["scripts"] == {"mybench": "mybench.__main__:main"}
    assert wrapper["scripts"]["mybench-verify"] == "mybench.verify.__main__:main"


def test_wrapper_entry_point_is_importable_and_callable():
    from mybench.verify.__main__ import main

    assert callable(main)


def test_main_entry_point_is_importable_and_callable():
    from mybench.__main__ import main

    assert callable(main)


def test_wheel_installs_the_channel_agnostic_console_script(tmp_path):
    isolated_env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    source = tmp_path / "source"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(".git", "*.egg-info", "__pycache__", ".pytest_cache"),
    )
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        [
            shutil.which("python3") or sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(wheelhouse),
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=isolated_env,
    )
    wheel = next(wheelhouse.glob("mybench-*.whl"))
    venv = tmp_path / "isolated"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)],
        check=True,
        capture_output=True,
        text=True,
        env=isolated_env,
    )
    python = venv / "bin" / "python"
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
        check=True,
        capture_output=True,
        text=True,
        env=isolated_env,
    )
    command = venv / "bin" / "mybench"
    result = subprocess.run(
        [str(command), "--help"], capture_output=True, text=True, env=isolated_env
    )
    assert result.returncode == 0
    assert "{init,scan,report,capture,status,publish,verify}" in result.stdout
