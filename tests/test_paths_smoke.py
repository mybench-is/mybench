"""Smoke test for mybench.paths — the data dir must sit OUTSIDE every repo (invariant #2)."""

from pathlib import Path

from mybench import paths


def test_data_dir_is_outside_this_repo():
    d = paths.data_dir().resolve()
    repo_root = Path(__file__).resolve().parents[1]
    assert repo_root not in d.parents
    assert d.name == "mybench"


def test_data_dir_default_under_local_share(monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    d = paths.data_dir()
    assert d.parent.name == "share"
    assert d.parent.parent.name == ".local"
