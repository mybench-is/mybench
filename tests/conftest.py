"""Suite-wide privacy guards (invariant #2 / MYB-2.1 AC #4).

Every test runs with XDG_DATA_HOME pointed at a per-test tmp dir, so no test
can ever touch the real data dir; after the whole run, the repo tree is
scanned for data-dir artifacts and the run fails if any appeared.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
# Basenames/dirnames that only ever belong under the data dir (never in a repo).
FORBIDDEN_BASENAMES = {
    "capture.lock",
    "device.key",
    "device.pub",
    "identity.key",
    "identity.pub",
    "ledger.db",
    "log-signing",
    "session-scope.key",
}
FORBIDDEN_DIRNAMES = {"archive", "nonces", "normalized", "queue", "reports"}


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))


def scan_repo_for_data_artifacts() -> list[Path]:
    skip = {".git", ".venv", "__pycache__", ".pytest_cache"}
    hits = []
    for p in REPO_ROOT.rglob("*"):
        if skip & set(p.parts):
            continue
        if p.name in FORBIDDEN_BASENAMES or (p.is_dir() and p.name in FORBIDDEN_DIRNAMES):
            hits.append(p)
    return hits


@pytest.fixture(scope="session", autouse=True)
def _repo_tree_privacy_guard():
    # Session teardown runs after every test; an assertion here fails the run
    # (unlike pytest_sessionfinish, which cannot change the exit code).
    yield
    hits = scan_repo_for_data_artifacts()
    assert not hits, (
        "PRIVACY GUARD FAILED (invariant #2): data-dir artifacts inside the repo tree:\n"
        + "\n".join(f"  {h}" for h in hits)
    )
