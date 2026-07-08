"""Filesystem locations for mybench.

Privacy invariant #2: nonces and the ledger live in a dedicated local data
directory (mode 0700, OUTSIDE all repos), never in any repo, test output, or
logs. This module is the single source of truth for that path.
"""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Return the mybench local data directory (may not exist yet).

    Honors ``XDG_DATA_HOME``, falling back to ``~/.local/share``. Always resolves
    outside every repo.
    """
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "mybench"


def ensure_data_dir() -> Path:
    """Create the data directory with mode 0700 if needed and return it."""
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d
