"""Shared opaque capture identity derivation (ADR-0002 §4 amendment).

The polling daemon and lifecycle hooks must join on one namespace.  This
module is deliberately path-in/content-out: callers supply a source-relative
path, but only the truncated stem plus a keyed HMAC can leave the function.
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path


def session_id_for_path(
    transcript_path: Path,
    *,
    watch_root: Path,
    source: str,
    scope_key: bytes,
) -> str:
    """Return the daemon-compatible opaque id for one transcript path."""
    relative = transcript_path.relative_to(watch_root).as_posix()
    tag = hmac.new(
        scope_key,
        f"{source}:{relative}".encode(),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"{transcript_path.stem[:40]}-{tag}"
