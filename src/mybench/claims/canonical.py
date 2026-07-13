"""Canonical JSON for claims — the byte-reproducibility substrate (MYB-10.1).

One serialization for signing, storage, and comparison (handoff §4 rule 1,
ADR-0012 determinism discipline): UTF-8, lexicographically sorted keys,
compact separators, and **no floats anywhere** — numeric outputs are
integers, fixed-precision decimal *strings*, or band labels. Floats are
rejected structurally (not rounded, not tolerated) because IEEE-754
formatting is exactly the kind of platform wobble that breaks the two-run
byte-compare gate and, later, local-vs-enclave byte-identity.

Same convention as anchor batches and identity records
(``json.dumps(sort_keys=True, separators=(",", ":"))``): non-ASCII text is
escaped (``ensure_ascii``), which keeps the byte stream ASCII-safe and
deterministic while remaining valid UTF-8. The signature covers the
canonical bytes of the claim *without* its ``signature`` field.
"""

from __future__ import annotations

import json


class CanonicalError(ValueError):
    pass


def check_canonical_value(obj: object, path: str = "$") -> None:
    """Reject anything canonical JSON for claims may not carry.

    Floats (incl. NaN/inf) at any depth, non-string dict keys, and types
    without an exact JSON meaning all raise with the offending path, so a
    scorer bug names its own location instead of surfacing as a byte diff.
    ``bool`` is checked before ``int`` on purpose (bool subclasses int).
    """
    if isinstance(obj, float):
        raise CanonicalError(
            f"float at {path}: use integers, fixed-precision decimal strings, or band labels"
        )
    if obj is None or isinstance(obj, (bool, int, str)):
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise CanonicalError(f"non-string key at {path}: {type(key).__name__}")
            check_canonical_value(value, f"{path}.{key}")
        return
    if isinstance(obj, (list, tuple)):
        for i, value in enumerate(obj):
            check_canonical_value(value, f"{path}[{i}]")
        return
    raise CanonicalError(f"unsupported type at {path}: {type(obj).__name__}")


def canonical_bytes(obj: dict) -> bytes:
    """The one true byte form: checked, sorted, compact."""
    check_canonical_value(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def signed_bytes(claim: dict) -> bytes:
    """The exact bytes a claim signature covers: canonical JSON minus ``signature``."""
    return canonical_bytes({k: v for k, v in claim.items() if k != "signature"})
