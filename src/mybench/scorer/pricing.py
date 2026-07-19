"""Immutable, effective-dated pricing inputs for deterministic local scoring.

Snapshots are ordinary packaged JSON resources.  Loading computes their
content address and validates their closed schema; it never consults a clock,
environment variable, or network service.  Updating a price card means adding
a new versioned resource.  Existing versions are retained for recomputation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib import resources

from mybench.claims.canonical import canonical_bytes
from mybench.schemas import load_validator

PRICING_SNAPSHOT_SCHEMA_VERSION = "1"
DEFAULT_PRICING_SNAPSHOT_VERSION = "1.0.0"
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")


class PricingSnapshotError(ValueError):
    """A packaged pricing snapshot is missing, mutable-looking, or invalid."""


@dataclass(frozen=True)
class PricingSnapshot:
    """Owned canonical bytes plus the externally recorded snapshot identity."""

    version: str
    digest: str
    currency: str
    _bytes: bytes

    def document(self) -> dict:
        """Return a fresh value so callers cannot mutate the pinned input."""

        return json.loads(self._bytes)

    def reference(self) -> dict[str, str]:
        return {"version": self.version, "digest": self.digest, "currency": self.currency}


def load_pricing_snapshot(version: str) -> PricingSnapshot:
    """Load exactly one named in-package snapshot and compute its checksum."""

    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        raise PricingSnapshotError("pricing snapshot version is invalid")
    name = f"pricing_snapshot_{version}.json"
    try:
        raw = resources.files("mybench.registry").joinpath(name).read_bytes()
        value = json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise PricingSnapshotError("pricing snapshot is unavailable or invalid") from exc
    errors = sorted(load_validator("pricing_snapshot.schema.json").iter_errors(value), key=str)
    if errors:
        raise PricingSnapshotError("pricing snapshot violates the closed schema")
    if value["version"] != version:
        raise PricingSnapshotError("pricing snapshot filename and version disagree")

    aliases: set[tuple[str, str]] = set()
    intervals: set[tuple[str, str, str, str | None]] = set()
    for rate in value["rates"]:
        if rate["effective_until"] is not None and rate["effective_until"] < rate["effective_from"]:
            raise PricingSnapshotError("pricing snapshot has an inverted effective interval")
        interval = (
            rate["provider"],
            rate["model_sku"],
            rate["effective_from"],
            rate["effective_until"],
        )
        if interval in intervals:
            raise PricingSnapshotError("pricing snapshot repeats a model interval")
        intervals.add(interval)
        for alias in rate["aliases"]:
            key = (rate["provider"], alias)
            if key in aliases:
                raise PricingSnapshotError("pricing snapshot aliases are ambiguous")
            aliases.add(key)

    encoded = canonical_bytes(value)
    return PricingSnapshot(
        version=version,
        digest=hashlib.sha256(encoded).hexdigest(),
        currency=value["currency"],
        _bytes=encoded,
    )


def pricing_snapshot_artifact(version: str) -> dict:
    """Return deterministic bytes-ready identity and content for audit tooling."""

    snapshot = load_pricing_snapshot(version)
    return {"reference": snapshot.reference(), "snapshot": snapshot.document()}


__all__ = [
    "DEFAULT_PRICING_SNAPSHOT_VERSION",
    "PRICING_SNAPSHOT_SCHEMA_VERSION",
    "PricingSnapshot",
    "PricingSnapshotError",
    "load_pricing_snapshot",
    "pricing_snapshot_artifact",
]
