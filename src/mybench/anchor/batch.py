"""Anchor batch builder (MYB-3.1): deterministic publishable artifacts.

A batch covers a contiguous ledger row range ``[row_start, row_end)``. Its
Merkle leaves are the covered rows' ``session_root`` values (already the
publishable form, threat model §3); the batch root applies ADR-0002 §3's
``day`` finalization wrapper — with the threat model's daily cadence, one
batch per day IS the day root, but the builder itself is cadence-agnostic
(the caller decides where to cut).

Determinism (AC #1): every field derives from ledger content — ``ts`` is the
newest covered row's timestamp, not build time (anchor time comes from the
OTS proof, MYB-3.2) — serialization is canonical (compact, sorted keys), and
Ed25519 signatures are deterministic (RFC 8032). Same ledger prefix ⇒
byte-identical artifact, across runs and processes.

The artifact embeds ``chain_tip`` (h of the last covered row) so verifiers
can call ``verify_chain(expect_tip=…)`` — trailing truncation of the local
ledger is undetectable without it (MYB-2.4). Publishing these hashes is
safe: every row's h commits to an unguessable session_root, so no
dictionary/confirmation attack applies (MYB-1.3 §2 does not reach them).
"""

from __future__ import annotations

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mybench import paths
from mybench.commitments import day_root
from mybench.ledger import Ledger
from mybench.schemas import load_validator

SCHEMA_VERSION = "1"
SCHEME = "mybench:v1"


class AnchorError(RuntimeError):
    pass


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def signed_bytes(batch: dict) -> bytes:
    """The exact bytes the device signature covers: canonical JSON minus sig."""
    return _canonical({k: v for k, v in batch.items() if k != "sig"})


def canonical_bytes(batch: dict) -> bytes:
    """The exact artifact file bytes: canonical JSON of the full batch + newline."""
    return _canonical(batch) + b"\n"


def validate_batch(batch: dict) -> None:
    """Schema whitelist + internal consistency; raises AnchorError."""
    errors = sorted(load_validator("anchor_batch.schema.json").iter_errors(batch), key=str)
    if errors:
        raise AnchorError(f"anchor batch schema violation: {errors[0].message}")
    if batch["row_end"] <= batch["row_start"]:
        raise AnchorError("row_end must be greater than row_start")
    if batch["row_count"] != batch["row_end"] - batch["row_start"]:
        raise AnchorError("row_count does not match the covered range")
    if batch["session_count"] > batch["row_count"]:
        raise AnchorError("session_count exceeds row_count")


def build_batch(ledger: Ledger | None = None, *, previous: dict | None = None,
                row_end: int | None = None) -> dict:
    """Build (and sign) the next anchor batch.

    ``previous`` is the last published batch (or None for the first);
    coverage starts at its ``row_end``, guaranteeing contiguous,
    non-overlapping ranges (AC #3). ``row_end`` defaults to the full chain.
    """
    ledger = ledger if ledger is not None else Ledger()
    total = ledger.verify_chain()
    row_start = 0 if previous is None else previous["row_end"]
    row_end = total if row_end is None else row_end
    if row_end > total:
        raise AnchorError(f"row_end {row_end} beyond ledger length {total}")
    rows = ledger.rows()[row_start:row_end]
    if not rows:
        raise AnchorError("empty row range — nothing to anchor")
    leaves = [bytes.fromhex(r["session_root"]) for r in rows if r["type"] == "session"]
    if not leaves:
        raise AnchorError("no session rows in range — nothing to anchor")

    key_path, _ = paths.ensure_device_key()
    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    device_pub = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    batch = {
        "schema_version": SCHEMA_VERSION,
        "scheme": SCHEME,
        "row_start": row_start,
        "row_end": row_end,
        "row_count": row_end - row_start,
        "session_count": len(leaves),
        "root": day_root(leaves).hex(),
        "chain_tip": rows[-1]["h"],
        "ts": max(r["ts"] for r in rows),
        "device_pub": device_pub.hex(),
    }
    batch["sig"] = private.sign(signed_bytes(batch)).hex()
    validate_batch(batch)
    return batch


def verify_batch(batch: dict, rows: list[dict] | None = None) -> None:
    """Verify schema, signature, and (given the covered rows) root and tip.

    Raises AnchorError on any failure. This is the seed of the Phase 4
    verify CLI's PROVEN-tier checks.
    """
    validate_batch(batch)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(batch["device_pub"])).verify(
            bytes.fromhex(batch["sig"]), signed_bytes(batch)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AnchorError("device signature does not verify") from exc
    if rows is None:
        return
    if len(rows) != batch["row_count"]:
        raise AnchorError("covered row count mismatch")
    leaves = [bytes.fromhex(r["session_root"]) for r in rows if r["type"] == "session"]
    if len(leaves) != batch["session_count"]:
        raise AnchorError("session count mismatch")
    if day_root(leaves).hex() != batch["root"]:
        raise AnchorError("root does not recompute from the covered rows")
    if rows[-1]["h"] != batch["chain_tip"]:
        raise AnchorError("chain tip does not match the last covered row")
