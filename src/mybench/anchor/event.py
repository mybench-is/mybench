"""Anchor events — schema v2 + layout v1 (MYB-8.3, ADR-0004 §§4–5).

An event is the v2 projection of a batch (mybench.anchor.batch remains the
computation core): identity-namespaced, coarse-dated (UTC date only — the
v1 artifact's second-precision ts is the privacy regression this fixes),
carrying item_count and client_version, re-signed by the device key.
One event per identity per UTC day; event files are immutable.

``migrate_flat_repo`` converts a pre-ADR-0004 flat clone (anchor-*.json at
the root) into layout v1 in place — legitimate only while the repo is
private and its URL unpublished, which is exactly the window ADR-0004
reserves for it. The OTS proof carries over untouched: it stamps the root,
and the root does not change.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

import mybench
from mybench import paths
from mybench.anchor.batch import AnchorError, signed_bytes, verify_batch
from mybench.identity import (
    device_binding_record,
    genesis_record,
    handle_binding_record,
    local_identity_id,
)
from mybench.schemas import load_validator

SPEC_RELPATH = Path("schema") / "anchor.v1.md"

SPEC_TEXT = """# mybench anchors log — layout v1 / anchor event schema v2

One immutable JSON file per anchor event:

    anchors/<identity-id>/<YYYY>/<MM>/<DD>.json         the event
    anchors/<identity-id>/<YYYY>/<MM>/<DD>.json.ots     OpenTimestamps proof,
                                                        added once confirmed
    identities/<identity-id>/genesis.json               inception record
    identities/<identity-id>/handle-NNNN.json           signed handle binding
    identities/<identity-id>/device-XXXXXXXX.json       signed device binding
    checkpoints/<YYYY>/<MM>/<DD>.json                   daily project tree head

- identity-id = hex(SHA-256("mybench:v1:identity" || raw genesis identity
  pubkey)). Handles are mutable display labels; bindings are signed records.
- One anchor event per identity per UTC day. Files are created once and
  never modified; an absent .ots means the proof is still pending Bitcoin
  confirmation (re-check later).
- Event fields and encodings: anchor_event.schema.json (v2) in the mybench
  source repo. Every event is Ed25519-signed by a device key that chains to
  the identity via a device-binding record.
- Date-based paths are deliberate: gaps are visible and meaningful.
  "No anchor for a day" is distinguishable from "withheld activity" via
  continuity of the covered ledger row ranges (row_start/row_end chain with
  no gaps or overlaps across an identity's events).
"""


class EventError(AnchorError):
    pass


def event_relpaths(identity_id: str, date: str) -> tuple[Path, Path]:
    y, m, d = date.split("-")
    base = Path("anchors") / identity_id / y / m / f"{d}.json"
    return base, base.with_name(base.name + ".ots")


def identity_relpath(identity_id: str) -> Path:
    return Path("identities") / identity_id


def build_event(batch: dict, rows: list[dict], *, date: str) -> dict:
    """Project a verified v1 batch to a v2 event and sign it with the device key."""
    verify_batch(batch)
    covered = rows[batch["row_start"] : batch["row_end"]]
    if len(covered) != batch["row_count"]:
        raise EventError("rows slice does not match the batch's covered range")
    item_count = sum(r["item_count"] for r in covered if r["type"] == "session")
    key_path, _ = paths.ensure_device_key()
    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    event = {
        "schema_version": "2",
        "scheme": batch["scheme"],
        "identity_id": local_identity_id(),
        "date": date,
        "row_start": batch["row_start"],
        "row_end": batch["row_end"],
        "row_count": batch["row_count"],
        "session_count": batch["session_count"],
        "item_count": item_count,
        "root": batch["root"],
        "chain_tip": batch["chain_tip"],
        "client_version": mybench.__version__,
        "device_pub": batch["device_pub"],
    }
    event["sig"] = private.sign(signed_bytes(event)).hex()
    validate_event(event)
    return event


def verify_event(event: dict) -> None:
    """Schema + device-signature verification (raises EventError)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    validate_event(event)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(event["device_pub"])).verify(
            bytes.fromhex(event["sig"]), signed_bytes(event)
        )
    except (InvalidSignature, ValueError) as exc:
        raise EventError("event device signature does not verify") from exc


def stage_event(event: dict, proof_bytes: bytes, staging: Path) -> tuple[Path, Path]:
    """Write an event + its (possibly pending) proof into the staging tree."""
    rel_event, rel_proof = event_relpaths(event["identity_id"], event["date"])
    event_path, proof_path = staging / rel_event, staging / rel_proof
    if event_path.exists():
        raise EventError(f"{rel_event} already staged — one event per identity per UTC day")
    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_path.write_bytes(event_bytes(event))
    proof_path.write_bytes(proof_bytes)
    return event_path, proof_path


def validate_event(event: dict) -> None:
    errors = sorted(load_validator("anchor_event.schema.json").iter_errors(event), key=str)
    if errors:
        raise EventError(f"anchor event schema violation: {errors[0].message}")
    if event["row_count"] != event["row_end"] - event["row_start"]:
        raise EventError("row_count does not match the covered range")


def event_bytes(event: dict) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def write_identity_records(repo: Path, handle: str, date: str) -> list[Path]:
    """Genesis + handle + retroactive device binding under identities/<id>/."""
    identity_id = local_identity_id()
    _, device_pub_path = paths.ensure_device_key()
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    device_raw = load_pem_public_key(device_pub_path.read_bytes()).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    directory = repo / identity_relpath(identity_id)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, record in (
        ("genesis.json", genesis_record(date)),
        ("handle-0000.json", handle_binding_record(handle, date, seq=0)),
        (f"device-{device_raw.hex()[:8]}.json",
         device_binding_record(device_raw.hex(), date, scope="retroactive")),
    ):
        target = directory / name
        if target.exists():
            raise EventError(f"{target} exists — identity records are immutable")
        target.write_bytes(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
                           + b"\n")
        written.append(target)
    return written


def migrate_flat_repo(clone: Path, rows: list[dict], *, handle: str) -> dict:
    """Convert a flat pre-ADR-0004 clone to layout v1 in place (pre-publication only).

    Each flat batch becomes a v2 event dated by the batch ts's UTC date; the
    OTS proof moves unchanged (it stamps the root). Old flat files are
    removed. Caller reviews, commits, pushes.
    """
    flat = sorted(clone.glob("anchor-*.json"))
    if not flat:
        raise EventError("no flat artifacts to migrate")
    identity_id = local_identity_id()
    manifest = {"identity_id": identity_id, "events": [], "records": [], "removed": []}
    for artifact in flat:
        batch = json.loads(artifact.read_bytes())
        date = batch["ts"][:10]
        event = build_event(batch, rows, date=date)
        event_path, proof_path = (clone / p for p in event_relpaths(identity_id, date))
        if event_path.exists():
            raise EventError(f"{event_path} exists — one event per identity per UTC day")
        event_path.parent.mkdir(parents=True, exist_ok=True)
        event_path.write_bytes(event_bytes(event))
        old_proof = artifact.with_name(artifact.name[: -len(".json")] + ".root.ots")
        if old_proof.exists():
            proof_path.write_bytes(old_proof.read_bytes())
            old_proof.unlink()
            manifest["removed"].append(old_proof.name)
        artifact.unlink()
        manifest["removed"].append(artifact.name)
        manifest["events"].append(str(event_path.relative_to(clone)))
    # Identity records carry the first event's date (the binding provably
    # existed from the log's first migrated day onward).
    first = Path(manifest["events"][0])
    record_date = f"{first.parts[-3]}-{first.parts[-2]}-{first.stem}"
    manifest["records"] = [
        str(p.relative_to(clone))
        for p in write_identity_records(clone, handle, record_date)
    ]
    spec = clone / SPEC_RELPATH
    spec.parent.mkdir(exist_ok=True)
    spec.write_text(SPEC_TEXT)
    manifest["spec"] = str(SPEC_RELPATH)
    return manifest
