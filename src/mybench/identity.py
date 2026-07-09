"""Identity model (ADR-0004 §3): genesis-fingerprint IDs and signed records.

Three layers, deliberately decomposed:
- **identity ID** — ``hex(SHA-256("mybench:v1:identity" || raw genesis
  identity pubkey))``, full 64 hex. Self-certifying, never derived from a
  handle, never changes. This is the log namespace key.
- **identity keypair** — dedicated Ed25519 (paths.ensure_identity_key),
  signs binding records ONLY; can be held offline after setup.
- **handle** — mutable display label (``[a-z0-9-]{3,32}``); the handle→ID
  binding is itself a signed, logged record. Rename = new binding record.

Records are canonical-JSON dicts signed by the identity key (same
signed-bytes convention as anchor batches). Control rotation happens via
future succession records — formats here are extensible on purpose
(MYB-8.11 designs the mechanics).
"""

from __future__ import annotations

import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mybench import paths

DOMAIN_IDENTITY = b"mybench:v1:identity"
HANDLE_RE = re.compile(r"^[a-z0-9-]{3,32}$")
RECORD_SCHEMA_VERSION = "1"


class IdentityError(RuntimeError):
    pass


def identity_id_for(raw_pub: bytes) -> str:
    if len(raw_pub) != 32:
        raise IdentityError(f"raw Ed25519 pubkey must be 32 bytes, got {len(raw_pub)}")
    return hashlib.sha256(DOMAIN_IDENTITY + raw_pub).hexdigest()


def _load_private() -> Ed25519PrivateKey:
    key_path, _ = paths.ensure_identity_key()
    return serialization.load_pem_private_key(key_path.read_bytes(), password=None)


def _raw_pub(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def local_identity_id() -> str:
    return identity_id_for(_raw_pub(_load_private()))


def _signed(record: dict, private: Ed25519PrivateKey) -> dict:
    body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    return {**record, "sig": private.sign(body).hex()}


def verify_record(record: dict, identity_pub_hex: str) -> None:
    """Check a record's signature against the identity pubkey; raises IdentityError."""
    body = json.dumps(
        {k: v for k, v in record.items() if k != "sig"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(identity_pub_hex)).verify(
            bytes.fromhex(record["sig"]), body
        )
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise IdentityError(f"record signature does not verify: {record.get('type')}") from exc


def genesis_record(date: str) -> dict:
    """The inception record: binds the ID to its genesis pubkey. Extensible on purpose."""
    private = _load_private()
    raw = _raw_pub(private)
    return _signed(
        {
            "schema_version": RECORD_SCHEMA_VERSION,
            "type": "genesis",
            "identity_id": identity_id_for(raw),
            "identity_pub": raw.hex(),
            "date": date,
        },
        private,
    )


def handle_binding_record(handle: str, date: str, seq: int = 0) -> dict:
    if not HANDLE_RE.fullmatch(handle):
        raise IdentityError(f"handle {handle!r} violates [a-z0-9-]{{3,32}}")
    private = _load_private()
    return _signed(
        {
            "schema_version": RECORD_SCHEMA_VERSION,
            "type": "handle-binding",
            "identity_id": identity_id_for(_raw_pub(private)),
            "handle": handle,
            "seq": seq,
            "date": date,
        },
        private,
    )


def device_binding_record(device_pub_hex: str, date: str, scope: str = "active") -> dict:
    """Bind a device key to the identity. scope="retroactive" additionally
    claims anchors previously signed by this device key for this identity."""
    if scope not in ("active", "retroactive"):
        raise IdentityError(f"unknown binding scope {scope!r}")
    if len(bytes.fromhex(device_pub_hex)) != 32:
        raise IdentityError("device_pub must be a raw 32-byte Ed25519 key, hex")
    private = _load_private()
    return _signed(
        {
            "schema_version": RECORD_SCHEMA_VERSION,
            "type": "device-binding",
            "identity_id": identity_id_for(_raw_pub(private)),
            "device_pub": device_pub_hex,
            "scope": scope,
            "date": date,
        },
        private,
    )
