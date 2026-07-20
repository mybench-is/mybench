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
import os
import re
import secrets
import stat
from datetime import date as calendar_date
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mybench import paths

DOMAIN_IDENTITY = b"mybench:v1:identity"
HANDLE_RE = re.compile(r"^[a-z0-9-]{3,32}$")
RECORD_SCHEMA_VERSION = "1"
_IDENTITY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")
_MAX_RECORD_BYTES = 16 * 1024
_LOCAL_STATE_ERROR = "local identity state is invalid"


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


def record_bytes(record: dict) -> bytes:
    """Return the one admitted canonical encoding for an identity record."""
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"


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


def _invalid_state() -> IdentityError:
    # This error deliberately carries no identity, path, filename, record byte,
    # or key detail. CLI callers must be able to report every failure safely.
    return IdentityError(_LOCAL_STATE_ERROR)


def _valid_date(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 10:
        return False
    try:
        return calendar_date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _parse_canonical_record(raw: bytes) -> dict:
    if not raw or len(raw) > _MAX_RECORD_BYTES:
        raise _invalid_state()
    try:
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _invalid_state() from exc
    if not isinstance(record, dict) or record_bytes(record) != raw:
        raise _invalid_state()

    record_type = record.get("type")
    common = {"schema_version", "type", "identity_id", "date", "sig"}
    fields = {
        "genesis": common | {"identity_pub"},
        "handle-binding": common | {"handle", "seq"},
        "device-binding": common | {"device_pub", "scope"},
    }
    if record_type not in fields or set(record) != fields[record_type]:
        raise _invalid_state()
    if (
        record.get("schema_version") != RECORD_SCHEMA_VERSION
        or not isinstance(record.get("identity_id"), str)
        or not _IDENTITY_ID_RE.fullmatch(record["identity_id"])
        or not _valid_date(record.get("date"))
        or not isinstance(record.get("sig"), str)
        or not _SIGNATURE_RE.fullmatch(record["sig"])
    ):
        raise _invalid_state()
    if record_type == "genesis":
        if not isinstance(record.get("identity_pub"), str) or not _PUBLIC_KEY_RE.fullmatch(
            record["identity_pub"]
        ):
            raise _invalid_state()
    elif record_type == "handle-binding":
        seq = record.get("seq")
        if (
            not isinstance(record.get("handle"), str)
            or not HANDLE_RE.fullmatch(record["handle"])
            or not isinstance(seq, int)
            or isinstance(seq, bool)
            or not 0 <= seq <= 9999
        ):
            raise _invalid_state()
    else:
        if (
            not isinstance(record.get("device_pub"), str)
            or not _PUBLIC_KEY_RE.fullmatch(record["device_pub"])
            or record.get("scope") not in {"active", "retroactive"}
        ):
            raise _invalid_state()
    return record


def _validate_chain(
    named_bytes: tuple[tuple[str, bytes], ...],
    *,
    identity_id: str,
    current_device_pub: str,
    founder_exact: bool = False,
) -> tuple[dict, ...]:
    parsed: list[tuple[str, dict]] = []
    for name, raw in named_bytes:
        record = _parse_canonical_record(raw)
        record_type = record["type"]
        if record_type == "genesis":
            canonical_name = "genesis.json"
        elif record_type == "handle-binding":
            canonical_name = f"handle-{record['seq']:04d}.json"
        else:
            canonical_name = f"device-{record['device_pub'][:8]}.json"
        if name != canonical_name:
            raise _invalid_state()
        parsed.append((name, record))

    genesis = [record for _name, record in parsed if record["type"] == "genesis"]
    if len(genesis) != 1:
        raise _invalid_state()
    root = genesis[0]
    try:
        if (
            root["identity_id"] != identity_id
            or identity_id_for(bytes.fromhex(root["identity_pub"])) != identity_id
        ):
            raise _invalid_state()
        for _name, record in parsed:
            if record["identity_id"] != identity_id:
                raise _invalid_state()
            verify_record(record, root["identity_pub"])
    except (IdentityError, KeyError, TypeError, ValueError) as exc:
        raise _invalid_state() from exc

    handle_records = [record for _name, record in parsed if record["type"] == "handle-binding"]
    device_records = [record for _name, record in parsed if record["type"] == "device-binding"]
    if len({record["seq"] for record in handle_records}) != len(handle_records):
        raise _invalid_state()
    if len({record["device_pub"] for record in device_records}) != len(device_records):
        raise _invalid_state()
    current = [record for record in device_records if record["device_pub"] == current_device_pub]
    if len(current) != 1:
        raise _invalid_state()

    ordered_handles = sorted(handle_records, key=lambda item: item["seq"])
    if any(record["date"] < root["date"] for record in (*handle_records, *device_records)):
        raise _invalid_state()
    if any(
        earlier["date"] > later["date"]
        for earlier, later in zip(ordered_handles, ordered_handles[1:], strict=False)
    ):
        raise _invalid_state()
    if founder_exact and (
        len(parsed) != 3
        or len(handle_records) != 1
        or handle_records[0]["seq"] != 0
        or len(device_records) != 1
        or device_records[0]["scope"] != "retroactive"
        or not root["date"] <= handle_records[0]["date"] <= device_records[0]["date"]
    ):
        raise _invalid_state()

    order = {"genesis": 0, "handle-binding": 1, "device-binding": 2}
    return tuple(
        record
        for _name, record in sorted(
            parsed,
            key=lambda item: (
                order[item[1]["type"]],
                item[1].get("seq", 0),
                item[0],
            ),
        )
    )


def _device_public_hex() -> str:
    _key_path, pub_path = paths.ensure_device_key()
    try:
        public = serialization.load_pem_public_key(pub_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise _invalid_state() from exc
    if not isinstance(public, Ed25519PublicKey):
        raise _invalid_state()
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _checked_private_directory(directory: Path) -> None:
    try:
        info = directory.lstat()
    except OSError as exc:
        raise _invalid_state() from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise _invalid_state()


def _read_file(path: Path, *, private: bool) -> tuple[bytes, tuple[int, int]]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or (private and stat.S_IMODE(before.st_mode) != 0o600)
            or before.st_size <= 0
            or before.st_size > _MAX_RECORD_BYTES
        ):
            raise _invalid_state()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NOATIME", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise _invalid_state()
            raw = b""
            while len(raw) <= _MAX_RECORD_BYTES:
                chunk = os.read(fd, _MAX_RECORD_BYTES + 1 - len(raw))
                if not chunk:
                    break
                raw += chunk
            after = os.fstat(fd)
            if (
                len(raw) > _MAX_RECORD_BYTES
                or (after.st_dev, after.st_ino, after.st_size)
                != (opened.st_dev, opened.st_ino, opened.st_size)
            ):
                raise _invalid_state()
        finally:
            os.close(fd)
    except IdentityError:
        raise
    except OSError as exc:
        raise _invalid_state() from exc
    return raw, (before.st_atime_ns, before.st_mtime_ns)


def _managed_record_bytes(identity_id: str) -> tuple[tuple[str, bytes], ...]:
    state_root = paths.identity_state_dir()
    records_root = paths.identity_records_dir()
    identity_root = paths.identity_record_dir(identity_id)
    for directory in (state_root, records_root, identity_root):
        _checked_private_directory(directory)
    try:
        roots = tuple(records_root.iterdir())
        entries = tuple(identity_root.iterdir())
    except OSError as exc:
        raise _invalid_state() from exc
    if len(roots) != 1 or roots[0].name != identity_id or roots[0].is_symlink():
        raise _invalid_state()
    if not entries:
        raise _invalid_state()
    return tuple((entry.name, _read_file(entry, private=True)[0]) for entry in sorted(entries))


def load_local_identity_chain() -> tuple[dict, ...]:
    """Load and strictly verify the current device's canonical offline chain.

    This is the public consumer API for preview and later local signing flows.
    It never consults anchor staging, a Git clone, or the network, and it never
    rewrites valid state.
    """
    identity_id = local_identity_id()
    current_device_pub = _device_public_hex()
    return _validate_chain(
        _managed_record_bytes(identity_id),
        identity_id=identity_id,
        current_device_pub=current_device_pub,
    )


def _store_is_absent(identity_id: str) -> bool:
    state_root = paths.identity_state_dir()
    records_root = paths.identity_records_dir()
    identity_root = paths.identity_record_dir(identity_id)
    if identity_root.exists() or identity_root.is_symlink():
        return False
    for directory in (state_root, records_root):
        if directory.exists() or directory.is_symlink():
            _checked_private_directory(directory)
    if records_root.exists():
        try:
            if any(records_root.iterdir()):
                raise _invalid_state()
        except OSError as exc:
            raise _invalid_state() from exc
    return True


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(fd, content[offset:])
        if written <= 0:
            raise OSError("identity record write did not progress")
        offset += written


def _install_records(
    identity_id: str,
    files: tuple[tuple[str, bytes, tuple[int, int] | None], ...],
) -> None:
    records_root = paths.ensure_identity_records_dir()
    target = paths.identity_record_dir(identity_id)
    if target.exists() or target.is_symlink():
        raise _invalid_state()
    pending = records_root / f".pending-{secrets.token_hex(16)}"
    try:
        os.mkdir(pending, 0o700)
        os.chmod(pending, 0o700)
        for name, raw, timestamps in files:
            record_path = pending / name
            fd = os.open(
                record_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                _write_all(fd, raw)
                os.fchmod(fd, 0o600)
                if timestamps is not None:
                    os.utime(fd, ns=timestamps)
                os.fsync(fd)
            finally:
                os.close(fd)
        _fsync_directory(pending)
        os.rename(pending, target)
        _fsync_directory(records_root)
    except Exception:
        if pending.is_dir() and not pending.is_symlink():
            for child in pending.iterdir():
                if child.is_file() and not child.is_symlink():
                    child.unlink()
            pending.rmdir()
            _fsync_directory(records_root)
        raise


def _fresh_record_files(date: str) -> tuple[tuple[str, bytes, None], ...]:
    if not _valid_date(date):
        raise IdentityError("identity bootstrap date is invalid")
    device_pub = _device_public_hex()
    genesis = genesis_record(date)
    binding = device_binding_record(device_pub, date, scope="active")
    return (
        ("genesis.json", record_bytes(genesis), None),
        (f"device-{device_pub[:8]}.json", record_bytes(binding), None),
    )


def _assert_unsymlinked_directory(directory: Path) -> None:
    absolute = directory.absolute()
    for component in reversed((absolute, *absolute.parents)):
        try:
            info = component.lstat()
        except OSError as exc:
            raise _invalid_state() from exc
        if stat.S_ISLNK(info.st_mode):
            raise _invalid_state()
    try:
        info = absolute.lstat()
    except OSError as exc:
        raise _invalid_state() from exc
    if not stat.S_ISDIR(info.st_mode):
        raise _invalid_state()


def _legacy_record_files(
    clone: Path, identity_id: str, current_device_pub: str
) -> tuple[tuple[str, bytes, tuple[int, int]], ...]:
    clone = Path(clone)
    _assert_unsymlinked_directory(clone)
    identities = clone / "identities"
    source = identities / identity_id
    _assert_unsymlinked_directory(identities)
    _assert_unsymlinked_directory(source)
    try:
        entries = tuple(sorted(source.iterdir()))
    except OSError as exc:
        raise _invalid_state() from exc
    if len(entries) != 3:
        raise _invalid_state()
    loaded = tuple((entry.name, *_read_file(entry, private=False)) for entry in entries)
    _validate_chain(
        tuple((name, raw) for name, raw, _times in loaded),
        identity_id=identity_id,
        current_device_pub=current_device_pub,
        founder_exact=True,
    )
    return loaded


def migrate_founder_identity_records(legacy_clone: Path) -> tuple[dict, ...]:
    """Copy one exact, verified founder-era chain into A11 exactly once.

    The explicit clone is an input only. Once the canonical store exists, this
    function verifies it without reopening the clone, rewriting records, or
    changing any key.
    """
    identity_id = local_identity_id()
    current_device_pub = _device_public_hex()
    if not _store_is_absent(identity_id):
        return load_local_identity_chain()
    source = _legacy_record_files(Path(legacy_clone), identity_id, current_device_pub)
    _install_records(identity_id, source)
    return load_local_identity_chain()


def bootstrap_or_verify_local_identity(
    *,
    date: str,
    fresh_install: bool,
    legacy_clone: Path | None = None,
) -> tuple[dict, ...]:
    """Shared init path: verify, exact-migrate, or bootstrap fresh A11 state."""
    identity_id = local_identity_id()
    if not _store_is_absent(identity_id):
        return load_local_identity_chain()
    if legacy_clone is not None:
        return migrate_founder_identity_records(legacy_clone)
    if not fresh_install:
        raise IdentityError("local identity state needs an explicit founder migration")
    files = _fresh_record_files(date)
    current_device_pub = _device_public_hex()
    _validate_chain(
        tuple((name, raw) for name, raw, _timestamps in files),
        identity_id=identity_id,
        current_device_pub=current_device_pub,
    )
    _install_records(identity_id, files)
    return load_local_identity_chain()
