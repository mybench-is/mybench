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
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date as calendar_date
from pathlib import Path
from typing import Iterator

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


@dataclass(frozen=True)
class _OpenedDirectory:
    fd: int
    parent_fd: int | None
    name: str | None
    opened: os.stat_result
    policy: str


_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _directory_invariant(info: os.stat_result, policy: str) -> tuple[int, ...]:
    base = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
    if policy == "anchor":
        return base
    return base + (info.st_mode, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def _validate_opened_directory(opened: _OpenedDirectory) -> None:
    try:
        current = os.fstat(opened.fd)
        if not stat.S_ISDIR(current.st_mode) or _directory_invariant(
            current, opened.policy
        ) != _directory_invariant(opened.opened, opened.policy):
            raise _invalid_state()
        if opened.policy == "private" and stat.S_IMODE(current.st_mode) != 0o700:
            raise _invalid_state()
        if opened.parent_fd is not None and opened.name is not None:
            linked = os.stat(opened.name, dir_fd=opened.parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(linked.st_mode)
                or stat.S_ISLNK(linked.st_mode)
                or (linked.st_dev, linked.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise _invalid_state()
    except IdentityError:
        raise
    except OSError as exc:
        raise _invalid_state() from exc


def _open_child_directory(
    opened: list[_OpenedDirectory], parent_fd: int, name: str, *, policy: str
) -> _OpenedDirectory:
    try:
        fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        info = os.fstat(fd)
        child = _OpenedDirectory(fd, parent_fd, name, info, policy)
        _validate_opened_directory(child)
        opened.append(child)
        return child
    except IdentityError:
        if "fd" in locals():
            os.close(fd)
        raise
    except OSError as exc:
        if "fd" in locals():
            os.close(fd)
        raise _invalid_state() from exc


@contextmanager
def _open_absolute_directory(
    directory: Path, *, final_policy: str
) -> Iterator[tuple[_OpenedDirectory, list[_OpenedDirectory]]]:
    absolute = directory.absolute()
    parts = absolute.parts
    if not parts or parts[0] != absolute.anchor or any(part in {"", ".", ".."} for part in parts[1:]):
        raise _invalid_state()
    opened: list[_OpenedDirectory] = []
    try:
        root_fd = os.open(absolute.anchor, _DIRECTORY_FLAGS)
        root = _OpenedDirectory(root_fd, None, None, os.fstat(root_fd), "anchor")
        opened.append(root)
        current = root
        for index, part in enumerate(parts[1:]):
            policy = final_policy if index == len(parts[1:]) - 1 else "anchor"
            current = _open_child_directory(opened, current.fd, part, policy=policy)
        yield current, opened
        for item in reversed(opened):
            _validate_opened_directory(item)
    except IdentityError:
        raise
    except OSError as exc:
        raise _invalid_state() from exc
    finally:
        for item in reversed(opened):
            try:
                os.close(item.fd)
            except OSError:
                pass


def _file_invariant(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_file_at(directory_fd: int, name: str, *, private: bool) -> tuple[bytes, tuple[int, int]]:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NOATIME", 0)
        fd = os.open(name, flags, dir_fd=directory_fd)
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (private and stat.S_IMODE(opened.st_mode) != 0o600)
                or opened.st_size <= 0
                or opened.st_size > _MAX_RECORD_BYTES
            ):
                raise _invalid_state()
            raw = b""
            while len(raw) <= _MAX_RECORD_BYTES:
                chunk = os.read(fd, _MAX_RECORD_BYTES + 1 - len(raw))
                if not chunk:
                    break
                raw += chunk
            current = os.fstat(fd)
            linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                len(raw) > _MAX_RECORD_BYTES
                or not stat.S_ISREG(linked.st_mode)
                or stat.S_ISLNK(linked.st_mode)
                or _file_invariant(current) != _file_invariant(opened)
                or (linked.st_dev, linked.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise _invalid_state()
        finally:
            os.close(fd)
    except IdentityError:
        raise
    except OSError as exc:
        raise _invalid_state() from exc
    return raw, (opened.st_atime_ns, opened.st_mtime_ns)


def _managed_record_bytes(identity_id: str) -> tuple[tuple[str, bytes], ...]:
    with _open_absolute_directory(paths.data_dir(), final_policy="private") as (
        data,
        opened,
    ):
        state_root = _open_child_directory(opened, data.fd, "identity", policy="private")
        records_root = _open_child_directory(
            opened, state_root.fd, "records", policy="private"
        )
        roots = tuple(sorted(os.listdir(records_root.fd)))
        if roots != (identity_id,):
            raise _invalid_state()
        identity_root = _open_child_directory(
            opened, records_root.fd, identity_id, policy="private"
        )
        entries = tuple(sorted(os.listdir(identity_root.fd)))
        if not entries:
            raise _invalid_state()
        return tuple(
            (name, _read_file_at(identity_root.fd, name, private=True)[0]) for name in entries
        )


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
    with _open_absolute_directory(paths.data_dir(), final_policy="private") as (
        data,
        opened,
    ):
        data_entries = set(os.listdir(data.fd))
        if "identity" not in data_entries:
            return True
        state_root = _open_child_directory(opened, data.fd, "identity", policy="private")
        if tuple(sorted(os.listdir(state_root.fd))) != ("records",):
            raise _invalid_state()
        records_root = _open_child_directory(
            opened, state_root.fd, "records", policy="private"
        )
        roots = tuple(sorted(os.listdir(records_root.fd)))
        if not roots:
            return True
        if identity_id in roots:
            return False
        raise _invalid_state()


def _retryable_bootstrap_state() -> bool:
    """Recognize only the exact footprint left by an interrupted record install.

    Older key-only installations have all four key roles but no empty A11
    hierarchy; any evidence/config/anchor data or unexpected entry also makes
    this false. That distinction prevents a founder-era identity from silently
    receiving replacement chronology while allowing our own cleaned atomic
    install failure to resume.
    """
    expected_empty = {
        "anchors",
        "archive",
        "enrollments",
        "ledger",
        "nonces",
        "queue",
        "reports",
    }
    try:
        with _open_absolute_directory(paths.data_dir(), final_policy="private") as (
            data,
            opened,
        ):
            if set(os.listdir(data.fd)) != {*expected_empty, "identity", "keys"}:
                return False
            for name in sorted(expected_empty):
                directory = _open_child_directory(opened, data.fd, name, policy="private")
                if os.listdir(directory.fd):
                    return False
            keys = _open_child_directory(opened, data.fd, "keys", policy="private")
            key_names = {"device.key", "device.pub", "identity.key", "identity.pub"}
            if set(os.listdir(keys.fd)) != key_names:
                return False
            for name in sorted(key_names):
                _read_file_at(keys.fd, name, private=name.endswith(".key"))
            state_root = _open_child_directory(opened, data.fd, "identity", policy="private")
            if tuple(os.listdir(state_root.fd)) != ("records",):
                return False
            records = _open_child_directory(opened, state_root.fd, "records", policy="private")
            return not os.listdir(records.fd)
    except (IdentityError, OSError):
        return False


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


def _legacy_record_files(
    clone: Path, identity_id: str, current_device_pub: str
) -> tuple[tuple[str, bytes, tuple[int, int]], ...]:
    with _open_absolute_directory(Path(clone), final_policy="stable") as (
        clone_root,
        opened,
    ):
        identities = _open_child_directory(
            opened, clone_root.fd, "identities", policy="stable"
        )
        source = _open_child_directory(opened, identities.fd, identity_id, policy="stable")
        entries = tuple(sorted(os.listdir(source.fd)))
        if len(entries) != 3:
            raise _invalid_state()
        loaded = tuple(
            (name, *_read_file_at(source.fd, name, private=False)) for name in entries
        )
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
    if not fresh_install and not _retryable_bootstrap_state():
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
