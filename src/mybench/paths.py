"""Filesystem locations for mybench — the single source of truth for the data dir.

Privacy invariant #2: nonces and the ledger live in a dedicated local data
directory (mode 0700, OUTSIDE all repos), never in any repo, test output, or
logs. No other module may construct data paths (test-enforced).

Layout under the data dir (ADR-0001 §5, ADR-0002 §§4–5):
    nonces/   per-session nonce files (0600)      — asset A2
    ledger/   hash-chained ledger                 — asset A3
    keys/     device.key (0600) / device.pub      — Ed25519 device identity
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_DIR_MODE = 0o700
_KEY_MODE = 0o600
# Permission bits that must NOT be set on data dirs/keys (group/other access).
_LOOSE_BITS = 0o077


class PathsError(RuntimeError):
    """Base error for data-dir bootstrap failures."""


class InsecurePermissionsError(PathsError):
    """An existing data path is group/other-accessible.

    Deliberately NOT auto-repaired (decided in MYB-2.1): loose permissions on
    A2/A3 may mean the secrets were already exposed — that event must surface
    to the owner, not be silently chmod-ed away.
    """


class DataDirInsideRepoError(PathsError):
    """The resolved data dir sits inside a git worktree (invariant #2)."""


def data_dir() -> Path:
    """Return the mybench local data directory (may not exist yet).

    Honors ``XDG_DATA_HOME``, falling back to ``~/.local/share``.
    """
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "mybench"


def nonces_dir() -> Path:
    return data_dir() / "nonces"


def ledger_dir() -> Path:
    return data_dir() / "ledger"


def keys_dir() -> Path:
    return data_dir() / "keys"


def anchors_dir() -> Path:
    """Staging area for anchor artifacts + OTS proofs before publication."""
    return data_dir() / "anchors"


def enrollments_dir() -> Path:
    """Per-repo commit-binding enrollment records (MYB-3.7).

    The enrollment point (HEAD at opt-in) is local-only state, so it lives
    here in the 0700 data dir — never in a repo, never in the ledger
    (invariant #2). Keyed by the opaque HMAC repo id, so the file name leaks
    no path either.
    """
    return data_dir() / "enrollments"


def enrollment_path(repo_id: str) -> Path:
    return enrollments_dir() / f"{repo_id}.json"


def device_key_path() -> Path:
    return keys_dir() / "device.key"


def device_pub_path() -> Path:
    return keys_dir() / "device.pub"


def session_scope_key_path() -> Path:
    return keys_dir() / "session-scope.key"


def commit_signing_key_path() -> Path:
    return keys_dir() / "log-signing"


def commit_signing_pub_path() -> Path:
    return keys_dir() / "log-signing.pub"


def ensure_commit_signing_key() -> tuple[Path, Path]:
    """SSH Ed25519 keypair that signs anchors-log git commits (ADR-0004 §6).

    The LOG-OPERATOR signature — distinct from user signatures inside anchor
    files and from the identity key. OpenSSH format because git's SSH
    signing consumes it directly. Register the .pub on the committing
    GitHub account for the Verified badge (owner UI step; noted in
    SETUP_TODO). Never overwritten.
    """
    ensure_data_dir()
    key_path, pub_path = commit_signing_key_path(), commit_signing_pub_path()
    if key_path.exists():
        _assert_tight(key_path, _KEY_MODE)
    else:
        private = Ed25519PrivateKey.generate()
        pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        pub = private.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _KEY_MODE)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        pub_path.write_bytes(pub + b" mybench-log-signer\n")
    return key_path, pub_path


def identity_key_path() -> Path:
    return keys_dir() / "identity.key"


def identity_pub_path() -> Path:
    return keys_dir() / "identity.pub"


def ensure_identity_key() -> tuple[Path, Path]:
    """Ensure the Ed25519 IDENTITY keypair exists (ADR-0004 §3); never overwrite.

    Distinct from the device key: the identity key signs bindings only
    (handle→ID, device→ID, succession) and its GENESIS public key's
    fingerprint is the permanent log namespace ID. After setup and backup it
    can be held offline — losing it (and its backup) is losing the namespace
    until the rotation/recovery ADR (MYB-8.11) exists.
    """
    ensure_data_dir()
    key_path, pub_path = identity_key_path(), identity_pub_path()

    if key_path.exists():
        _assert_tight(key_path, _KEY_MODE)
        private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise PathsError(f"{key_path} is not an Ed25519 private key")
    else:
        private = Ed25519PrivateKey.generate()
        pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _KEY_MODE)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)

    pub_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not pub_path.exists() or pub_path.read_bytes() != pub_pem:
        pub_path.write_bytes(pub_pem)
    return key_path, pub_path


def ensure_session_scope_key() -> bytes:
    """Random local key for the keyed session-id path disambiguator.

    ADR-0002 §4 amendment (2026-07-08): session ids may carry a keyed-HMAC
    suffix over the watch-relative path so files sharing a stem (nested
    subagent transcripts) get distinct identities; raw path components remain
    forbidden in ids. The key is a local-only secret: 32 bytes, 0600, never
    rotated or overwritten (rotation would orphan every nonce file name).
    """
    ensure_data_dir()
    p = session_scope_key_path()
    if p.exists():
        _assert_tight(p, _KEY_MODE)
        key = p.read_bytes()
        if len(key) != 32:
            raise PathsError(f"{p} is corrupt: expected 32 bytes, found {len(key)}")
        return key
    key = secrets.token_bytes(32)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _KEY_MODE)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def _is_worktree_root(p: Path) -> bool:
    git = p / ".git"
    # A dir with HEAD (worktree root) or a gitdir-pointer file (linked
    # worktree / submodule). Bare ".git" dirs without HEAD are junk, not repos.
    return git.is_file() or (git.is_dir() and (git / "HEAD").exists())


def _assert_not_in_repo(d: Path) -> None:
    for p in (d, *d.parents):
        if _is_worktree_root(p):
            raise DataDirInsideRepoError(
                f"refusing to use data dir {d}: inside git worktree at {p} (invariant #2)"
            )


def _assert_tight(p: Path, allowed_bits: int) -> None:
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode & _LOOSE_BITS:
        raise InsecurePermissionsError(
            f"{p} has mode {mode:04o} (group/other access); expected {allowed_bits:04o}. "
            f"Not auto-repairing — verify nothing leaked, then: chmod {allowed_bits:o} {p}"
        )


def _ensure_dir(d: Path) -> Path:
    existed = d.is_dir()
    d.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    if existed:
        _assert_tight(d, _DIR_MODE)
    else:
        os.chmod(d, _DIR_MODE)  # mkdir mode is subject to umask
    return d


def ensure_data_dir() -> Path:
    """Create (or validate) the data dir tree; refuse repos and loose perms."""
    d = data_dir()
    _assert_not_in_repo(d)
    _ensure_dir(d)
    for sub in (nonces_dir(), ledger_dir(), keys_dir(), anchors_dir(), enrollments_dir()):
        _ensure_dir(sub)
    return d


def ensure_device_key() -> tuple[Path, Path]:
    """Ensure the Ed25519 device keypair exists (ADR-0002 §5); never overwrite.

    Returns (private_key_path, public_key_path). Private key: PKCS#8 PEM,
    0600. Public key: SubjectPublicKeyInfo PEM, re-derivable from the private
    key (and re-derived if missing).
    """
    ensure_data_dir()
    key_path, pub_path = device_key_path(), device_pub_path()

    if key_path.exists():
        _assert_tight(key_path, _KEY_MODE)
        private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise PathsError(f"{key_path} is not an Ed25519 private key")
    else:
        private = Ed25519PrivateKey.generate()
        pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _KEY_MODE)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)

    pub_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not pub_path.exists() or pub_path.read_bytes() != pub_pem:
        pub_path.write_bytes(pub_pem)
    return key_path, pub_path
