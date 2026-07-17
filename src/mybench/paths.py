"""Filesystem locations for mybench — the single source of truth for the data dir.

Privacy invariant #2: nonces and the ledger live in a dedicated local data
directory (mode 0700, OUTSIDE all repos), never in any repo, test output, or
logs. No other module may construct data paths (test-enforced).

Layout under the data dir (ADR-0001 §5, ADR-0002 §§4–5):
    nonces/       per-session nonce files (0600)      — asset A2
    ledger/       hash-chained ledger                 — asset A3
    normalized/   content-free normalized artifacts   — asset A8
    archive/      byte-exact transcript preimages     — asset A9
    reports/      private local report artifacts       — asset A10
    scan-config.json confirmed local scan locations (0600)
    scan-health.json successful scan times + opaque source ids (0600)
    scan-health.lock serializes health receipt replacement (0600)
    schedule.json  scheduler backend + last scheduled result (0600)
    schedule.lock  serializes schedule receipt replacement (0600)
    queue/        whitelisted hook tuples (0600)       — asset A3 ingress
    capture.lock  whole-scan daemon flock (0600)
    keys/         device.key (0600) / device.pub      — Ed25519 device identity
    anchors/      staged anchor artifacts + OTS proofs pre-publication
    enrollments/  per-repo commit-binding enrollment records (MYB-3.7)
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_DIR_MODE = 0o700
_KEY_MODE = 0o600
# Permission bits that must NOT be set on data dirs/keys (group/other access).
_LOOSE_BITS = 0o077
ARCHIVE_SOURCES = ("claude-code", "codex", "synthetic")
_OPAQUE_SESSION_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_CORPUS_COMMITMENT_RE = re.compile(r"[0-9a-f]{64}")
_REPORT_ID_RE = re.compile(r"[0-9a-f]{64}")
_DURABLE_DIRS: set[tuple[str, int, int]] = set()
_DURABLE_ROOT_CHAINS: set[tuple[str, int, int]] = set()
XDG_DATA_HOME_ENV = "XDG_DATA_HOME"


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
    base = os.environ.get(XDG_DATA_HOME_ENV) or (Path.home() / ".local" / "share")
    return Path(base) / "mybench"


def configured_data_home() -> Path | None:
    """Explicit scheduler environment needed to reproduce :func:`data_dir`."""
    raw = os.environ.get(XDG_DATA_HOME_ENV)
    return Path(raw).expanduser().absolute() if raw else None


def data_home_environment_name() -> str:
    """Return the environment name whose value selects the data-dir root."""
    return XDG_DATA_HOME_ENV


def nonces_dir() -> Path:
    return data_dir() / "nonces"


def ledger_dir() -> Path:
    return data_dir() / "ledger"


def normalized_dir() -> Path:
    """A8 root: parser-versioned, content-free normalized artifacts."""
    return data_dir() / "normalized"


def normalized_corpus_dir(commitment: str) -> Path:
    """Return one content-addressed A8 corpus directory without creating it."""
    if not isinstance(commitment, str) or not _CORPUS_COMMITMENT_RE.fullmatch(commitment):
        raise PathsError("invalid normalized corpus commitment")
    return normalized_dir() / commitment


def normalized_corpus_path(commitment: str) -> Path:
    """Return the canonical artifact path for one validated A8 commitment."""
    return normalized_corpus_dir(commitment) / "corpus.json"


def archive_dir() -> Path:
    """A9 root: local-only, session-addressed transcript preimages."""
    return data_dir() / "archive"


def reports_dir() -> Path:
    """A10 root: private local reports that are never published implicitly."""
    return data_dir() / "reports"


def scan_config_path() -> Path:
    """Confirmed local source locations and exclusions (0600, private)."""
    return data_dir() / "scan-config.json"


def scan_health_path() -> Path:
    """Successful-scan receipt with opaque location fingerprints (0600)."""
    return data_dir() / "scan-health.json"


def scan_health_lock_path() -> Path:
    """Writer lock for atomic scan-health receipt updates (0600)."""
    return data_dir() / "scan-health.lock"


def schedule_path() -> Path:
    """Scheduler registration and last-run health state (0600, private)."""
    return data_dir() / "schedule.json"


def schedule_lock_path() -> Path:
    """Writer lock for atomic scheduler-state replacement (0600)."""
    return data_dir() / "schedule.lock"


def report_dir(report_id: str) -> Path:
    """Return one content-addressed private report directory without creating it."""
    if not isinstance(report_id, str) or not _REPORT_ID_RE.fullmatch(report_id):
        raise PathsError("invalid local report id")
    return reports_dir() / report_id


def queue_dir() -> Path:
    """Private ingress queue for already-whitelisted capture observations."""
    return data_dir() / "queue"


def claude_lifecycle_queue_path() -> Path:
    return queue_dir() / "claude-lifecycle.jsonl"


def claude_lifecycle_failure_path() -> Path:
    return queue_dir() / "claude-lifecycle.failures"


def archive_source_dir(source: str) -> Path:
    if source not in ARCHIVE_SOURCES:
        raise PathsError(f"unknown archive source {source!r}")
    return archive_dir() / source


def archive_session_path(source: str, session_id: str) -> Path:
    """Return the A9 path without creating it; both components are closed-set/opaque."""
    if not _OPAQUE_SESSION_ID_RE.fullmatch(session_id):
        raise PathsError("invalid opaque archive session id")
    return archive_source_dir(source) / session_id


def capture_scan_lock_path() -> Path:
    """Global daemon-scan lock; serializes A2/A3/A9 reconciliation."""
    return data_dir() / "capture.lock"


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


def load_device_key() -> Ed25519PrivateKey:
    """Ensure + load the device private key in one step (MYB-10.1).

    The one shared loader for signers — ensure_device_key already parses and
    type-checks the PEM; per-call-site reloads (anchor batch/event, claims)
    should converge here so key-format changes (MYB-8.11 rotation ADR) have
    one seam.
    """
    key_path, _ = ensure_device_key()
    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise PathsError(f"{key_path} is not an Ed25519 private key")
    return private


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
    # Check both the configured spelling and its resolved destination.  An
    # XDG/data-dir symlink must not bypass the repository-containment guard.
    candidates = {d.absolute(), d.resolve()}
    for candidate in candidates:
        for p in (candidate, *candidate.parents):
            if _is_worktree_root(p):
                raise DataDirInsideRepoError(
                    f"refusing to use data dir {d}: inside git worktree at {p} "
                    "(invariant #2)"
                )


def _assert_tight(p: Path, allowed_bits: int) -> None:
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode & _LOOSE_BITS:
        raise InsecurePermissionsError(
            f"{p} has mode {mode:04o} (group/other access); expected {allowed_bits:04o}. "
            f"Not auto-repairing — verify nothing leaked, then: chmod {allowed_bits:o} {p}"
        )


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _directory_key(directory: Path) -> tuple[str, int, int]:
    info = directory.stat()
    return (str(directory.absolute()), info.st_dev, info.st_ino)


def _durable_chain_root() -> Path:
    """Topmost ancestor whose entries mybench must persist: the data-home base.

    The data dir is always ``<base>/mybench`` (see :func:`data_dir`), so
    fsyncing from the leaf up to and including ``base`` persists every directory
    mybench itself creates. Nothing above ``base`` is mybench's to create, and
    those ancestors up to ``/`` may be unopenable under sandboxing — e.g. a
    systemd unit with ``PrivateTmp=`` makes ``os.open("/")`` raise ``EACCES`` —
    so the durability walk must stop here rather than ascend to the root.
    """
    base = os.environ.get(XDG_DATA_HOME_ENV) or (Path.home() / ".local" / "share")
    return Path(base).absolute()


def _ensure_root_chain_durable(d: Path) -> None:
    """Repair a possibly interrupted data-root mkdir from leaf up to the base."""
    key = _directory_key(d)
    if key in _DURABLE_ROOT_CHAINS:
        return
    absolute = d.absolute()
    root = _durable_chain_root()
    for directory in (absolute, *absolute.parents):
        _fsync_directory(directory)
        if directory == root:
            break
    _DURABLE_ROOT_CHAINS.add(key)


def _ensure_dir(d: Path) -> Path:
    if d.is_symlink():
        raise PathsError("refusing symlinked managed data directory")
    existed = d.is_dir()
    missing = []
    cursor = d.absolute()
    while not cursor.exists():
        if cursor.is_symlink():
            raise PathsError("refusing symlinked managed data-directory component")
        missing.append(cursor)
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    d.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    if existed:
        _assert_tight(d, _DIR_MODE)
    else:
        os.chmod(d, _DIR_MODE)  # mkdir mode is subject to umask
        # Persist each newly created directory entry from leaf to the first
        # pre-existing ancestor. This makes a fresh data-dir bootstrap durable,
        # rather than assuming XDG/mybench was provisioned before capture.
        for directory in (*missing, cursor):
            _fsync_directory(directory)
    key = _directory_key(d)
    if key not in _DURABLE_DIRS:
        if existed:
            # A previous process may have completed mkdir/chmod but died before
            # its directory fsync. Re-establish that barrier once per process.
            _fsync_directory(d)
        _DURABLE_DIRS.add(key)
    return d


def ensure_data_dir() -> Path:
    """Create (or validate) the data dir tree; refuse repos and loose perms."""
    d = data_dir()
    _assert_not_in_repo(d)
    _ensure_dir(d)
    for sub in (
        nonces_dir(),
        ledger_dir(),
        archive_dir(),
        reports_dir(),
        queue_dir(),
        keys_dir(),
        anchors_dir(),
        enrollments_dir(),
    ):
        _ensure_dir(sub)
    _ensure_root_chain_durable(d)
    return d


def ensure_archive_source_dir(source: str) -> Path:
    """Create/validate one 0700 source namespace below the A9 archive root."""
    ensure_data_dir()
    return _ensure_dir(archive_source_dir(source))


def ensure_reports_dir() -> Path:
    """Create/validate the 0700 A10 local-report root."""
    ensure_data_dir()
    return _ensure_dir(reports_dir())


def ensure_report_dir(report_id: str) -> Path:
    """Create/validate one 0700 content-addressed local-report directory."""
    directory = report_dir(report_id)
    ensure_reports_dir()
    return _ensure_dir(directory)


def ensure_queue_dir() -> Path:
    """Create/validate the 0700 hook-ingress queue below the private data dir."""
    ensure_data_dir()
    return _ensure_dir(queue_dir())


def ensure_normalized_dir() -> Path:
    """Create/validate the 0700 A8 normalized-artifact root lazily."""
    ensure_data_dir()
    return _ensure_dir(normalized_dir())


def ensure_normalized_corpus_dir(commitment: str) -> Path:
    """Create/validate one 0700 content-addressed A8 corpus directory."""
    corpus_dir = normalized_corpus_dir(commitment)
    ensure_normalized_dir()
    return _ensure_dir(corpus_dir)


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
