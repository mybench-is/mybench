"""Canary leak scanner — the enforcement mechanism for privacy invariant #1.

``assert_no_canaries(paths, canaries)`` scans artifact file names and bytes for
each canary in raw form and common encodings (hex upper/lower, base64 at all
three byte phases, and inside gzip streams).  Paths may be whole report or
preview directories and recurse through every file. Every test that writes
artifacts runs its outputs through this, and the anchor publisher's mandatory
pre-push gate (MYB-3.4) runs it in production against the local secret corpus
(stored nonces + key material) on the exact staged bytes.
"""

from __future__ import annotations

import base64
import json
import zlib
from pathlib import Path

from mybench import paths as mybench_paths

GZIP_MAGIC = b"\x1f\x8b"


class CanaryLeakError(AssertionError):
    """A canary (or an encoding of it) was found in a published artifact."""


def _b64_needles(data: bytes) -> list[bytes]:
    """Substrings that must appear if ``data`` is embedded in any base64 stream.

    A canary inside a larger base64-encoded stream is encoded at one of three
    byte phases; for each phase we compute the encoding with a synthetic
    prefix and trim the boundary blocks that depend on surrounding bytes.
    """
    needles = []
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        for phase in range(3):
            enc = encode(bytes(phase) + data)
            start = 4 if phase else 0  # first block blends with the prefix
            trimmed = enc[start:-4]  # last block blends with suffix/padding
            if trimmed:
                needles.append(trimmed)
    return needles


def _needles(canary: bytes) -> list[tuple[str, bytes]]:
    hexed = canary.hex()
    return [
        ("raw", canary),
        ("hex", hexed.encode()),
        ("HEX", hexed.upper().encode()),
        *[("base64", n) for n in _b64_needles(canary)],
    ]


def _haystacks(data: bytes) -> list[tuple[str, bytes]]:
    """The raw bytes plus every decodable gzip stream embedded in them."""
    stacks = [("", data)]
    off = data.find(GZIP_MAGIC)
    while off != -1:
        try:
            # zlib wbits=31 = gzip container; decompressobj tolerates trailing bytes.
            out = zlib.decompressobj(wbits=31).decompress(data[off:])
            if out:
                stacks.append((f"gzip@{off}:", out))
        except zlib.error:
            pass  # magic false-positive or corrupt stream: raw scan still applies
        off = data.find(GZIP_MAGIC, off + 1)
    return stacks


def scan_file(
    path: Path,
    canaries: list[bytes],
    *,
    label: Path | str | None = None,
) -> list[str]:
    """Scan one file's bytes, using an optional safe diagnostic label."""
    data = path.read_bytes()
    diagnostic_label = path if label is None else Path(label)
    hits = []
    for where, stack in _haystacks(data):
        for canary_index, canary in enumerate(canaries):
            for encoding, needle in _needles(canary):
                if needle in stack:
                    hits.append(
                        f"{diagnostic_label}: {where}{encoding} form of secret "
                        f"corpus item {canary_index}"
                    )
                    break  # one hit per (haystack, canary) is enough detail
    return hits


def _redacted_path_label(bundle_path: Path, needle: bytes) -> Path:
    """Return a useful relative label without echoing a canary-bearing name."""
    parts = []
    redacted = False
    for part in bundle_path.parts:
        if needle in part.encode(errors="surrogateescape"):
            parts.append("<redacted-canary-name>")
            redacted = True
        else:
            parts.append(part)
    if not redacted:
        return Path("<redacted-canary-path>")
    return Path(*parts)


def _scan_path(bundle_path: Path, canaries: list[bytes]) -> list[str]:
    """Scan a bundle-relative path without treating its private parent as output."""
    path_bytes = str(bundle_path).encode(errors="surrogateescape")
    hits = []
    for canary_index, canary in enumerate(canaries):
        for encoding, needle in _needles(canary):
            if needle in path_bytes:
                safe_label = _redacted_path_label(bundle_path, needle)
                hits.append(
                    f"{safe_label}: path:{encoding} form of secret corpus item {canary_index}"
                )
                break
    return hits


def local_secret_corpus() -> list[bytes]:
    """Load this machine's nonce and private-key bytes without logging values.

    The corpus is intentionally assembled only inside the mode-0700 data dir.
    Public-key files are excluded; all other regular key files and every stored
    nonce are negative needles for an exact-byte publication gate.
    """

    corpus: list[bytes] = []
    nonces = mybench_paths.nonces_dir()
    if nonces.is_dir():
        for nonce_file in sorted(nonces.glob("*.jsonl")):
            for line in nonce_file.read_bytes().splitlines():
                try:
                    corpus.append(bytes.fromhex(json.loads(line)["nonce"]))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError("local nonce corpus is malformed") from exc
    keys = mybench_paths.keys_dir()
    if keys.is_dir():
        for key_file in sorted(keys.iterdir()):
            if key_file.is_file() and key_file.suffix != ".pub":
                corpus.append(key_file.read_bytes())
    return corpus


def assert_no_canaries(paths: list[Path] | list[str], canaries: list[bytes]) -> int:
    """Scan files (dirs recurse) for canaries; raise CanaryLeakError on any hit.

    Returns the number of files scanned; raises ValueError if nothing was
    scanned or no canaries were given — a vacuous scan must never pass green.
    """
    if not canaries:
        raise ValueError("no canaries given — refusing a vacuous scan")
    files: list[tuple[Path, Path]] = []
    path_hits: list[str] = []
    for p in map(Path, paths):
        if p.is_dir():
            for entry in (p, *sorted(p.rglob("*"))):
                relative = Path(".") if entry == p else entry.relative_to(p)
                path_hits.extend(_scan_path(relative, canaries))
                if entry.is_file():
                    files.append((entry, relative))
        else:
            relative = Path(p.name)
            path_hits.extend(_scan_path(relative, canaries))
            if p.is_file():
                files.append((p, relative))
    if not files:
        raise ValueError(f"no files to scan under {list(map(str, paths))} — vacuous scan")
    hits = path_hits + [
        hit
        for file_path, relative in sorted(files)
        for hit in scan_file(file_path, canaries, label=relative)
    ]
    if hits:
        raise CanaryLeakError(
            "canary data found in published artifacts (invariant #1):\n  " + "\n  ".join(hits)
        )
    return len(files)


def assert_no_canaries_in_directory(directory: Path | str, canaries: list[bytes]) -> int:
    """Scan one complete report/preview directory, refusing non-directories.

    This named helper makes the whole-bundle privacy gate hard to accidentally
    replace with a partial file list.  It delegates encoding and vacuous-scan
    behavior to :func:`assert_no_canaries`.
    """
    root = Path(directory)
    if not root.is_dir():
        raise ValueError(f"not a directory to scan: {root}")
    return assert_no_canaries([root], canaries)
