"""Canary leak scanner — the enforcement mechanism for privacy invariant #1.

``assert_no_canaries(paths, canaries)`` scans artifact files for each canary
in raw form and common encodings (hex upper/lower, base64 at all three byte
phases, and inside gzip streams). Every test that writes artifacts runs its
outputs through this, and the anchor publisher's mandatory pre-push gate
(MYB-3.4) runs it in production against the local secret corpus (stored
nonces + key material) on the exact staged bytes.
"""

from __future__ import annotations

import base64
import zlib
from pathlib import Path

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


def scan_file(path: Path, canaries: list[bytes]) -> list[str]:
    data = path.read_bytes()
    hits = []
    for where, stack in _haystacks(data):
        for canary in canaries:
            for encoding, needle in _needles(canary):
                if needle in stack:
                    hits.append(f"{path}: {where}{encoding} form of canary {canary[:12]!r}…")
                    break  # one hit per (haystack, canary) is enough detail
    return hits


def assert_no_canaries(paths: list[Path] | list[str], canaries: list[bytes]) -> int:
    """Scan files (dirs recurse) for canaries; raise CanaryLeakError on any hit.

    Returns the number of files scanned; raises ValueError if nothing was
    scanned or no canaries were given — a vacuous scan must never pass green.
    """
    if not canaries:
        raise ValueError("no canaries given — refusing a vacuous scan")
    files: list[Path] = []
    for p in map(Path, paths):
        files.extend(f for f in (p.rglob("*") if p.is_dir() else [p]) if f.is_file())
    if not files:
        raise ValueError(f"no files to scan under {list(map(str, paths))} — vacuous scan")
    hits = [hit for f in sorted(files) for hit in scan_file(f, canaries)]
    if hits:
        raise CanaryLeakError(
            "canary content found in published artifacts (invariant #1):\n  " + "\n  ".join(hits)
        )
    return len(files)
