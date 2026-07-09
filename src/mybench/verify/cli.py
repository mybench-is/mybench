"""Skeptic verify CLI (MYB-5.1): zero context, no trust in the owner required.

Input: a public anchors location (local clone path, or a git/https URL that
gets cloned to a temp dir). Checks, in order:

1. every artifact is schema-valid and device-signature-verified, all batches
   signed by the same device key;
2. anchor-chain continuity: contiguous, non-overlapping row ranges starting
   at row 0 (no gaps — deleted history would show here, ADV-6);
3. every artifact has its OTS proof, the proof binds exactly that artifact's
   root;
4. attestation status per anchor: "bitcoin-confirmed (height N)" vs
   "pending (calendar-attested, not yet Bitcoin-confirmed)" — never
   conflated (OQ #10: pending counts toward PASS, labeled);
5. online by default: block headers fetched from TWO independent public
   explorers (blockstream.info, mempool.space); both must agree, and the
   proof's commitment must equal the header's merkle root. ``--offline`` (or
   unreachable explorers) degrades honestly to "attested at height N —
   verify the header independently".

Role separation: this module never reads a ledger, nonce store, or data dir
— it consumes public artifacts only (test-enforced: runs with no data dir).
What this CANNOT check: that session roots correspond to any particular
content (that is what selective disclosure is for), or rows the owner never
anchored (mybench proves what happened, not that nothing else did).
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from mybench.anchor.batch import AnchorError, verify_batch
from mybench.anchor.ots import OtsError, proof_info

ARTIFACT_RE = re.compile(r"^anchor-\d{8}-\d{8}\.json$")
EXPLORERS = ("https://blockstream.info/api", "https://mempool.space/api")


def _fetch_json(url: str, timeout: float = 15.0):
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — pinned hosts
        return resp.read().decode()


def fetch_merkle_root(height: int, fetch=_fetch_json) -> str | None:
    """Block merkle root at height, agreed by both explorers; None if unreachable."""
    roots = set()
    for base in EXPLORERS:
        try:
            block_hash = fetch(f"{base}/block-height/{height}").strip()
            block = json.loads(fetch(f"{base}/block/{block_hash}"))
            roots.add(block["merkle_root"])
        except Exception:  # noqa: BLE001 — explorer down/unreachable
            return None
    if len(roots) != 1:
        raise VerifyFailure(f"explorers DISAGREE on block {height} merkle root")
    return roots.pop()


class VerifyFailure(Exception):
    pass


def _bitcoin_commitments(root: bytes, ots_bytes: bytes) -> list[tuple[int, bytes]]:
    """(height, commitment msg) pairs for every Bitcoin attestation in the proof."""
    import io

    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile

    dtf = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(ots_bytes)))
    return [
        (a.height, msg)
        for msg, a in dtf.timestamp.all_attestations()
        if isinstance(a, BitcoinBlockHeaderAttestation)
    ]


def _obtain(source: str, workdir: Path) -> Path:
    if Path(source).is_dir():
        return Path(source)
    clone = workdir / "anchors"
    proc = subprocess.run(
        ["git", "clone", "-q", "--depth", "1", source, str(clone)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise VerifyFailure(f"could not clone {source}: {proc.stderr.strip()}")
    return clone


def verify_anchors(source: str, *, check_bitcoin: bool = True, fetch=_fetch_json) -> dict:
    """Run all checks; returns {verdict, lines, failures, confirmed, pending}."""
    lines: list[str] = []
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        directory = _obtain(source, Path(tmp))
        artifacts = sorted(p for p in directory.iterdir() if ARTIFACT_RE.fullmatch(p.name))
        if not artifacts:
            raise VerifyFailure(f"no anchor artifacts found in {source}")

        batches, keys = [], set()
        for artifact in artifacts:
            try:
                batch = json.loads(artifact.read_bytes())
                verify_batch(batch)
            except (ValueError, AnchorError) as exc:
                failures.append(f"{artifact.name}: {exc}")
                continue
            keys.add(batch["device_pub"])
            batches.append((artifact, batch))
        if len(keys) > 1:
            failures.append(f"batches signed by {len(keys)} different device keys")
        lines.append(f"{len(batches)} anchor batch(es), schema-valid, device-signed")

        batches.sort(key=lambda ab: ab[1]["row_start"])
        if batches and batches[0][1]["row_start"] != 0:
            failures.append("history does not start at row 0 (missing early anchors)")
        for (_, a), (_, b) in zip(batches, batches[1:]):
            if b["row_start"] != a["row_end"]:
                failures.append(
                    f"gap/overlap between rows {a['row_end']} and {b['row_start']}"
                )
        if batches:
            lines.append(
                f"continuity: rows 0..{batches[-1][1]['row_end']} covered with no gaps"
            )

        confirmed = pending = 0
        for artifact, batch in batches:
            proof = artifact.with_name(artifact.name[: -len(".json")] + ".root.ots")
            if not proof.exists():
                failures.append(f"{artifact.name}: missing OTS proof")
                continue
            root = bytes.fromhex(batch["root"])
            try:
                info = proof_info(root, proof.read_bytes())
            except OtsError as exc:
                failures.append(f"{proof.name}: {exc}")
                continue
            if not info["digest_matches"]:
                failures.append(f"{proof.name}: proof does not bind this artifact's root")
                continue
            name = f"rows [{batch['row_start']}, {batch['row_end']})"
            if info["confirmed"]:
                confirmed += 1
                heights = info["bitcoin_heights"]
                status = f"bitcoin-confirmed (height {', '.join(map(str, heights))})"
                if check_bitcoin:
                    status += _check_headers(root, proof.read_bytes(), fetch, failures, proof.name)
            else:
                pending += 1
                status = "pending (calendar-attested, not yet Bitcoin-confirmed)"
            lines.append(f"{name}: {status}")

    if pending and not failures:
        lines.append("note: pending proofs upgrade automatically once Bitcoin confirms;"
                     " re-run later for full confirmation")
    verdict = "FAIL" if failures else "PASS"
    return {
        "verdict": verdict,
        "lines": lines,
        "failures": failures,
        "confirmed": confirmed,
        "pending": pending,
    }


def _check_headers(root, ots_bytes, fetch, failures, proof_name) -> str:
    for height, msg in _bitcoin_commitments(root, ots_bytes):
        try:
            merkle_root = fetch_merkle_root(height, fetch)
        except VerifyFailure as exc:
            failures.append(str(exc))
            return ""
        if merkle_root is None:
            return " — explorers unreachable; verify the header independently"
        if msg[::-1].hex() != merkle_root and msg.hex() != merkle_root:
            failures.append(
                f"{proof_name}: commitment does NOT match block {height} merkle root"
            )
            return ""
    return ", header cross-checked against 2 explorers"


def render(result: dict) -> str:
    out = [f"mybench verify: {result['verdict']}"]
    out += [f"  {line}" for line in result["lines"]]
    out += [f"  FAIL: {f}" for f in result["failures"]]
    out.append(
        f"  proofs: {result['confirmed']} bitcoin-confirmed, {result['pending']} pending"
    )
    return "\n".join(out)
