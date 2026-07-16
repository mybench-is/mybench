"""OpenTimestamps stamping of anchor roots (MYB-3.2).

Wire discipline (invariant #1): the ONLY bytes sent to a calendar are the
32-byte batch root digest, POSTed to ``<calendar>/digest`` — proven by the
mock-calendar capture test. We deliberately skip otsclient's pre-submission
nonce: its purpose is hiding a private file hash from calendar operators,
but a batch root is a designed-public artifact (threat model §3), and the
bare digest keeps the wire payload trivially auditable.

Proof lifecycle: stamping returns a *pending* proof (calendar attestation);
Bitcoin confirmation takes hours, after which ``upgrade_proof`` fetches and
merges the Bitcoin attestation. Verification here (``proof_info``) covers
structure, digest binding, and the attestation inventory; checking a Bitcoin
attestation against real block headers needs a header source and lands in
the Phase 4 verify CLI. Report semantics for fresh proofs — "pending
(calendar-attested, not yet Bitcoin-confirmed)" — are OPEN_QUESTIONS #10.
"""

from __future__ import annotations

import io
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
    StreamDeserializationContext,
)
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from mybench import paths
from mybench.anchor.batch import canonical_bytes

DEFAULT_CALENDARS = (
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
)
_HEADERS = {
    "Accept": "application/vnd.opentimestamps.v1",
    "User-Agent": "mybench-anchor/0",
}
_FILE_MODE = 0o600


class OtsError(RuntimeError):
    pass


@dataclass(frozen=True)
class StampResult:
    """A pending proof plus the private first-successful-response observation."""

    proof: bytes
    receipt_ts: str


def _clock_now() -> datetime:
    return datetime.now(UTC)


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise OtsError("receipt clock must return a UTC-aware datetime")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _http(url: str, data: bytes | None = None, timeout: float = 15.0) -> bytes:
    req = urllib.request.Request(url, data=data, headers=_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — caller pins URLs
        return resp.read()


def _subs(ts: Timestamp):
    yield ts
    for _op, sub in ts.ops.items():
        yield from _subs(sub)


def stamp_root_observed(
    root: bytes,
    calendars=DEFAULT_CALENDARS,
    timeout: float = 15.0,
    *,
    clock: Callable[[], datetime] = _clock_now,
) -> StampResult:
    """Stamp a root and remember the first successfully merged response time.

    Calendars remain sequential and best-effort.  The clock is sampled exactly
    once, immediately after the first response successfully deserializes and
    merges; later attempts cannot move the observation.
    """
    if len(root) != 32:
        raise OtsError(f"root must be a 32-byte digest, got {len(root)} bytes")
    ts = Timestamp(root)
    failures = []
    receipt_ts = None
    for attempt, calendar in enumerate(calendars, start=1):
        try:
            resp = _http(calendar.rstrip("/") + "/digest", data=root, timeout=timeout)
            ts.merge(Timestamp.deserialize(BytesDeserializationContext(resp), root))
        except Exception as exc:  # noqa: BLE001 — any one calendar may be down
            failures.append(f"attempt {attempt}: {type(exc).__name__}")
            continue
        if receipt_ts is None:
            receipt_ts = _utc_timestamp(clock())
    if not ts.attestations and not ts.ops:
        raise OtsError("no calendar accepted the digest — " + "; ".join(failures))
    if receipt_ts is None:  # defensive: a merged response must have sampled the clock
        raise OtsError("calendar proof was created without a receipt observation")
    dtf = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return StampResult(ctx.getbytes(), receipt_ts)


def stamp_root(root: bytes, calendars=DEFAULT_CALENDARS, timeout: float = 15.0) -> bytes:
    """Submit the root digest to calendars; return serialized pending .ots proof."""
    return stamp_root_observed(root, calendars, timeout).proof


def upgrade_proof(ots_bytes: bytes, timeout: float = 15.0) -> tuple[bytes, bool]:
    """Ask calendars for Bitcoin attestations of pending commitments.

    Returns (possibly-updated proof bytes, fully_confirmed). Network failures
    leave the proof unchanged — upgrading retries harmlessly later.
    """
    dtf = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(ots_bytes)))
    changed = False
    for sub in _subs(dtf.timestamp):
        for attestation in list(sub.attestations):
            if not isinstance(attestation, PendingAttestation):
                continue
            url = attestation.uri.rstrip("/") + "/timestamp/" + sub.msg.hex()
            try:
                resp = _http(url, timeout=timeout)
                sub.merge(Timestamp.deserialize(BytesDeserializationContext(resp), sub.msg))
                changed = True
            except Exception:  # noqa: BLE001 — not yet upgraded, or calendar down
                continue
    confirmed = any(
        isinstance(a, BitcoinBlockHeaderAttestation)
        for _msg, a in dtf.timestamp.all_attestations()
    )
    if not changed:
        return ots_bytes, confirmed
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes(), confirmed


def proof_info(root: bytes, ots_bytes: bytes) -> dict:
    """Structure + digest-binding check and attestation inventory (see module doc)."""
    try:
        dtf = DetachedTimestampFile.deserialize(
            StreamDeserializationContext(io.BytesIO(ots_bytes))
        )
    except Exception as exc:
        raise OtsError(f"unparseable .ots proof: {type(exc).__name__}") from exc
    pending, heights = [], []
    for _msg, attestation in dtf.timestamp.all_attestations():
        if isinstance(attestation, PendingAttestation):
            pending.append(attestation.uri)
        elif isinstance(attestation, BitcoinBlockHeaderAttestation):
            heights.append(attestation.height)
    return {
        "digest_matches": dtf.file_digest == root and isinstance(dtf.file_hash_op, OpSHA256),
        "pending": sorted(set(pending)),
        "bitcoin_heights": sorted(set(heights)),
        "confirmed": bool(heights),
    }


# -- staging under the data dir (AC #3) ------------------------------------------


def _write_0600(path: Path, data: bytes) -> None:
    import os

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def batch_paths(batch: dict, directory: Path | None = None) -> tuple[Path, Path]:
    directory = directory if directory is not None else paths.anchors_dir()
    stem = f"anchor-{batch['row_start']:08d}-{batch['row_end']:08d}"
    # The proof stamps the batch ROOT (recomputable from the artifact), not
    # the artifact file bytes — hence .root.ots, not .json.ots.
    return directory / f"{stem}.json", directory / f"{stem}.root.ots"


def stamp_batch(batch: dict, calendars=DEFAULT_CALENDARS, directory: Path | None = None,
                timeout: float = 15.0) -> tuple[Path, Path]:
    """Write the artifact + pending .ots proof under the data dir; idempotent."""
    if directory is None:
        paths.ensure_data_dir()
    artifact_path, proof_path = batch_paths(batch, directory)
    artifact = canonical_bytes(batch)
    if artifact_path.exists():
        if artifact_path.read_bytes() != artifact:
            raise OtsError(f"{artifact_path} exists with different content — refusing overwrite")
    else:
        _write_0600(artifact_path, artifact)
    if not proof_path.exists():
        _write_0600(proof_path, stamp_root(bytes.fromhex(batch["root"]), calendars, timeout))
    return artifact_path, proof_path


def upgrade_batch_proof(proof_path: Path, timeout: float = 15.0) -> bool:
    upgraded_bytes, confirmed = upgrade_proof(proof_path.read_bytes(), timeout)
    if upgraded_bytes != proof_path.read_bytes():
        _write_0600(proof_path, upgraded_bytes)
    return confirmed
