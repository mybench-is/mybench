"""Skeptic verify CLI v2 — layout v1 (MYB-8.6, ADR-0004).

Input: a public anchors-log location (local clone path, or a git/https URL
that gets shallow-cloned to a temp dir). The full trust chain, in order:

1. **Whitelist**: the log contains anchors, identity records, checkpoints,
   the schema spec, and a README — anything else fails (anchors-only rule).
2. **Identities**: every genesis record is self-certifying — the directory
   name must equal SHA-256("mybench:v1:identity" || genesis pubkey) — and
   every handle/device binding must verify against the genesis key.
3. **Events**: schema + device signature; the signing device key must be
   BOUND to the identity; the file's path must match its identity/date.
4. **Coverage/continuity** per identity: row ranges chain from 0 with no
   gaps or overlaps, in date order — "no anchor that day" is visibly
   different from "withheld activity", which would show as a range gap.
5. **Proofs** (two-step write): an absent .ots is reported as
   "proof not yet published (pending Bitcoin confirmation)" — it counts
   toward PASS, labeled (OQ #10). A present proof must bind its event's
   root; online (default), Bitcoin block headers are fetched from TWO
   independent explorers which must agree; ``--offline`` degrades honestly.

Role separation: this module never reads a ledger, nonce store, or data
dir. What it CANNOT check: that session roots correspond to particular
content (selective disclosure's job), or activity the owner never anchored
(mybench proves what happened, not that nothing else did).
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from mybench.anchor.event import EventError, verify_event
from mybench.anchor.ots import OtsError, proof_info
from mybench.identity import IdentityError, identity_id_for, verify_record

EVENT_RE = re.compile(r"^anchors/([0-9a-f]{64})/(\d{4})/(\d{2})/(\d{2})\.json$")
PROOF_RE = re.compile(r"^anchors/[0-9a-f]{64}/\d{4}/\d{2}/\d{2}\.json\.ots$")
RECORD_RE = re.compile(
    r"^identities/([0-9a-f]{64})/(genesis|handle-\d{4}|device-[0-9a-f]{8})\.json$"
)
TOLERATED_RE = re.compile(r"^(README\.md|LICENSE.*|schema/.+\.md|checkpoints/.+\.json)$")
EXPLORERS = ("https://blockstream.info/api", "https://mempool.space/api")


class VerifyFailure(Exception):
    pass


def _fetch_json(url: str, timeout: float = 15.0):
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — pinned hosts
        return resp.read().decode()


def fetch_merkle_root(height: int, fetch=_fetch_json) -> str | None:
    roots = set()
    for base in EXPLORERS:
        try:
            block_hash = fetch(f"{base}/block-height/{height}").strip()
            roots.add(json.loads(fetch(f"{base}/block/{block_hash}"))["merkle_root"])
        except Exception:  # noqa: BLE001 — explorer down/unreachable
            return None
    if len(roots) != 1:
        raise VerifyFailure(f"explorers DISAGREE on block {height} merkle root")
    return roots.pop()


def _bitcoin_commitments(ots_bytes: bytes) -> list[tuple[int, bytes]]:
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


def _load_identities(directory: Path, failures: list[str]) -> dict[str, dict]:
    """id -> {"pub": hex, "devices": set, "handles": [..]}; failures appended."""
    identities: dict[str, dict] = {}
    root = directory / "identities"
    if not root.is_dir():
        return identities
    for id_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        iid = id_dir.name
        genesis_path = id_dir / "genesis.json"
        if not genesis_path.is_file():
            failures.append(f"identities/{iid}: missing genesis record")
            continue
        try:
            genesis = json.loads(genesis_path.read_bytes())
            verify_record(genesis, genesis["identity_pub"])
        except (ValueError, KeyError, IdentityError) as exc:
            failures.append(f"identities/{iid}/genesis.json: {exc}")
            continue
        if identity_id_for(bytes.fromhex(genesis["identity_pub"])) != iid:
            failures.append(
                f"identities/{iid}: directory name is NOT the genesis-key fingerprint"
            )
            continue
        info = {"pub": genesis["identity_pub"], "devices": set(), "handles": []}
        for record_path in sorted(id_dir.glob("*.json")):
            if record_path.name == "genesis.json":
                continue
            try:
                record = json.loads(record_path.read_bytes())
                verify_record(record, info["pub"])
            except (ValueError, IdentityError) as exc:
                failures.append(f"identities/{iid}/{record_path.name}: {exc}")
                continue
            if record.get("type") == "device-binding":
                info["devices"].add(record["device_pub"])
            elif record.get("type") == "handle-binding":
                info["handles"].append(record["handle"])
        identities[iid] = info
    return identities


def verify_anchors(source: str, *, check_bitcoin: bool = True, fetch=_fetch_json) -> dict:
    lines: list[str] = []
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        directory = _obtain(source, Path(tmp))
        rels = sorted(
            p.relative_to(directory).as_posix()
            for p in directory.rglob("*")
            if p.is_file() and ".git" not in p.parts
        )
        unknown = [r for r in rels
                   if not (EVENT_RE.match(r) or PROOF_RE.match(r) or RECORD_RE.match(r)
                           or TOLERATED_RE.match(r))]
        if unknown:
            failures.append(f"unexpected files in an anchors-only log: {unknown}")

        identities = _load_identities(directory, failures)
        for iid, info in identities.items():
            handle = info["handles"][-1] if info["handles"] else "(no handle)"
            lines.append(
                f"identity {iid[:12]}… — handle {handle!r}, "
                f"{len(info['devices'])} bound device(s), genesis self-certifies"
            )

        events_by_id: dict[str, list[dict]] = {}
        for rel in rels:
            m = EVENT_RE.match(rel)
            if not m:
                continue
            iid, y, mo, d = m.groups()
            try:
                event = json.loads((directory / rel).read_bytes())
                verify_event(event)
            except (ValueError, EventError) as exc:
                failures.append(f"{rel}: {exc}")
                continue
            if event["identity_id"] != iid or event["date"] != f"{y}-{mo}-{d}":
                failures.append(f"{rel}: path does not match event identity/date")
                continue
            if iid not in identities:
                failures.append(f"{rel}: no identity records for this id")
                continue
            if event["device_pub"] not in identities[iid]["devices"]:
                failures.append(f"{rel}: signed by a device key NOT bound to the identity")
                continue
            events_by_id.setdefault(iid, []).append(event)

        confirmed = pending = 0
        for iid, events in sorted(events_by_id.items()):
            events.sort(key=lambda e: e["date"])
            expected = 0
            for event in events:
                if event["row_start"] != expected:
                    failures.append(
                        f"{iid[:12]}… {event['date']}: row_start {event['row_start']} "
                        f"breaks continuity (expected {expected}) — gap or withheld rows"
                    )
                expected = max(expected, event["row_end"])
                rel, rel_proof = (
                    f"anchors/{iid}/{event['date'].replace('-', '/')}.json",
                    f"anchors/{iid}/{event['date'].replace('-', '/')}.json.ots",
                )
                name = f"{event['date']}: rows [{event['row_start']}, {event['row_end']})"
                proof_path = directory / rel_proof
                if not proof_path.exists():
                    pending += 1
                    lines.append(f"  {name} — proof not yet published "
                                 f"(pending Bitcoin confirmation)")
                    continue
                try:
                    info = proof_info(bytes.fromhex(event["root"]), proof_path.read_bytes())
                except OtsError as exc:
                    failures.append(f"{rel_proof}: {exc}")
                    continue
                if not info["digest_matches"]:
                    failures.append(f"{rel_proof}: proof does not bind this event's root")
                    continue
                if info["confirmed"]:
                    confirmed += 1
                    status = (f"bitcoin-confirmed "
                              f"(height {', '.join(map(str, info['bitcoin_heights']))})")
                    if check_bitcoin:
                        status += _check_headers(proof_path.read_bytes(), fetch,
                                                 failures, rel_proof)
                else:
                    pending += 1
                    status = "pending (calendar-attested, not yet Bitcoin-confirmed)"
                lines.append(f"  {name} — {status}")
            lines.append(
                f"identity {iid[:12]}…: rows 0..{expected} covered, "
                f"{len(events)} anchor day(s), no gaps"
                if not any(iid[:12] in f for f in failures)
                else f"identity {iid[:12]}…: coverage NOT continuous"
            )

        if not events_by_id and not failures:
            raise VerifyFailure(f"no anchor events found in {source}")
        checkpoints = [r for r in rels if r.startswith("checkpoints/")]
        if checkpoints:
            lines.append(f"{len(checkpoints)} checkpoint(s) present "
                         f"(tree-head verification arrives with the checkpoint story)")

    if pending and not failures:
        lines.append("note: pending proofs publish automatically once Bitcoin confirms;"
                     " re-run later for full confirmation")
    return {
        "verdict": "FAIL" if failures else "PASS",
        "lines": lines,
        "failures": failures,
        "confirmed": confirmed,
        "pending": pending,
        "identities": len(identities),
    }


def _check_headers(ots_bytes, fetch, failures, proof_rel) -> str:
    for height, msg in _bitcoin_commitments(ots_bytes):
        try:
            merkle_root = fetch_merkle_root(height, fetch)
        except VerifyFailure as exc:
            failures.append(str(exc))
            return ""
        if merkle_root is None:
            return " — explorers unreachable; verify the header independently"
        if msg[::-1].hex() != merkle_root and msg.hex() != merkle_root:
            failures.append(f"{proof_rel}: commitment does NOT match block {height} "
                            f"merkle root")
            return ""
    return ", header cross-checked against 2 explorers"


def render(result: dict) -> str:
    out = [f"mybench verify: {result['verdict']}"]
    out += [f"  {line}" for line in result["lines"]]
    out += [f"  FAIL: {f}" for f in result["failures"]]
    out.append(
        f"  identities: {result['identities']} · proofs: {result['confirmed']} "
        f"bitcoin-confirmed, {result['pending']} pending"
    )
    return "\n".join(out)
