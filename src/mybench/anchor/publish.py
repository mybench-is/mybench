"""Anchor publisher with a MANDATORY pre-push leak gate (MYB-3.4).

``publish()`` is the single entry point; the only ``git push`` call site in
mybench lives inside it, strictly after the gate. There is no code path that
publishes without gating — by construction, not convention.

The gate, on the exact staged bytes:
1. Filename whitelist — only ``anchor-NNNNNNNN-NNNNNNNN.json`` and matching
   ``.root.ots`` proofs, always in pairs; anything else refuses the push.
2. Per artifact: schema whitelist + device signature (verify_batch) and
   proof digest binding (proof_info); staged ranges must be contiguous.
3. Leak scan (mybench.leakscan) against the local secret corpus — every
   nonce in the nonce store and every key file's bytes, in raw/hex/base64/
   gzip encodings — plus any test-supplied canaries. A vacuous corpus is an
   error, never a pass.

Dry-run is the default: it returns/prints the exact files, sizes, and
SHA-256s that WOULD be pushed; a real push requires ``push=True`` (CLI:
``--push``). The publisher maintains an append-only clone under the data dir
(or a caller-supplied dir) and only ever fast-forwards.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from mybench import paths
from mybench.anchor.batch import AnchorError, verify_batch
from mybench.anchor.ots import OtsError, proof_info
from mybench.leakscan import CanaryLeakError, assert_no_canaries

FILENAME_RE = re.compile(r"^anchor-\d{8}-\d{8}\.(json|root\.ots)$")


class PublishError(RuntimeError):
    pass


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise PublishError(f"git {args[0]} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def staged_files(staging: Path | None = None) -> list[Path]:
    staging = staging if staging is not None else paths.anchors_dir()
    return sorted(p for p in staging.iterdir() if p.is_file()) if staging.is_dir() else []


def local_secret_corpus() -> list[bytes]:
    """Everything that must never appear in a published byte, from this machine."""
    corpus: list[bytes] = []
    if paths.nonces_dir().is_dir():
        for nf in sorted(paths.nonces_dir().glob("*.jsonl")):
            for line in nf.read_bytes().splitlines():
                corpus.append(bytes.fromhex(json.loads(line)["nonce"]))
    if paths.keys_dir().is_dir():
        for kf in sorted(paths.keys_dir().iterdir()):
            if kf.is_file() and kf.suffix != ".pub":
                corpus.append(kf.read_bytes())
    return corpus


def gate(files: list[Path], extra_canaries: tuple[bytes, ...] = ()) -> None:
    """The mandatory pre-push gate. Raises PublishError; never publishes on failure."""
    if not files:
        raise PublishError("nothing staged — refusing an empty publish")
    bad = [f.name for f in files if not FILENAME_RE.fullmatch(f.name)]
    if bad:
        raise PublishError(f"non-whitelisted filenames staged: {bad}")
    artifacts = {f for f in files if f.suffix == ".json"}
    proofs = {f for f in files if f.name.endswith(".root.ots")}
    if {f.name[: -len(".json")] for f in artifacts} != {
        f.name[: -len(".root.ots")] for f in proofs
    }:
        raise PublishError("staged artifacts and proofs are not in matching pairs")

    batches = []
    for artifact in sorted(artifacts):
        try:
            batch = json.loads(artifact.read_bytes())
            verify_batch(batch)
        except (ValueError, AnchorError) as exc:
            raise PublishError(f"{artifact.name}: {exc}") from exc
        proof = artifact.with_name(artifact.name[: -len(".json")] + ".root.ots")
        try:
            info = proof_info(bytes.fromhex(batch["root"]), proof.read_bytes())
        except OtsError as exc:
            raise PublishError(f"{proof.name}: {exc}") from exc
        if not info["digest_matches"]:
            raise PublishError(f"{proof.name}: proof does not bind this artifact's root")
        batches.append(batch)
    batches.sort(key=lambda b: b["row_start"])
    for a, b in zip(batches, batches[1:]):
        if b["row_start"] != a["row_end"]:
            raise PublishError("staged batches are not contiguous")

    corpus = local_secret_corpus() + list(extra_canaries)
    if not corpus:
        raise PublishError("empty secret corpus — refusing a vacuous leak scan")
    try:
        assert_no_canaries(files, corpus)
    except CanaryLeakError as exc:
        raise PublishError(f"LEAK GATE FIRED — push refused:\n{exc}") from exc


def _sync_clone(remote_url: str, clone_dir: Path) -> None:
    if not clone_dir.exists():
        proc = subprocess.run(
            ["git", "clone", "-q", remote_url, str(clone_dir)], capture_output=True, text=True
        )
        if proc.returncode != 0:
            raise PublishError(f"clone failed: {proc.stderr.strip()}")
        _git(clone_dir, "symbolic-ref", "HEAD", "refs/heads/master")
        _git(clone_dir, "config", "user.name", "mybench publisher")
        _git(clone_dir, "config", "user.email", "mybench-publisher@invalid")
    elif _git(clone_dir, "ls-remote", "--heads", "origin", "master"):
        _git(clone_dir, "pull", "-q", "--ff-only", "origin", "master")


def publish(
    remote_url: str,
    *,
    push: bool = False,
    staging: Path | None = None,
    clone_dir: Path | None = None,
    extra_canaries: tuple[bytes, ...] = (),
) -> dict:
    """Gate, then (only with push=True) commit + push the staged anchor tree."""
    files = staged_files(staging)
    gate(files, extra_canaries)
    manifest = [
        {
            "name": f.name,
            "bytes": f.stat().st_size,
            "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
        }
        for f in files
    ]
    if not push:
        return {"dry_run": True, "files": manifest}

    clone_dir = clone_dir if clone_dir is not None else paths.data_dir() / "anchors-repo"
    _sync_clone(remote_url, clone_dir)
    new = []
    for f in files:
        dest = clone_dir / f.name
        if dest.exists() and dest.read_bytes() == f.read_bytes():
            continue
        if dest.exists() and f.suffix == ".json":
            # Artifacts are append-only forever; only .root.ots proofs may be
            # republished (pending → Bitcoin-confirmed upgrades).
            raise PublishError(f"{f.name} already published with different bytes")
        dest.write_bytes(f.read_bytes())
        new.append(f.name)
    if not new:
        return {"dry_run": False, "files": manifest, "pushed": [], "commit": None}
    _git(clone_dir, "add", "--", *new)
    changed = _git(clone_dir, "status", "--porcelain").splitlines()
    unexpected = [c for c in changed if c[3:] not in new]
    if unexpected:
        raise PublishError(f"unexpected working-tree changes: {unexpected}")
    ranges = ", ".join(sorted(n for n in new if n.endswith(".json")))
    _git(clone_dir, "commit", "-q", "-m", f"anchor: {ranges or 'proof upgrades'}")
    # The ONLY push call site in mybench — reachable solely through gate() above.
    _git(clone_dir, "push", "-q", "origin", "master")
    return {
        "dry_run": False,
        "files": manifest,
        "pushed": new,
        "commit": _git(clone_dir, "rev-parse", "HEAD"),
    }
