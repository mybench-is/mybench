"""Anchors-log publisher v2 — layout v1, signed commits, confirmed-only proofs.

``publish()`` remains the single entry point; the only ``git push`` call
site in mybench lives inside it, strictly after the gate (MYB-3.4's rule,
carried forward). v2 discipline per ADR-0004 §§4–6:

- staging mirrors the repo layout (``anchors/<id>/<YYYY>/<MM>/<DD>.json``,
  ``identities/…``, ``schema/…``); nothing outside the path whitelist moves;
- one SIGNED commit per anchor event (dedicated SSH log-signing key from the
  data dir; machine-generated messages); records/schema files ride a single
  "log: records" commit;
- **pending proofs never publish**: a ``.json.ots`` leaves staging only once
  Bitcoin-confirmed, as its own follow-up commit — published files are
  created once and never modified;
- continuity enforced at publish time: a new event's row_start must equal
  the identity's last published row_end (0 for the first); one event per
  identity per UTC day is structural (the path IS the day);
- the leak gate scans the exact staged bytes against the local secret
  corpus (every nonce + every private key file) plus test canaries.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from mybench import paths
from mybench.anchor.event import EventError, verify_event
from mybench.anchor.ots import OtsError, proof_info
from mybench.identity import verify_record
from mybench.leakscan import CanaryLeakError, assert_no_canaries

EVENT_RE = re.compile(r"^anchors/[0-9a-f]{64}/\d{4}/\d{2}/\d{2}\.json$")
PROOF_RE = re.compile(r"^anchors/[0-9a-f]{64}/\d{4}/\d{2}/\d{2}\.json\.ots$")
RECORD_RE = re.compile(
    r"^identities/[0-9a-f]{64}/(genesis|handle-\d{4}|device-[0-9a-f]{8})\.json$"
)
SPEC_RE = re.compile(r"^schema/anchor\.v1\.md$")


class PublishError(RuntimeError):
    pass


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise PublishError(f"git {args[0]} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def staged_files(staging: Path | None = None) -> list[tuple[Path, str]]:
    """(absolute path, repo-relative posix path) pairs; archives excluded."""
    staging = staging if staging is not None else paths.anchors_dir()
    if not staging.is_dir():
        return []
    out = []
    for p in sorted(staging.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(staging).as_posix()
        if any(part.startswith("archive") for part in p.relative_to(staging).parts):
            continue
        out.append((p, rel))
    return out


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


def _load_event(path: Path, rel: str) -> dict:
    try:
        event = json.loads(path.read_bytes())
        verify_event(event)
    except (ValueError, EventError) as exc:
        raise PublishError(f"{rel}: {exc}") from exc
    expected = f"anchors/{event['identity_id']}/{event['date'].replace('-', '/')}.json"
    if rel != expected:
        raise PublishError(f"{rel}: path does not match event identity/date ({expected})")
    return event


def gate(files: list[tuple[Path, str]], extra_canaries: tuple[bytes, ...] = ()) -> None:
    """The mandatory pre-push gate. Raises PublishError; never publishes on failure."""
    if not files:
        raise PublishError("nothing staged — refusing an empty publish")
    bad = [rel for _p, rel in files
           if not (EVENT_RE.match(rel) or PROOF_RE.match(rel)
                   or RECORD_RE.match(rel) or SPEC_RE.match(rel))]
    if bad:
        raise PublishError(f"non-whitelisted paths staged: {bad}")

    by_rel = {rel: p for p, rel in files}
    genesis_pub: dict[str, str] = {}
    for p, rel in files:
        if RECORD_RE.match(rel) and rel.endswith("genesis.json"):
            record = json.loads(p.read_bytes())
            verify_record(record, record["identity_pub"])
            genesis_pub[record["identity_id"]] = record["identity_pub"]
    for p, rel in files:
        if RECORD_RE.match(rel) and not rel.endswith("genesis.json"):
            record = json.loads(p.read_bytes())
            pub = genesis_pub.get(record.get("identity_id", ""))
            if pub:  # genesis not staged → publish() checks against the clone
                verify_record(record, pub)
        elif EVENT_RE.match(rel):
            event = _load_event(p, rel)
            proof_rel = rel + ".ots"
            if proof_rel in by_rel:
                try:
                    info = proof_info(bytes.fromhex(event["root"]),
                                      by_rel[proof_rel].read_bytes())
                except OtsError as exc:
                    raise PublishError(f"{proof_rel}: {exc}") from exc
                if not info["digest_matches"]:
                    raise PublishError(f"{proof_rel}: proof does not bind this event's root")

    corpus = local_secret_corpus() + list(extra_canaries)
    if not corpus:
        raise PublishError("empty secret corpus — refusing a vacuous leak scan")
    try:
        assert_no_canaries([p for p, _rel in files], corpus)
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
    elif _git(clone_dir, "ls-remote", "--heads", "origin", "master"):
        _git(clone_dir, "pull", "-q", "--ff-only", "origin", "master")


def _configure_signing(clone_dir: Path) -> None:
    key_path, pub_path = paths.ensure_commit_signing_key()
    signers = paths.keys_dir() / "log-allowed-signers"
    if not signers.exists():
        signers.write_bytes(b"mybench-log " + pub_path.read_bytes())
    _git(clone_dir, "config", "user.name", "mybench publisher")
    _git(clone_dir, "config", "user.email", "mybench-publisher@invalid")
    _git(clone_dir, "config", "gpg.format", "ssh")
    _git(clone_dir, "config", "user.signingkey", str(key_path))
    _git(clone_dir, "config", "commit.gpgsign", "true")
    _git(clone_dir, "config", "gpg.ssh.allowedSignersFile", str(signers))


def _last_row_end(clone_dir: Path, identity_id: str) -> int:
    last = 0
    for p in sorted((clone_dir / "anchors" / identity_id).rglob("*.json")):
        if p.name.endswith(".json"):
            last = max(last, json.loads(p.read_bytes())["row_end"])
    return last


def publish(
    remote_url: str,
    *,
    push: bool = False,
    staging: Path | None = None,
    clone_dir: Path | None = None,
    extra_canaries: tuple[bytes, ...] = (),
) -> dict:
    """Gate, then (only with push=True) commit + push the staged layout-v1 tree."""
    files = staged_files(staging)
    gate(files, extra_canaries)
    manifest = [
        {"path": rel, "bytes": p.stat().st_size,
         "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p, rel in files
    ]
    if not push:
        return {"dry_run": True, "files": manifest}

    clone_dir = clone_dir if clone_dir is not None else paths.data_dir() / "anchors-repo"
    _sync_clone(remote_url, clone_dir)
    _configure_signing(clone_dir)

    def _commit(message: str, rels: list[str]) -> str:
        _git(clone_dir, "add", "--", *rels)
        _git(clone_dir, "commit", "-q", "-m", message)
        return _git(clone_dir, "rev-parse", "HEAD")

    commits, pushed, pending = [], [], []
    records = [(p, rel) for p, rel in files if RECORD_RE.match(rel) or SPEC_RE.match(rel)]
    new_records = []
    for p, rel in records:
        dest = clone_dir / rel
        if dest.exists():
            if dest.read_bytes() != p.read_bytes():
                raise PublishError(f"{rel}: published records are immutable")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(p.read_bytes())
        new_records.append(rel)
    if new_records:
        commits.append(_commit("log: records", new_records))
        pushed += new_records

    events = sorted(
        ((p, rel) for p, rel in files if EVENT_RE.match(rel)), key=lambda pr: pr[1]
    )
    for p, rel in events:
        dest = clone_dir / rel
        if dest.exists():
            if dest.read_bytes() != p.read_bytes():
                raise PublishError(f"{rel}: published anchor events are immutable")
            continue
        event = json.loads(p.read_bytes())
        expected_start = _last_row_end(clone_dir, event["identity_id"])
        if event["row_start"] != expected_start:
            raise PublishError(
                f"{rel}: row_start {event['row_start']} breaks continuity "
                f"(identity's last published row_end is {expected_start})"
            )
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(p.read_bytes())
        commits.append(_commit(f"anchor: {rel}", [rel]))
        pushed.append(rel)

    for p, rel in files:
        if not PROOF_RE.match(rel):
            continue
        dest = clone_dir / rel
        event_path = clone_dir / rel[: -len(".ots")]
        if not event_path.exists():
            raise PublishError(f"{rel}: proof staged for an unpublished event")
        root = bytes.fromhex(json.loads(event_path.read_bytes())["root"])
        info = proof_info(root, p.read_bytes())
        if not info["digest_matches"]:
            raise PublishError(f"{rel}: proof does not bind the published event's root")
        if not info["confirmed"]:
            pending.append(rel)  # two-step write: stays staged until confirmed
            continue
        if dest.exists():
            if dest.read_bytes() != p.read_bytes():
                raise PublishError(f"{rel}: proofs are written once, never modified")
            continue
        dest.write_bytes(p.read_bytes())
        commits.append(_commit(f"anchor proof: {rel}", [rel]))
        pushed.append(rel)
        p.unlink()  # published and immutable; staging copy no longer needed

    if pushed:
        # The ONLY push call site in mybench — reachable solely through gate().
        _git(clone_dir, "push", "-q", "origin", "master")
    return {
        "dry_run": False,
        "files": manifest,
        "pushed": pushed,
        "pending": pending,
        "commits": commits,
    }
