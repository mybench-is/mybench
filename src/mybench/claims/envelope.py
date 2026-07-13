"""Claim envelope v0 — build, sign, validate, verify (MYB-10.1, handoff §3).

Every assessment output is one signed claim in this envelope; canonical JSON
(:mod:`mybench.claims.canonical`) is the wire and storage format. This is
the signing/serialization substrate the Workflow Fingerprint outputs stand
on (report.json / report.sig / evidence-manifest.json / public-report.sig —
roadmap Stage 1 §7/§8 via MYB-13.9 and MYB-14.1), not a standalone artifact.

Two implementer-note deltas from the handoff §3 sketch, both required for
standalone verification and both mirroring existing conventions:

- ``signer`` — the verifying key is embedded (kind + raw pubkey hex), as
  anchor batches embed ``device_pub``. ``kind`` labels the non-production
  dev key *structurally*, but it is SELF-CERTIFIED — covered by the very
  signature being checked — so it confers no provenance by itself. Like the
  anchors verify CLI (which accepts an event's device_pub only when a signed
  device-binding record lists it), callers must bind ``signer.pub`` to a
  trusted key set before presenting device-tier anything; pass
  ``trusted_device_pubs`` to :func:`verify_claim` for exactly that.
  Production claims are signed by the EXISTING Ed25519 device key
  (ADR-0002 §5, roadmap Stage 1 §5) — the dev key never becomes a parallel
  signing identity.
- Tier *presentation* of ``execution_env`` / signer kinds is owner-gated
  (OQ #30, MYB-10.17): nothing here maps either to a trust-tier name.

``signed_at`` is a runner-supplied input; nothing in this module reads the
clock, network, or environment (handoff §4 rule 2). Claims stay local until
the THREAT_MODEL §3 revision opens a publish gate (invariant #4, MYB-16.2).
"""

from __future__ import annotations

import copy
import json
from collections.abc import Collection
from datetime import datetime
from importlib import resources

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mybench import paths
from mybench.claims.canonical import (
    CanonicalError,
    canonical_bytes,
    check_canonical_value,
    signed_bytes,
)
from mybench.schemas import load_validator


class ClaimError(RuntimeError):
    pass


def _schema_signer_kinds() -> tuple[str, ...]:
    # One source of truth: the schema enum (finder-confirmed drift hazard).
    schema = json.loads(
        resources.files("mybench.schemas").joinpath("claim.schema.json").read_text()
    )
    return tuple(schema["properties"]["signer"]["properties"]["kind"]["enum"])


SIGNER_KINDS = _schema_signer_kinds()


def build_claim(
    *,
    claim_type: str,
    registry_id: str,
    registry_version: str,
    scorer_name: str,
    scorer_version: str,
    corpus_commitment: str | list[str],
    window_start: str,
    window_end: str,
    output: dict,
    derivation_class: str,
    signed_at: str,
    execution_env: str = "local-unattested",
    attestation_evidence: list[dict] | None = None,
    anchor_refs: list[str] | None = None,
    measurement: str | None = None,
) -> dict:
    """Assemble an unsigned claim. All variability enters as parameters —
    ``signed_at`` included — so identical inputs are byte-identical claims.

    Deterministic normalization (handoff §4 rule 3 — one byte form per
    meaning): multi-root ``corpus_commitment`` and ``anchor_refs`` are
    sorted and de-duplicated; an empty/absent ``anchor_refs`` has exactly
    one representation (key omitted). Mutable arguments are deep-copied so
    later caller mutation can never touch the claim (signatures freeze
    bytes; the claim must own its snapshot).
    """
    if isinstance(corpus_commitment, list):
        corpus_commitment = sorted(set(corpus_commitment))
    inputs: dict = {
        "corpus_commitment": corpus_commitment,
        "evidence_window": {"start": window_start, "end": window_end},
    }
    if anchor_refs:
        inputs["anchor_refs"] = sorted(set(anchor_refs))
    return {
        "claim_type": claim_type,
        "registry_id": registry_id,
        "registry_version": registry_version,
        "scorer": {"name": scorer_name, "version": scorer_version, "measurement": measurement},
        "inputs": inputs,
        "output": copy.deepcopy(output),
        "derivation_class": derivation_class,
        "execution_env": execution_env,
        "attestation_evidence": copy.deepcopy(list(attestation_evidence or [])),
        "signed_at": signed_at,
    }


def _parse_instant(value: str, where: str) -> datetime:
    """Real-instant check on top of the schema regex (a regex happily takes
    month 99 — and jsonschema's re.search would take Unicode digits if the
    pattern used ``\\d``)."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ClaimError(f"{where} is not a real UTC instant") from exc


def validate_claim(claim: dict) -> None:
    """Canonical-form check + schema whitelist + rules the schema can't say."""
    try:
        check_canonical_value(claim)
    except CanonicalError as exc:
        raise ClaimError(f"claim is not canonical-JSON-safe: {exc}") from exc
    errors = sorted(load_validator("claim.schema.json").iter_errors(claim), key=str)
    if errors:
        raise ClaimError(f"claim schema violation: {errors[0].message}")
    window = claim["inputs"]["evidence_window"]
    start = _parse_instant(window["start"], "evidence_window.start")
    end = _parse_instant(window["end"], "evidence_window.end")
    if start > end:
        raise ClaimError("evidence_window.start is after evidence_window.end")
    _parse_instant(claim["signed_at"], "signed_at")
    roots = claim["inputs"]["corpus_commitment"]
    if isinstance(roots, list) and roots != sorted(set(roots)):
        raise ClaimError("corpus_commitment array must be sorted and duplicate-free")
    refs = claim["inputs"].get("anchor_refs")
    if refs is not None and refs != sorted(set(refs)):
        raise ClaimError("anchor_refs must be sorted and duplicate-free")


def sign_claim(claim: dict, private: Ed25519PrivateKey, *, kind: str) -> dict:
    """Sign an unsigned claim; returns the signed, validated claim dict.

    Canonical safety is checked (and wrapped in :class:`ClaimError`) BEFORE
    the key touches anything; the returned claim is a deep copy so caller
    mutation of the input dicts cannot corrupt what was signed.
    """
    if kind not in SIGNER_KINDS:
        raise ClaimError(f"unknown signer kind {kind!r}; expected one of {SIGNER_KINDS}")
    if "signature" in claim or "signer" in claim:
        raise ClaimError("claim is already signed — build a fresh claim instead of re-signing")
    try:
        check_canonical_value(claim)
    except CanonicalError as exc:
        raise ClaimError(f"claim is not canonical-JSON-safe: {exc}") from exc
    pub = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signed = {**copy.deepcopy(claim), "signer": {"kind": kind, "pub": pub.hex()}}
    signed["signature"] = private.sign(signed_bytes(signed)).hex()
    validate_claim(signed)
    return signed


def sign_with_device_key(claim: dict) -> dict:
    """Production signing: the existing Ed25519 device key (ADR-0002 §5).

    Loads the key per call; bulk signers (report bundles, MYB-13.9) should
    call :func:`mybench.paths.load_device_key` once and use
    :func:`sign_claim` directly.
    """
    return sign_claim(claim, paths.load_device_key(), kind="device")


def local_device_pub() -> str:
    """This machine's device public key (raw hex) — the natural one-element
    ``trusted_device_pubs`` set for local verification."""
    private = paths.load_device_key()
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def dev_signing_key(seed: bytes | None = None) -> Ed25519PrivateKey:
    """NON-PRODUCTION signing key (tests, local development).

    Claims it signs carry ``signer.kind == "dev"`` and verify only up to the
    self-run tier. A 32-byte ``seed`` gives a deterministic key for golden
    fixtures; without one the key is ephemeral (never written anywhere).
    """
    if seed is None:
        return Ed25519PrivateKey.generate()
    if len(seed) != 32:
        raise ClaimError("dev signing seed must be exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def verify_claim(
    claim: dict, *, trusted_device_pubs: Collection[str] | None = None
) -> dict:
    """Validate + verify the signature against the embedded signer key.

    Returns a copy of the ``signer`` object (``kind`` + ``pub``). The kind
    is SELF-CERTIFIED — anyone can mint a key and label it ``device`` — so
    a bare ``verify_claim(claim)`` proves only integrity: the claim is
    intact and was signed by the embedded key. To trust a ``device`` label,
    pass ``trusted_device_pubs`` (e.g. ``{local_device_pub()}`` locally, or
    pubs from signed device-binding records — the anchors-verify pattern);
    a ``device`` claim whose key is not in the set is rejected. Mapping
    kinds/envs to presentation is deliberately not this module (OQ #30).
    """
    validate_claim(claim)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(claim["signer"]["pub"])).verify(
            bytes.fromhex(claim["signature"]), signed_bytes(claim)
        )
    except InvalidSignature as exc:
        raise ClaimError("claim signature does not verify") from exc
    signer = dict(claim["signer"])
    if signer["kind"] == "device" and trusted_device_pubs is not None:
        if signer["pub"] not in trusted_device_pubs:
            raise ClaimError("signer claims kind=device but its key is not a trusted device key")
    return signer


def claim_file_bytes(claim: dict) -> bytes:
    """The exact on-disk artifact bytes: canonical JSON + trailing newline
    (same convention as anchor batch files)."""
    validate_claim(claim)
    return canonical_bytes(claim) + b"\n"


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise ClaimError(f"duplicate JSON key {key!r} in claim file")
        obj[key] = value
    return obj


def load_claim(data: bytes) -> dict:
    """Parse stored claim-file bytes, enforcing the one-true-byte-form on
    READ as well as write: duplicate JSON keys are rejected (json.loads
    silently keeps the last, letting raw bytes and parsed content disagree
    about what was signed), and the bytes must round-trip exactly through
    :func:`claim_file_bytes`. Callers still run :func:`verify_claim`."""
    try:
        claim = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ClaimError("claim file is not valid JSON") from exc
    if not isinstance(claim, dict):
        raise ClaimError("claim file is not a JSON object")
    validate_claim(claim)
    if canonical_bytes(claim) + b"\n" != data:
        raise ClaimError("claim file is not in canonical form (byte round-trip failed)")
    return claim
