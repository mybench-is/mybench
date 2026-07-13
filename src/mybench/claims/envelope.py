"""Claim envelope v0 — build, sign, validate, verify (MYB-10.1, handoff §3).

Every assessment output is one signed claim in this envelope; canonical JSON
(:mod:`mybench.claims.canonical`) is the wire and storage format. This is
the signing/serialization substrate the Workflow Fingerprint outputs stand
on (report.json / report.sig / evidence-manifest.json / public-report.sig —
roadmap Stage 1 §7/§8 via MYB-13.9 and MYB-14.1), not a standalone artifact.

Two implementer-note deltas from the handoff §3 sketch, both required for
standalone verification and both mirroring existing conventions:

- ``signer`` — the verifying key is embedded (kind + raw pubkey hex), as
  anchor batches embed ``device_pub``. ``kind`` makes the non-production
  dev key *structurally* labeled: verification reports the kind and callers
  present dev-signed claims only up to the self-run tier. Production claims
  are signed by the EXISTING Ed25519 device key (ADR-0002 §5, roadmap
  Stage 1 §5) — the dev key never becomes a parallel signing identity.
- Tier *presentation* of ``execution_env`` / signer kinds is owner-gated
  (OQ #30, MYB-10.17): nothing here maps either to a trust-tier name.

``signed_at`` is a runner-supplied input; nothing in this module reads the
clock, network, or environment (handoff §4 rule 2). Claims stay local until
the THREAT_MODEL §3 revision opens a publish gate (invariant #4, MYB-16.2).
"""

from __future__ import annotations

from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mybench import paths
from mybench.claims.canonical import CanonicalError, canonical_bytes, signed_bytes
from mybench.schemas import load_validator

SIGNER_KINDS = ("device", "dev")


class ClaimError(RuntimeError):
    pass


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
    ``signed_at`` included — so identical inputs are byte-identical claims."""
    inputs: dict = {
        "corpus_commitment": corpus_commitment,
        "evidence_window": {"start": window_start, "end": window_end},
    }
    if anchor_refs:
        inputs["anchor_refs"] = list(anchor_refs)
    return {
        "claim_type": claim_type,
        "registry_id": registry_id,
        "registry_version": registry_version,
        "scorer": {"name": scorer_name, "version": scorer_version, "measurement": measurement},
        "inputs": inputs,
        "output": output,
        "derivation_class": derivation_class,
        "execution_env": execution_env,
        "attestation_evidence": list(attestation_evidence or []),
        "signed_at": signed_at,
    }


def _parse_window_ts(value: str, where: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ClaimError(f"unparseable {where} timestamp") from exc


def validate_claim(claim: dict) -> None:
    """Canonical-form check + schema whitelist + cross-field consistency."""
    try:
        canonical_bytes(claim)
    except CanonicalError as exc:
        raise ClaimError(f"claim is not canonical-JSON-safe: {exc}") from exc
    errors = sorted(load_validator("claim.schema.json").iter_errors(claim), key=str)
    if errors:
        raise ClaimError(f"claim schema violation: {errors[0].message}")
    window = claim["inputs"]["evidence_window"]
    start = _parse_window_ts(window["start"], "evidence_window.start")
    end = _parse_window_ts(window["end"], "evidence_window.end")
    if start > end:
        raise ClaimError("evidence_window.start is after evidence_window.end")


def sign_claim(claim: dict, private: Ed25519PrivateKey, *, kind: str) -> dict:
    """Sign an unsigned claim; returns the signed, validated claim dict."""
    if kind not in SIGNER_KINDS:
        raise ClaimError(f"unknown signer kind {kind!r}; expected one of {SIGNER_KINDS}")
    if "signature" in claim or "signer" in claim:
        raise ClaimError("claim is already signed — build a fresh claim instead of re-signing")
    pub = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signed = {**claim, "signer": {"kind": kind, "pub": pub.hex()}}
    signed["signature"] = private.sign(signed_bytes(signed)).hex()
    validate_claim(signed)
    return signed


def sign_with_device_key(claim: dict) -> dict:
    """Production signing: the existing Ed25519 device key (ADR-0002 §5)."""
    key_path, _ = paths.ensure_device_key()
    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    return sign_claim(claim, private, kind="device")


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


def verify_claim(claim: dict) -> str:
    """Validate + verify the signature against the embedded signer key.

    Returns the signer ``kind`` (``"device"`` or ``"dev"``); the caller maps
    kinds/envs to presentation — deliberately not this module (OQ #30).
    """
    validate_claim(claim)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(claim["signer"]["pub"])).verify(
            bytes.fromhex(claim["signature"]), signed_bytes(claim)
        )
    except InvalidSignature as exc:
        raise ClaimError("claim signature does not verify") from exc
    return claim["signer"]["kind"]


def claim_file_bytes(claim: dict) -> bytes:
    """The exact on-disk artifact bytes: canonical JSON + trailing newline
    (same convention as anchor batch files)."""
    validate_claim(claim)
    return canonical_bytes(claim) + b"\n"
