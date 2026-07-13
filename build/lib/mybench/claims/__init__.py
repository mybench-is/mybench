"""Claim envelope + canonical JSON + signing (MYB-10.1, phase L0).

The deterministic signing/serialization substrate for every assessment
claim and, downstream, the Workflow Fingerprint report artifacts
(MYB-13.9 / MYB-14.1). See envelope.py for the envelope contract and
canonical.py for the byte discipline.
"""

from mybench.claims.canonical import (
    CanonicalError,
    canonical_bytes,
    check_canonical_value,
    signed_bytes,
)
from mybench.claims.envelope import (
    SIGNER_KINDS,
    ClaimError,
    build_claim,
    claim_file_bytes,
    dev_signing_key,
    load_claim,
    local_device_pub,
    sign_claim,
    sign_with_device_key,
    validate_claim,
    verify_claim,
)

__all__ = [
    "CanonicalError",
    "ClaimError",
    "SIGNER_KINDS",
    "build_claim",
    "canonical_bytes",
    "check_canonical_value",
    "claim_file_bytes",
    "dev_signing_key",
    "load_claim",
    "local_device_pub",
    "sign_claim",
    "sign_with_device_key",
    "signed_bytes",
    "validate_claim",
    "verify_claim",
]
