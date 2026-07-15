"""Deterministic, content-opaque transcript normalization (MYB-10.4)."""

from mybench.normalizer.claude import (
    CLAUDE_ADAPTER_VERSION,
    ContentResolution,
    ResolutionIntegrityError,
    ResolutionRecord,
    VerifiedRecord,
    VerifiedSession,
    normalize_claude,
    resolve_content_pointer,
    resolution_coverage,
)
from mybench.normalizer.contract import (
    AUTHORSHIP_POLICY_VERSION,
    EPISODE_STITCHER_VERSION,
    NORMALIZER_VERSION,
    NoEvidence,
    NormalizationError,
    validate_corpus_artifact,
)

__all__ = [
    "AUTHORSHIP_POLICY_VERSION",
    "CLAUDE_ADAPTER_VERSION",
    "ContentResolution",
    "EPISODE_STITCHER_VERSION",
    "NORMALIZER_VERSION",
    "NoEvidence",
    "NormalizationError",
    "ResolutionIntegrityError",
    "ResolutionRecord",
    "VerifiedRecord",
    "VerifiedSession",
    "normalize_claude",
    "resolve_content_pointer",
    "resolution_coverage",
    "validate_corpus_artifact",
]
