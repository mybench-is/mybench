"""Shared normalized-corpus contract for every transcript adapter.

Claude owns the first implementation, but callers and sibling adapters use
this module for the byte contract and artifact validator. Keeping that public
surface source-neutral prevents a Codex-only schema or Merkle fork.
"""

from mybench.normalizer.claude import (
    AUTHORSHIP_POLICY_VERSION as AUTHORSHIP_POLICY_VERSION,
    DOMAIN_NORMALIZED_CORPUS as DOMAIN_NORMALIZED_CORPUS,
    DOMAIN_NORMALIZED_EVENT as DOMAIN_NORMALIZED_EVENT,
    DOMAIN_NORMALIZED_MANIFEST as DOMAIN_NORMALIZED_MANIFEST,
    EPISODE_STITCHER_VERSION as EPISODE_STITCHER_VERSION,
    NORMALIZER_VERSION as NORMALIZER_VERSION,
    NoEvidence as NoEvidence,
    NormalizationError as NormalizationError,
    corpus_commitment as corpus_commitment,
    event_leaf_hash as event_leaf_hash,
    manifest_leaf_hash as manifest_leaf_hash,
    validate_corpus_artifact as validate_corpus_artifact,
)

__all__ = [
    "AUTHORSHIP_POLICY_VERSION",
    "DOMAIN_NORMALIZED_CORPUS",
    "DOMAIN_NORMALIZED_EVENT",
    "DOMAIN_NORMALIZED_MANIFEST",
    "EPISODE_STITCHER_VERSION",
    "NORMALIZER_VERSION",
    "NoEvidence",
    "NormalizationError",
    "corpus_commitment",
    "event_leaf_hash",
    "manifest_leaf_hash",
    "validate_corpus_artifact",
]
