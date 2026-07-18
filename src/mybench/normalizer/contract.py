"""Shared normalized-corpus contract for every transcript adapter.

Claude owns the v5 contract implementation, while the Claude and Codex sibling
adapters both use this module for the byte contract and artifact validator.
Keeping that public surface source-neutral prevents an adapter-specific schema
or Merkle fork.
"""

from mybench.normalizer.claude import (
    ARRIVAL_PATTERN_CLASSIFIER_VERSION as ARRIVAL_PATTERN_CLASSIFIER_VERSION,
    ARRIVAL_PATTERN_TAXONOMY_VERSION as ARRIVAL_PATTERN_TAXONOMY_VERSION,
    AUTHORSHIP_POLICY_VERSION as AUTHORSHIP_POLICY_VERSION,
    DOMAIN_NORMALIZED_CORPUS as DOMAIN_NORMALIZED_CORPUS,
    DOMAIN_NORMALIZED_EVENT as DOMAIN_NORMALIZED_EVENT,
    DOMAIN_NORMALIZED_MANIFEST as DOMAIN_NORMALIZED_MANIFEST,
    EPISODE_STITCHER_VERSION as EPISODE_STITCHER_VERSION,
    EPISODE_OPEN_MARKER_VERSION as EPISODE_OPEN_MARKER_VERSION,
    EPISODE_OUTCOME_CLASSIFIER_VERSION as EPISODE_OUTCOME_CLASSIFIER_VERSION,
    FORGE_ACTION_CLASSIFIER_VERSION as FORGE_ACTION_CLASSIFIER_VERSION,
    NORMALIZER_VERSION as NORMALIZER_VERSION,
    TOKEN_ACCOUNTING_POLICY_VERSION as TOKEN_ACCOUNTING_POLICY_VERSION,
    NoEvidence as NoEvidence,
    NormalizationError as NormalizationError,
    corpus_commitment as corpus_commitment,
    event_leaf_hash as event_leaf_hash,
    manifest_leaf_hash as manifest_leaf_hash,
    token_accounting_includes as token_accounting_includes,
    validate_corpus_artifact as validate_corpus_artifact,
)

__all__ = [
    "ARRIVAL_PATTERN_CLASSIFIER_VERSION",
    "ARRIVAL_PATTERN_TAXONOMY_VERSION",
    "AUTHORSHIP_POLICY_VERSION",
    "DOMAIN_NORMALIZED_CORPUS",
    "DOMAIN_NORMALIZED_EVENT",
    "DOMAIN_NORMALIZED_MANIFEST",
    "EPISODE_STITCHER_VERSION",
    "EPISODE_OPEN_MARKER_VERSION",
    "EPISODE_OUTCOME_CLASSIFIER_VERSION",
    "FORGE_ACTION_CLASSIFIER_VERSION",
    "NORMALIZER_VERSION",
    "TOKEN_ACCOUNTING_POLICY_VERSION",
    "NoEvidence",
    "NormalizationError",
    "corpus_commitment",
    "event_leaf_hash",
    "manifest_leaf_hash",
    "token_accounting_includes",
    "validate_corpus_artifact",
]
