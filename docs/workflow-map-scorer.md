# Workflow-map scorer v1

`mybench.scorer.workflow_map` computes the Workflow Fingerprint's workflow-map
aggregates from the MYB-10.4 episode identity projection and the MYB-13.2
structural phase classifier. It is a pure local CPU stage: inputs are explicit,
and it reads no clock, filesystem, environment, transcript content, or network.

## Input and identity boundary

The caller supplies the canonical-order normalized events already bound to the
explicit manifest episode list and the episode-stitcher version. The scorer
accepts only `ep-` identities matching the normalized-corpus schema, refuses
duplicates and unbound events, and counts distinct manifest identities for the
task-episode total. Identifiers are private grouping keys only and never enter
either output form.

## Deterministic formulas

- Consecutive identical known phases collapse within each episode. `UNKNOWN`
  breaks adjacency; phases on either side are never joined for transition or
  recurring-sequence mining.
- Exact local transition counts are corpus aggregates. Public transition cells
  are outgoing shares, banded after a five-transition cell floor.
- Recurring sequences are length 2–5 contiguous n-grams. Support is the count
  of distinct episodes containing the n-gram. Only support at least five is
  retained, then the top five sort by descending support and lexicographic
  sequence.
- A structural rework loop is an episode containing a version-1 backward edge
  from `BUILD|TEST|DEBUG` to `PLAN|BUILD`. Its report wording is descriptive,
  never a quality or deficit judgment.
- Authorship and model overlays are per-phase aggregate shares. Raw model
  strings reduce to the versioned public vocabulary; unrecognized values become
  `other` and missing values become `UNKNOWN`.
- Context-boundary rows annotate adjacent known phases for the boundary rate;
  they never expose a boundary position. Missing generation identity breaks
  adjacency rather than being guessed.
- Basis points use the report-v2 integer rounding rule. Public shares use the
  accepted `0-9%|10-24%|25-49%|50-74%|75-100%|UNKNOWN` bands.

## Privacy boundary

The output schema is closed. Local output contains only exact corpus aggregate
counts/rates, never an episode/session id or ordered per-episode stream. Public
atoms contain only support-qualified matrices, bands, the exact aggregate
episode total, fixed versions, and the ANCHORED ceiling. Tests scan the section
and logs for synthetic content, filename, and session canaries in raw and common
encodings, and prove the scanner fires on a planted canary.

This implements only admitted THREAT_MODEL v0.2.1 classes: corpus-level phase
transitions, recurring phase n-grams, human-vs-agent shares, rework-loop rates,
context-boundary rates, model-routing shares, task-episode totals, and evidence
confidence. It adds no publication, upload, listener, or local-live behavior.
