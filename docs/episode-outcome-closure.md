# Episode outcome and open-marker contract (MYB-19.5)

Status: implemented for private A8 normalized evidence only. THREAT_MODEL
v0.2.1 admits only bucketed, support-qualified episode-latency aggregates via a
separately reviewed ACTIVE descriptor. One-shot/practice-signal publication
remains behind OQ #33 and its registry gates.

## Versioned output

Normalized-corpus schema v4 adds these required fields to every stitched
`manifest.episodes[]` record:

- `episode_outcome`: `closed-with-bound-commit`, `abandoned`, or `unknown`;
- `outcome_classifier_version=1.0.0`;
- `episode_opened_at`: a canonical UTC timestamp or `unknown`; and
- `open_marker_version=1.0.0`.

The two versions are also pinned in `manifest.normalizer`. Episode membership
and identity remain governed by `episode_stitcher_version=2.0.0`; this task does
not change the stitching graph or task-episode id. A rule change requires a
version bump and corpus re-derivation.

## Session closure evidence

The trusted loader takes one consistent A3 snapshot and admits one Git closure
window only when all of these conditions hold:

1. exactly one `session_start` and one `session_end` exist for the opaque
   session id, in ledger row order;
2. both carry complete MYB-12.6 provenance and have equal opaque repo and
   worktree ids; and
3. binding candidates are same-repo `binding` rows strictly inside the
   lifecycle row range.

The pure normalizer reduces that window as follows:

| Session marker | Pinned structural condition |
|---|---|
| `bound-commit` | HEAD changed and the exact final `head_after` has a same-repo binding row inside the boundary range. |
| `ended-without-head-change` | The complete end boundary is observed, HEAD did not change, and no same-repo binding row lies inside the range. |
| `unknown` | Every other case, including missing/multiple boundaries, repo/worktree mismatch, reversed rows, a changed but unbound HEAD, or a binding that does not equal final HEAD. |

Only the closed marker enters A8 as `git_closure_evidence`; repo/worktree ids,
row indexes, bindings, and HEAD values do not. Thus episode outcome can be
re-derived from A8, while rebuilding the complete A8 corpus remains possible
from the existing A3 observations plus authenticated A9 records. There is no
capture change.

For one stitched episode, any `bound-commit` member yields
`closed-with-bound-commit`. `abandoned` requires every member to be
`ended-without-head-change`. All mixed, partial, or absent evidence yields
`unknown`. This is the MYB-12.6 structural association, not the future
MYB-10.10 replay-verified linkage proof.

## Episode-open marker

The unique root session is found from the same recorded parent/predecessor
graph used by the arrival classifier. Its observed lifecycle `started_at` is
the primary marker. If it is absent, the earliest normalized `observed_at` in
that root session is used. No unique root or no timestamp produces the literal
`unknown`; the normalizer never substitutes file time, commit time, child time,
or the current clock.

## ADR-0018 and publication boundary

The bound-commit outcome is a local structural closure marker. It does not
claim subject authorship, PR merge, merge time, acceptance, or task quality.
In particular, this task does not attribute a third-party-authored forge merge
commit to the subject and does not build a merge-time join. That future surface
requires an explicit ADR-0018 boundary ruling before implementation.

No raw outcome rate, conditioned one-shot rate, episode-open timestamp,
prompt-to-merge latency, or latency bucket is published by this task. The
v0.2.1 class admission does not activate a field: a latency aggregate needs a
separately reviewed ACTIVE descriptor implementing its granularity, controls,
tier, and coverage, while one-shot remains separately gated.
