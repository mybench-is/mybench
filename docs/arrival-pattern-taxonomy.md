# Arrival-pattern classifier spike (MYB-19.3)

Status: implemented for local A8 normalized evidence only. No arrival-pattern
value is publishable until MYB-19.7 rules on a conditioned published form.

## Contract and vocabulary

Normalized-corpus schema v3 adds one `manifest.episodes[]` output for every
stitched `task_episode_id`. Each output contains:

- `arrival_pattern`, from the closed vocabulary `cold-start`, `prepared-spec`,
  `iterative-emergence`, and `unknown`;
- `classifier_version=1.0.0`; and
- `taxonomy_version=1.0.0`.

The same two versions are pinned in `manifest.normalizer`. A rule or vocabulary
change requires the corresponding version bump and reclassification. UNKNOWN
is an ordinary result, not missing data.

The classifier consumes only normalized manifest lineage and closed event
fields. It never resolves a pointer or reads raw record bytes, free text,
commitments, paths, timestamps, model metadata, or provider metadata.

## Version 1.0.0 rule table

The episode stitcher first identifies the unique root session using
`parent_session_id` and `episode_predecessor`. Multiple or absent roots classify
as `unknown`. Events are ordered by `record_index` and `subevent_index` within
that root.

The arrival window ends inclusively at the first `test` event or the first
`tool-call` whose `tool_family` is not `read` or `search`. When neither marker
exists, the complete root-session event stream is the arrival window. Rules
then run in this fixed precedence order:

| Output | Content-opaque structural rule | Decision |
|---|---|---|
| `prepared-spec` | The window has a `reference` with `reference_kind=plan` or `instruction`; or an arrival is a `pasted-span`; or the first arrival's `content_shape` is `size_band=long` or `line_band=many`. | GO as an operational structural class. |
| `iterative-emergence` | No prepared marker fired and arrivals occur at two or more distinct `record_index` values. An arrival is a `turn` with `authorship=human-turn` or a `pasted-span`. | GO as an operational structural class. |
| `cold-start` | No prepared marker fired, exactly one arrival exists, it is a human `turn`, and its `content_shape` is `size_band=short` plus `line_band=single`. | GO as an operational structural class. |
| `unknown` | No unique root or arrival exists, the observed shape falls between pinned rules, a record is composite, or no rule fires. | GO; first-class fail-closed result. |

The labels describe these structural conditions only. They do not assert the
meaning, completeness, quality, or difficulty of the arriving request.

## Stability assessment

| Marker | Stability boundary | Treatment |
|---|---|---|
| Episode root and membership | ADR-0013 stitcher contract; `episode_stitcher_version=2.0.0` | Re-derive on a stitcher-version change. |
| `event_kind`, `authorship`, `record_index`, `subevent_index` | Shared normalized-corpus adapter contract | Fail schema validation if absent or outside the closed vocabulary. |
| `reference_kind=plan|instruction` | Shared versioned reference-event rule | Never substitute raw names or pointer contents. |
| `pasted-span` and `content_shape` bands | Shared versioned adapter output | Treat only the normalized marker/band as input; never inspect the underlying text. |
| `tool_family` and `test` boundary markers | Shared versioned adapter output | Unknown and newly introduced structures do not gain inferred meaning. |

Claude Code and Codex therefore feed the same rule table after adapter
normalization. Provider-specific raw fields are not alternate evidence.

## Deferred to JUDGED

Content semantics cannot be proved by these markers. In particular, deciding
whether an arrival actually contains a specification, whether later human
turns refine the same task, whether a brief arrival relies on unstated context,
or whether a pasted span has a particular semantic role requires content
interpretation. Those questions are deferred to a future JUDGED classifier;
v1 neither resolves pointers nor approximates them with keyword, fuzzy, model,
or provider-specific rules. Structurally ambiguous episodes emit `unknown`.

## Privacy and publication boundary

The episode output stays in the private normalized A8 corpus under the mode-0700
local data directory. It inherits the normalized-evidence coverage in
THREAT_MODEL §2 A8, §2.1, §3.5–3.6, §4, ADV-1, ADV-4, and ADV-6. This task adds
no report, claim, registry, or other publication surface. MYB-19.7 must admit
and control any future conditioned aggregate before it can leave the local
store.
