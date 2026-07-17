# Workflow Fingerprint report v2 — normative specification

**Status:** Accepted 2026-07-17 — owner-approved with ADR-0019 (MYB-13.1).
This document specifies the local report format and the maximum
publication-eligible projection; it does not publish anything or authorize
automatic publication.

Threat-model tracing: THREAT_MODEL §3.2–§3.6 (admitted report classes and
controls), §6 (trust tiers), ADV-1 (inference risk), ADV-2 (never overclaim),
ADR-0013 (input identity), ADR-0014 (execution environment → tier), ADR-0015
(presentation channels), and mybench-ops ADR-0019 (assembly architecture).

## 1. Architecture and compatibility

Report schema v2 is a **closed assembly envelope over registry-governed atomic
fields**:

1. A scorer emits a signed MYB-10 claim for one atomic report field. The claim
   cites one active descriptor-registry entry; that entry is the semantic
   authority for the field's input classes, value schema, formula version,
   support floor, disclosure class, inference risk, and presets.
2. The report assembler verifies every claim and its registry entry, then
   copies the claim value plus its digest and presentation metadata into the
   appropriate closed v2 section. It does not reinterpret the value.
3. `report.sig` (MYB-13.9) signs canonical `report.json` bytes. Individual
   claim signatures remain evidence inputs and are referenced by digest in the
   evidence manifest; they need not be duplicated in `report.json`.
4. The publication-preview builder (MYB-14.1) may select only fields whose
   registry disclosure is `PUBLISHABLE`, whose support and anchor gates pass,
   and whose risk class is admitted by the selected preset. `LOCAL_ONLY`
   fields never enter any preset. `internal-feature-only` claims never enter a
   report at all.

Every registry entry is one disclosure atom. If a semantic measurement has an
exact local form and a banded public form, those are two entries and two
claims; publication never edits fields out of a signed claim payload.

Schema v1's activity metrics remain in the top-level `metrics` array unchanged
so existing reports and the current renderer have a migration path. The seven
new Workflow Fingerprint sections live under `fingerprint`. A separate closed
`catalog_metrics` array is the registry-governed extension lane for metrics
outside those seven sections. It is empty in v0; later fields enter it without
an envelope bump only when an ACTIVE registry entry assigns the field to that
lane and every §3.6 gate passes. This reserves an honest report surface for
durability, throughput, override-survival, and later catalog families without
pretending they belong to a §6 fingerprint section.

The machine-readable envelope is
`src/mybench/schemas/report-v2.schema.json`; its canonical `$id` host is
`mybench.is`. Implementation must keep v1 validation available for old
reports.

## 2. Deterministic conventions

### 2.1 Named inputs

| Symbol | Versioned input class | Authority |
|---|---|---|
| `LEDGER` | validated ledger v1/v2 rows | hash-chained local ledger |
| `ANCHORS` | validated anchor events + private receipts | anchor event / receipt schemas |
| `EVENTS` | normalized session/git events | MYB-10.4 normalizer version |
| `PHASES` | per-episode phase stream over `TASK/PLAN/BUILD/TEST/DEBUG/REVIEW/COMMIT/UNKNOWN` | MYB-13.2 classifier version |
| `EPISODES` | normalized `task_episode_id` groups | ADR-0013 identity hierarchy |
| `LIFECYCLE` | start/resume/clear/compact/model-change events | ledger v2 + normalized historical markers |
| `META` | model/provider/effort/token metadata | MYB-12.5 contract + normalized historical fields |
| `GIT` | opted-in git evidence and pinned tips | MYB-10.5 normalized git store |
| `TOPOLOGY` | structure-only orchestration inventory snapshot | MYB-13.7 scanner version |
| `LANES` | normalized lane markers and stable event order; no prompt/result bytes | MYB-19.1 normalized-event widening |
| `PRICING` | versioned, checksummed pricing snapshot | MYB-13.6 pinned input |

No formula reads the clock, environment, or network. `generated_at`, registry
version/digest, pricing version/digest, scorer/classifier versions, and the
evidence window are explicit inputs.

Every row that consumes `LANES` remains a reserved registry entry until
MYB-19.1 supplies the normalized markers and the named scorer lands.

### 2.2 Common functions and bands

- `bp(n,d)`: if `d=0`, `UNKNOWN`; otherwise
  `floor((10000*n + floor(d/2))/d)`, capped at 10000. This is an integer
  basis-point value; floats are forbidden.
- `share_band(bp)`: `0-9%` for 0–999, `10-24%` for 1000–2499, `25-49%`
  for 2500–4999, `50-74%` for 5000–7499, `75-100%` for 7500–10000, or
  `UNKNOWN`.
- `count_band(n)`: `0`, `1-4`, `5-19`, `20-99`, `100-999`, or `1000+`.
- `confidence(coverage_bp)`: `UNKNOWN` when coverage is unknown; `LOW` below
  5000, `MEDIUM` from 5000–7499, and `HIGH` from 7500–10000. A
  characterization's confidence is the weaker of this result and the pinned
  classifier confidence.
- `token_band(n)`: `0`, `1-9k`, `10-99k`, `100-999k`, `1m-9.9m`, `10m+`.
- `cost_band(micro_usd)`: `$0`, `<$1`, `$1-9`, `$10-99`, `$100-999`,
  `$1000+`. Exact local costs are integer micro-USD, never floats.
- `ratio_band(n,d)`: `UNKNOWN` for `d=0`; otherwise `<0.5`, `0.5-0.99`,
  `1.0-1.99`, or `2.0+`, compared by integer cross-multiplication.

Arrays and cell lists are sorted lexicographically by their dimension tuple.
Top-N lists sort by descending support and then lexicographically. Changing a
taxonomy, formula, band edge, vocabulary, support floor, or sorting rule is a
descriptor version bump and re-disclosure event; changing the envelope is a
report schema bump.

`claim_digest` is lowercase SHA-256 over the claim's canonical signed bytes.
Section fields sort by `(registry_id, registry_version, claim_digest)` and a
report contains at most one field for a given registry id. Evidence-period
start must not follow end; `fingerprint.summary.evidence_period` must equal the
top-level `evidence_period`. `pricing_snapshot` is required whenever any cost
field is present. These cross-field rules are semantic validation performed in
addition to JSON Schema validation.

`caveats` contains controlled codes, not display prose. An active registry
entry owns the required code set and the corresponding display text; combined
registry/report validation rejects missing or extra codes. Initial codes are
`provider-reported-inflatable`, `persistence-not-quality`, and
`diagnostic-not-quality`. Display text remains subject to the registry's
banned-framings check.

Every atomic field wrapper also reserves these optional shapes:

- `reference_frame = {reference_corpus_id, reference_version, as_of_date,
  percentile_band}`;
- `conditioning = {axis, cell, min_support_met}`; and
- `tier_qualifier = unattested|attested`.

JSON Schema closes and type-checks those shapes. Registry/assembler validation
is the activation layer: `reference_frame` MUST be absent until both a §3
percentile class and the OQ #52 population ruling land; `tier_qualifier` MUST
be absent until MYB-7.7 activates JUDGED qualifiers; and a PUBLISHABLE field
can never carry `conditioning.min_support_met=false`. Below-support public
cells are absent. Once qualifiers activate they apply only to JUDGED claims,
must match `execution_env`, and remain subject to ADR-0014's cap rule.

### 2.3 Support, coverage, anchoring, and absence

- Unless a row below states a stricter floor, a report field requires at least
  5 eligible sessions or 5 eligible episodes. Below the floor the field is
  absent, never zero-valued; the section status explains
  `insufficient-evidence`.
- A rate denominator contains only observations for which the required marker
  is present. Missing markers reduce the adjacent coverage field; they are not
  imputed into numerator or denominator.
- A local-unattested content-derived field targets ANCHORED presentation under
  ADR-0014. It is publication-eligible only when every cited corpus commitment
  is covered by a confirmed anchor. The private report may show it while
  partial/pending, but must carry the separate anchor-state annotation.
- Backfilled evidence carries the IMPORTED annotation. While
  `anchored_span_days < 14`, capture-time fields retain the backfill annotation
  and cadence surfaces are suppressed, per THREAT_MODEL §3.4.
- `UNKNOWN` means the evidence cannot support the claim. It never means zero.

## 3. Field catalog

`PUBLISHABLE (R0)` is eligible for the employer-safe and full presets;
`PUBLISHABLE (R1)` is eligible only through individual opt-in/full-preset
review with its risk note. Eligibility is not publication: every publication
still requires the explicit preview/owner action.

Where a row names both an exact/local field and a band/public field, they are
separate registry entries with the suffixes `.exact` and `.band`.

### 3.1 Workflow summary

| Field id | Value and formula | Tier | Support | Disclosure |
|---|---|---|---|---|
| `fingerprint.summary.primary_pattern` | Classify each eligible episode from its collapsed known phase stream: `plan-build-test` when PLAN precedes BUILD and TEST follows BUILD with no backward rework edge; `plan-build-debug` when PLAN precedes BUILD and a pinned rework edge occurs; `build-test` when BUILD precedes/has no PLAN and TEST follows; `build-debug` when BUILD precedes/has no PLAN and a rework edge occurs; otherwise `mixed`. Corpus label = greatest episode count (ties lexicographic). Confidence is the weaker of eligible-episode coverage and the winning-label share. No free text. | ANCHORED; `characterization` | 20 episodes; winning label support ≥5 | PUBLISHABLE (R1) |
| `fingerprint.summary.recurring_sequences` | Top 5 contiguous `PHASES` n-grams of length 2–5 after adjacent duplicate collapse. N-grams containing UNKNOWN are excluded without bridging. Each cell is `(sequence, share_band(distinct supporting episodes / eligible episodes))`. | ANCHORED | ≥5 distinct episodes per n-gram | PUBLISHABLE (R0) |
| `fingerprint.summary.task_episode_total` | Exact count of distinct valid `task_episode_id` values in `EPISODES`. | ANCHORED | 5 episodes | PUBLISHABLE (R0) |
| `fingerprint.summary.evidence_period` | UTC dates of min/max included event time after all filters; no finer timestamp. | ANCHORED | 5 sessions | PUBLISHABLE (R0) |
| `fingerprint.summary.overall_coverage` | Rounded integer mean of `coverage_basis_points` across every non-summary field with a defined denominator. Absent evidence contributes its computed reduced coverage; `not-supported` implementation sections are excluded and remain visibly named by section status. | ANCHORED | 1 field with a denominator | PUBLISHABLE (R0) |
| `fingerprint.summary.confidence` | `confidence(overall_coverage)` reduced to the weakest confidence among fields shown in the summary. | ANCHORED | same as overall coverage | PUBLISHABLE (R0) |

### 3.2 Workflow map

For phase adjacency, collapse consecutive identical phase labels within each
episode. UNKNOWN breaks adjacency; phases on either side are never joined.

| Field id | Value and formula | Tier | Support | Disclosure |
|---|---|---|---|---|
| `fingerprint.workflow_map.transition_counts.exact` | Cells `(from,to,count)` over adjacent known `PHASES`. | ANCHORED | 5 episodes | LOCAL_ONLY |
| `fingerprint.workflow_map.transition_shares.band` | Cells `(from,to,share_band(count / outgoing_count(from)))`; cells with count <5 are absent. | ANCHORED | 5 transitions per cell | PUBLISHABLE (R0) |
| `fingerprint.workflow_map.authorship_shares.exact` | Cells `(phase, HUMAN|AGENT|UNKNOWN, bp(events / phase events))` from MYB-10.4 authorship tags. | ANCHORED | 5 tagged events per phase | LOCAL_ONLY |
| `fingerprint.workflow_map.authorship_shares.band` | Same cells with `share_band`; subject-type-neutral labels only. | ANCHORED | 5 tagged events per cell | PUBLISHABLE (R0) |
| `fingerprint.workflow_map.model_routing.exact` | Cells `(phase, pinned model id|other|UNKNOWN, bp(events / phase events))`. Provider/substrate is operational metadata only. | ANCHORED | 5 metadata-bearing events per cell | LOCAL_ONLY |
| `fingerprint.workflow_map.model_routing.band` | Same cells with `share_band`; only pinned public vocabulary plus `other/UNKNOWN`. | ANCHORED | 5 events per cell | PUBLISHABLE (R1) |
| `fingerprint.workflow_map.rework_loop_rate.exact` | `bp(episodes containing a pinned backward edge BUILD/TEST/DEBUG→PLAN/BUILD, eligible episodes)`. The exact edge set is classifier-versioned. | ANCHORED | 5 episodes | LOCAL_ONLY |
| `fingerprint.workflow_map.rework_loop_rate.band` | `share_band` of the exact rate; neutral wording, never deficit framing. | ANCHORED | 5 episodes | PUBLISHABLE (R0) |
| `fingerprint.workflow_map.context_boundary_rate.exact` | `bp(known phase transitions crossing a context generation, known phase transitions)` using ADR-0013 identities. | ANCHORED | 5 known transitions | LOCAL_ONLY |
| `fingerprint.workflow_map.context_boundary_rate.band` | `share_band` of the exact rate; no boundary position or session ordering. | ANCHORED | 5 known transitions | PUBLISHABLE (R0) |
| `fingerprint.workflow_map.unknown_phase_share` | `share_band(UNKNOWN classified events / all classified events)`; never suppressed because it qualifies the graph. | ANCHORED | 5 events | PUBLISHABLE (R0) |

### 3.3 Model role profile

Phases use the pinned taxonomy. Models/providers are restricted to the pinned
public vocabulary; unrecognized identifiers map to `other`, missing values to
`UNKNOWN`. Effort uses `low|medium|high|max|UNKNOWN` unless the capture schema
version pins a successor vocabulary.

| Field id | Value and formula | Tier | Support | Disclosure |
|---|---|---|---|---|
| `fingerprint.model_role.model_shares.exact` | Cells `(phase,model,bp(events / metadata-bearing phase events))`. | ANCHORED | 5 events per cell | LOCAL_ONLY |
| `fingerprint.model_role.model_shares.band` | Same cells with `share_band`. | ANCHORED | 5 events per cell | PUBLISHABLE (R1) |
| `fingerprint.model_role.provider_shares.exact` | Cells `(phase,provider,bp(events / metadata-bearing phase events))`; provider never appears in trust copy. | ANCHORED | 5 events per cell | LOCAL_ONLY |
| `fingerprint.model_role.provider_shares.band` | Same cells with `share_band`, pinned vocabulary only. | ANCHORED | 5 events per cell | PUBLISHABLE (R1) |
| `fingerprint.model_role.effort_shares.exact` | Cells `(phase,effort,bp(events / metadata-bearing phase events))`. | ANCHORED | 5 events per cell | LOCAL_ONLY |
| `fingerprint.model_role.effort_shares.band` | Same cells with `share_band`. | ANCHORED | 5 events per cell | PUBLISHABLE (R0) |
| `fingerprint.model_role.evidence_quality` | Cells `(phase, coverage_band, confidence)` where coverage is events with both known phase and requested metadata divided by eligible events. UNKNOWN is explicit. | ANCHORED | 5 eligible events | PUBLISHABLE (R0) |

### 3.4 Context-management profile

Each exact rate is integer basis points; each public rate is its `share_band`.
Every field carries lifecycle-marker coverage from §3.7.

| Field id pair (`.exact` / `.band`) | Exact formula | Tier | Support | Public risk |
|---|---|---|---|---|
| `fingerprint.context.fresh_session_rate` | fresh/startup sessions ÷ sessions with known start trigger | ANCHORED | 5 sessions | R0 |
| `fingerprint.context.resume_rate` | resume-triggered starts ÷ sessions with known start trigger | ANCHORED | 5 sessions | R0 |
| `fingerprint.context.clear_rate` | clear-triggered generations ÷ generations with known trigger | ANCHORED | 5 generations | R0 |
| `fingerprint.context.manual_compactions` | exact count locally; `count_band` publicly | ANCHORED | 5 lifecycle events | R0 |
| `fingerprint.context.automatic_compactions` | exact count locally; `count_band` publicly | ANCHORED | 5 lifecycle events | R0 |
| `fingerprint.context.generations_per_episode` | local cells `(count_band, exact episode count)`; public distribution uses banded share per generation-count band | ANCHORED | 5 episodes | R0 |
| `fingerprint.context.one_context_episode_rate` | episodes with exactly one known context generation ÷ episodes with generation coverage | ANCHORED | 5 episodes | R0 |
| `fingerprint.context.fresh_phase_split` | fresh sessions whose first known phase is PLAN vs BUILD/TEST/DEBUG/REVIEW/COMMIT vs UNKNOWN, divided by fresh sessions | ANCHORED | 5 fresh sessions | R0 |
| `fingerprint.context.model_change_boundary_rate` | known context boundaries with model change ÷ boundaries with model coverage on both sides | ANCHORED | 5 boundaries | R1 |
| `fingerprint.context.lane_switch_count_distribution` | LOCAL_ONLY cells `(count_band, exact episode count)`: for each eligible episode, count adjacent `LANES` events whose known normalized lane differs; an unknown lane breaks adjacency without bridging, then histogram the counts | ANCHORED | 5 episodes with lane coverage | no public form until MYB-19.7 |

For all rows except the two count rows, `.band` means `share_band` or a
banded distribution as stated. The `.exact` entry is LOCAL_ONLY and `.band`
is PUBLISHABLE at the listed risk.

### 3.5 Orchestration topology

The scanner is structure-only: contents are never read. Names and paths may
appear only in the private report.

Rows that consume `LANES` remain reserved until MYB-19.1 supplies normalized
lane markers and their named scorer lands. They do not widen the structure-only
scanner or authorize it to read orchestration-file contents.

| Field id | Value and formula | Tier | Support | Disclosure |
|---|---|---|---|---|
| `fingerprint.topology.named_hierarchy` | Sorted local tree of instruction levels, skill/hook/custom-agent names, plan/task directory names, validation-script names, worktree convention labels, and roots relative to the consented scan root. | ANCHORED | 1 consented root | LOCAL_ONLY |
| `fingerprint.topology.structure_counts.exact` | Exact counts by fixed category from `TOPOLOGY`; names/paths absent. | ANCHORED | 1 root | LOCAL_ONLY |
| `fingerprint.topology.structure_counts.band` | `count_band` by fixed category; category emitted only with support ≥5 across independent observed instances. | ANCHORED | k≥5 per category | PUBLISHABLE (R1) |
| `fingerprint.topology.instruction_depth` | Local exact maximum depth; public `count_band`, with paths absent. | ANCHORED | k≥5 observed instruction files | PUBLISHABLE (R1); exact form LOCAL_ONLY |
| `fingerprint.topology.presence_flags` | Fixed-taxonomy booleans for lanes, worktrees, skills, hooks, custom agents, plan/task dirs, and validation scripts; true requires ≥5 supporting instances, otherwise field is absent rather than false. | ANCHORED | k≥5 | PUBLISHABLE (R1) |
| `fingerprint.topology.evidence_sources` | Coverage cells for `file-structure` and `transcript-delegation`; scan-time topology is explicitly labeled, never represented as period-wide. | ANCHORED | one source | PUBLISHABLE (R0) |
| `fingerprint.topology.peak_parallel_lanes.exact` | LOCAL_ONLY histogram cells `(exact peak lane count, exact session count)`. Per session, peak is the largest number of distinct known `LANES` simultaneously active under the MYB-6.8 scorer's versioned interval rule; no session id, timestamp, or global scalar is retained. | ANCHORED | 5 sessions with lane start/end coverage | LOCAL_ONLY |
| `fingerprint.topology.peak_parallel_lanes.band` | Cells `(count_band(peak lanes), share_band(sessions in band / eligible sessions))`; a cell is absent below k=5. This is a within-session distribution, never a global peak or cross-session concurrency claim. | ANCHORED | k≥5 sessions per cell | PUBLISHABLE (R1) |
| `fingerprint.topology.lane_event_share_distribution` | LOCAL_ONLY cells `(share_band, exact lane-episode count)`: within each eligible episode, compute each known lane's tagged-event share, then histogram the shares without lane names or ids. This is a deterministic utilization proxy, not an interleaving-quality judgment. | ANCHORED | 5 episodes with lane coverage | LOCAL_ONLY; no public form until MYB-19.7 |

### 3.6 Token and cost profile

Token counts are provider-reported and potentially inflatable. Every token and
cost field carries the controlled caveat code
`provider-reported-inflatable`; every cost field additionally names `PRICING`
version/digest and states that it estimates the user's historical spend, not
Mybench compute or work quality.

| Field id | Value and formula | Tier | Support | Disclosure |
|---|---|---|---|---|
| `fingerprint.token_cost.tokens_by_model.exact` | Integer token sum by pinned model/other/UNKNOWN from `META`. | ANCHORED | 5 metadata-bearing sessions | LOCAL_ONLY |
| `fingerprint.token_cost.tokens_by_model.band` | `token_band` of the same sums. | ANCHORED | 5 sessions per cell | PUBLISHABLE (R1) |
| `fingerprint.token_cost.tokens_by_phase.exact` | Integer token sum by `PHASES`; unattributable tokens map to UNKNOWN. | ANCHORED | 5 phase-attributed sessions | LOCAL_ONLY |
| `fingerprint.token_cost.tokens_by_phase.band` | `token_band` of the same sums. | ANCHORED | 5 sessions per cell | PUBLISHABLE (R0) |
| `fingerprint.token_cost.cost_by_model.exact` | Integer micro-USD: input/output/cache token integers × matching `PRICING` integer rates, divided with the snapshot's pinned rounding rule. | ANCHORED | 5 sessions per cell | LOCAL_ONLY |
| `fingerprint.token_cost.cost_by_model.band` | `cost_band` of the same sums. | ANCHORED | 5 sessions per cell | PUBLISHABLE (R1) |
| `fingerprint.token_cost.cost_per_episode.exact` | Distribution of integer micro-USD episode totals into fixed local log buckets; no episode id/value appears. | ANCHORED | 5 episodes | LOCAL_ONLY |
| `fingerprint.token_cost.cost_per_episode.band` | Banded share of episodes in the pinned cost buckets; no point value. | ANCHORED | 5 episodes | PUBLISHABLE (R0) |
| `fingerprint.token_cost.planning_to_implementation_ratio.exact` | Integer pair `(planning_tokens, implementation_tokens)`; UNKNOWN when either phase coverage is insufficient. | ANCHORED | 5 phase-attributed episodes | LOCAL_ONLY |
| `fingerprint.token_cost.planning_to_implementation_ratio.band` | `ratio_band(planning_tokens, implementation_tokens)`. | ANCHORED | 5 episodes | PUBLISHABLE (R0) |
| `fingerprint.token_cost.rework_token_share` | Exact bp locally / `share_band` publicly: tokens in classifier-versioned rework-loop segments ÷ phase-attributed tokens. | ANCHORED | 5 rework-eligible episodes | PUBLISHABLE (R0); exact form LOCAL_ONLY |
| `fingerprint.token_cost.abandoned_session_token_share` | Exact bp locally / `share_band` publicly: tokens in sessions with a pinned structural abandoned outcome ÷ covered tokens. No semantic guess. | ANCHORED | 5 deterministically classified sessions | PUBLISHABLE (R0); exact form LOCAL_ONLY |
| `fingerprint.token_cost.tokens_before_first_passing_test` | Exact local log-bucket distribution over linked episodes; only built when pinned test-result markers exist. | ANCHORED | 5 linked episodes | LOCAL_ONLY for v2 |
| `fingerprint.token_cost.tokens_per_accepted_changed_line` | Exact local diagnostic ratio over MYB-10.10-linked accepted lines; required caveat code `diagnostic-not-quality`. | ANCHORED | 5 linked episodes | LOCAL_ONLY; structurally absent from presets/badges |

### 3.7 Evidence coverage

Coverage values use exact basis points locally and `share_band` publicly,
except the existing PROVEN v1 values retained verbatim. Missing/ambiguous
categories are a pinned enum:

`missing-marker`, `missing-pointer-target`, `conflicting-evidence`,
`unsupported-harness-version`, `unlinked-session`, `unknown-phase`,
`missing-model`, `missing-effort`, `missing-token-data`.

| Field id | Formula | Tier | Support | Disclosure |
|---|---|---|---|---|
| `fingerprint.coverage.git_session_linkage` | Until MYB-10.10 lands, the existing `binding_coverage` definition at pinned opted-in repo tips, labeled `binding-based stand-in`; successor = linked sessions ÷ eligible sessions. | PROVEN for binding coverage; ANCHORED for successor session linkage | one opted-in repo | PUBLISHABLE (R0) |
| `fingerprint.coverage.model` | events with recognized model or `other` ÷ model-eligible events | ANCHORED | 5 events | PUBLISHABLE (R0) |
| `fingerprint.coverage.effort` | events with recognized effort ÷ effort-eligible events | ANCHORED | 5 events | PUBLISHABLE (R0) |
| `fingerprint.coverage.context_lifecycle` | sessions with at least one reliable lifecycle marker ÷ eligible sessions | ANCHORED | 5 sessions | PUBLISHABLE (R0) |
| `fingerprint.coverage.token_data` | sessions with structurally valid token metadata ÷ token-eligible sessions | ANCHORED | 5 sessions | PUBLISHABLE (R0) |
| `fingerprint.coverage.provenance_split` | Existing metrics-v0 `evidence_provenance_split` formula over anchored row ranges; fixed IMPORTED/LIVE keys. | PROVEN | one anchored row | PUBLISHABLE (R0) |
| `fingerprint.coverage.missing_ambiguous.exact` | Exact counts by the pinned category enum only; no names, ids, or paths. | ANCHORED | none | LOCAL_ONLY |
| `fingerprint.coverage.missing_ambiguous.band` | `count_band` by category; categories with zero evidence are explicit only when the denominator exists. | ANCHORED | denominator exists | PUBLISHABLE (R0) |

## 4. Evidence-quality contract

Every fingerprint field entry carries:

- `coverage_basis_points` (0–10000) or `UNKNOWN`;
- `confidence` (`LOW|MEDIUM|HIGH|UNKNOWN`);
- `anchor_state` (`covered|partial|pending|not-applicable`);
- `disclosure` (`LOCAL_ONLY|PUBLISHABLE`), exactly matching the registry;
- `inference_risk` (`R0|R1|R2`), exactly matching the registry;
- the exact controlled caveat-code set required by the registry;
- optional reserved `reference_frame`, `conditioning`, and `tier_qualifier`
  shapes, subject to the activation rules in §2.2.

The report assembler rejects any mismatch. A section is `available`,
`insufficient-evidence`, or `not-supported`; all seven section keys remain in
the local report so missing functionality cannot masquerade as a clean zero.

### 4.1 Expanded catalog disposition

The registry envelope avoids inventing premature report fields. The following
disposition is part of the v2 freeze:

| Family | v2 disposition |
|---|---|
| Token headline bands | token/cost section; PUBLISHABLE under the admitted class with `provider-reported-inflatable` |
| Within-session peak-parallel-lane distribution | topology section; PUBLISHABLE at k≥5; global peak/cross-session concurrency deferred |
| Blame survival, throughput, override survival | future ACTIVE entries in `catalog_metrics`; survival requires `persistence-not-quality`; attribution remains ANCHORED |
| Deterministic lane-switch/utilization histograms | LOCAL_ONLY rows above; publication waits on MYB-19.7 |
| Agent-hours/durations, longest-run forms, episode latency, externalization/spec churn | no active v2 field; re-derivable later and gated by MYB-19.7 |
| One-shot, steering, acceptance | deferred behind the arrival/closure classifiers and OQ #33 practice-signal gate |
| Interleaving-quality and all other JUDGED families | deferred wholesale to the MYB-7 track; deterministic histograms do not imply quality |
| Forge actions | normalized-store derivation through MYB-19.11 only; no v2 report field |
| Percentiles | reserved shape only; never populated or published before the §3/OQ #52 gates |

Exact public token totals, public token-per-line ratios, weekly-keyed LOC
series, graded first-pass-acceptance framing, published percentiles, and
headline per-session extrema remain inadmissible without an owner revision.

## 5. Publishable subset (THREAT_MODEL §3.2 input/output)

Every current PUBLISHABLE field maps to an already-admitted v0.2.0 class:

| Report field family | THREAT_MODEL §3.2 class |
|---|---|
| `summary.primary_pattern`; topology structure/depth/presence and within-session peak-lane distribution | Orchestration-topology aggregates + archetype gallery |
| `summary.recurring_sequences` | Recurring phase-sequence n-grams |
| `summary.task_episode_total` | Task-episode totals + bucketed per-episode distributions |
| `summary.evidence_period`, `summary.overall_coverage`, `summary.confidence`, unknown/missing/coverage fields | Evidence-coverage section, with §3.4 temporal rules |
| Workflow-map transition shares | Corpus-level phase-transition aggregates |
| Workflow-map authorship shares | Human-vs-agent activity shares |
| Workflow-map rework rates | Rework-loop rates |
| Workflow-map context-boundary rates and context-management profile | Context-boundary and context-management rates |
| Workflow-map model routing and model/provider/effort profile | Model/provider/effort role profile |
| Token/cost bands, ratios, and bucketed episode distributions | Token/cost profile; task-episode distributions where applicable |
| Existing schema-v1 activity metrics | Counts, durations, cadence histograms, coverage percentages, streak lengths (the v0 set) |
| Future `catalog_metrics` blame-survival fields | Blame-survival cohorts |

The complete publication-eligible set is exactly the catalog rows marked
PUBLISHABLE above plus future `catalog_metrics` entries whose ACTIVE registry
versions cite an already-admitted §3.2 class, subject to all of these gates:

1. confirmed anchor coverage for every cited corpus commitment;
2. descriptor support/k-suppression satisfied;
3. selected preset admits the risk class (`employer-safe` = R0 only);
4. output, report location, caveat codes, and reserved-block state validate
   against the exact active registry entry;
5. no ordered per-session/per-episode sequence, id, timestamp, name, path,
   raw model string, or point value forbidden by THREAT_MODEL §3.5;
6. explicit owner preview and publication action.

This list is an instance-level implementation of the class ceilings already
adopted in THREAT_MODEL v0.2.0; it does not widen those ceilings. A new field
is LOCAL_ONLY until both this spec/ADR and the threat model admit it.

## 6. Required implementation and test handoff

- MYB-13.2–13.8: activate atomic registry entries with closed output schemas,
  formulas, support floors, disclosure, risk, caveats, and preset membership
  matching this catalog. Every output path gets a canary leak scan and planted
  firing test.
- MYB-10.9: validate claims and registry entries before rendering; group by
  the seven closed section names or the reserved `catalog_metrics` lane; apply
  ADR-0014/0015 tier presentation. Tests must reject inactive reserved blocks,
  unresolved/inactive catalog entries, missing required caveat codes, and
  qualifier/environment mismatches.
- MYB-13.9: assemble/sign report v2 and write the evidence manifest; preserve
  v1 report validation for old bundles.
- MYB-14.1: derive the redaction manifest and public preview from registry
  disclosure/presets, never from omission or a hand-maintained renderer list.
- THREAT_MODEL_TRACEABILITY: map the v2 assembly, each scorer, local bundle,
  and preview boundary to §3/§6/ADV-1/ADV-2 before implementation closes.

All tests use synthetic fixtures. No real transcript, filename, session id,
nonce, or local path belongs in this specification, schemas, fixtures, logs,
or repository history.
