# Metrics v0 — owner-approved specification (MYB-4.1)

**Status:** Accepted 2026-07-09 (owner sitting). MYB-4.2 implements this
verbatim. Report schema: `src/mybench/schemas/report.schema.json` (v1).
Threat-model tracing: §3 (published-report whitelist), §6 (trust tiers),
ADV-1 (report-granularity residual), ADV-2 (never overclaim).

## Disclosure policy (resolves mybench-ops OPEN_QUESTIONS #11)

**Aggregates + coarse histograms.** The report publishes machine-wide
totals and bucketed distributions only: no per-session values, no exact
per-day volumes, no time series in v0 (a quantized weekly strip arrives in
MYB-6.3 with its own recovery-resistance test), no hour-of-day granularity
ever (timezone/schedule leak, ADV-1). Rationale: sizes and fine-grained
timing correlate with what the work was; §3 permits counts/durations at
schema-defined granularity, and this document defines that granularity.

## Inputs and determinism (MYB-4.2 contract)

- Inputs: the ledger, the staged/published anchor artifacts, and — for
  binding coverage only — an enrolled public repo at a **pinned tip**
  recorded in the report. `generated_at` is supplied by the caller, never
  read from a clock inside the scorer.
- Same inputs ⇒ byte-identical report: canonical JSON (UTF-8, sorted keys,
  compact separators, trailing newline), metrics sorted by `name`,
  distribution objects keyed by bucket label with fixed label sets.
- Every bucket edge in this document is versioned: changing one is a
  schema_version event, not a tweak.
- "Latest row per session" = the session row with the highest `i` for each
  `session_id`; item counts always come from latest rows (growth rows
  supersede, never add).

## The v0 metric set

| # | name | value shape | tier | formula / justification |
|---|------|-------------|------|--------------------------|
| 1 | `anchored_span_days` | number | **PROVEN** | Days (UTC date diff) between earliest and latest published anchor-batch `ts`. Verifiable from public artifacts + OTS proofs alone; grows from the first anchor (2026-07-08) forward. |
| 2 | `ledger_span_days` | number | ANCHORED | Days between first and last ledger row `ts`. Capture-time claim: `ts` is when rows were appended (backfilled history collapses to its capture date — stated honestly; see caveat field). |
| 3 | `active_days` | integer | ANCHORED | Count of distinct UTC dates over session rows' `ts`. Same capture-time basis as #2. |
| 4 | `sessions_total` | integer | ANCHORED | Count of distinct `session_id` among session rows. Distinctness is a ledger-metadata fact, not anchor-verifiable (a session may grow across batches). |
| 5 | `anchored_capture_events` | integer | **PROVEN** | Sum of `session_count` over published anchor batches. The verifiable companion to #4: counts capture events, deliberately NOT deduplicated (a grown session anchors more than once). |
| 6 | `items_total` | integer | ANCHORED | Sum of `item_count` over latest rows. Item counts live only in ledger rows, not anchor artifacts. |
| 7 | `sessions_per_week_distribution` | object | ANCHORED | Histogram over weekly session counts: for each ISO week in [first, last] row ts, count sessions (by latest-row week of first appearance); publish the distribution of those weekly counts in buckets `0 / 1-5 / 6-15 / 16-40 / 40+`. A distribution over weeks — NOT a week-keyed time series. |
| 8 | `session_size_distribution` | object | ANCHORED | Latest-row `item_count` per session, bucketed `1-10 / 11-100 / 101-1000 / 1000+`. The coarse-histogram disclosure decision made concrete. |
| 9 | `source_breakdown` | object | ANCHORED | Distinct sessions per `source` (`claude-code` / `codex` / `synthetic`; synthetic must be zero in a real report — schema-checked by the scorer). |
| 10 | `binding_coverage` | object | **PROVEN** | Per enrolled repo (opt-in naming): bound commits (binding rows whose `commit_hash` ∈ repo history since enrollment) ÷ commits since enrollment, at the pinned tip recorded alongside. Binding rows are chain-tip-anchored; the denominator is publicly recomputable. |

(#4/#5 refine the approved "sessions_total (PROVEN)" line: the PROVEN batch
sum counts capture events, not distinct sessions — shipping both under
precise names beats shipping one subtly-wrong number.)

## Required caveats (report fields, not documentation)

- Metrics #2/#3/#4 (capture-time basis): the report carries a
  `backfill_note` stating that history captured by backfill is anchored as
  of anchor time (OQ #5 decision).
- JUDGED is excluded from v0; the schema keeps the tier enum
  version-extensible (future TEE-VERIFIED sits between ANCHORED and
  JUDGED — end-state notes §3) — new tiers arrive via schema_version bump,
  never by loosening validation.

## Exclusions (deliberate, test-guarded where possible)

Per-session values; exact per-day/per-week counts; hour-of-day anything;
ordered event sequences; repo names without per-repo opt-in confirmation;
token counts (arrive with MYB-6.4's reviewed ledger widening).
