# Metrics v0 — owner-approved specification (MYB-4.1)

**Status:** Accepted 2026-07-09 (owner sitting). MYB-4.2 implements this
verbatim. Report schema: `src/mybench/schemas/report.schema.json` (v1).
Threat-model tracing: §3 (published-report whitelist), §6 (trust tiers),
ADV-1 (report-granularity residual), ADV-2 (never overclaim).
Exclusions section updated 2026-07-14 (ADR sitting 2) to conform to
THREAT_MODEL v0.2.0's class-based §3 (MYB-16.2 AC #4); this document remains
the instance-level granularity spec for the shipped v0 metric set, under the
§3 ceilings.

## Disclosure policy (resolves mybench-ops OPEN_QUESTIONS #11)

**Aggregates + coarse histograms.** The report publishes machine-wide
totals and bucketed distributions only: no per-session values, no exact
per-day volumes, no time series in v0 (a quantized weekly strip arrives in
MYB-6.3 with its own recovery-resistance test), no hour-of-day granularity
ever (timezone/schedule leak, ADV-1). Rationale: sizes and fine-grained
timing correlate with what the work was; §3 permits counts/durations at
schema-defined granularity, and this document defines that granularity.

## Inputs and determinism (MYB-4.2 contract)

- Inputs: the ledger, the staged/published date-only anchor events, and — for
  binding coverage only — an enrolled public repo at a **pinned tip**
  recorded in the report. `generated_at` is supplied by the caller, never
  read from a clock inside the scorer.
- Same inputs ⇒ byte-identical report: canonical JSON (UTF-8, sorted keys,
  compact separators, trailing newline), metrics sorted by `name`,
  distribution objects keyed by bucket label with fixed label sets.
- Every bucket edge in this document is versioned: changing one is a
  schema_version event, not a tweak. Bucket LABELS are zero-padded so
  canonical sorted-JSON order is numeric order (2026-07-09 pre-publication
  fix, handoff #4); display layers strip the padding.
- "Latest row per session" = the session row with the highest `i` for each
  `session_id`; item counts always come from latest rows (growth rows
  supersede, never add).
- Ledger rows are ordered by integer `i` before derivation; anchor events are
  ordered by `(row_start, row_end, date, root, chain_tip)`. Input order never
  affects report bytes. The report header lists the distinct ledger and anchor
  `schema_version` values consumed, alongside the scorer/report versions.

## The v0 metric set

| # | name | value shape | tier | formula / justification |
|---|------|-------------|------|--------------------------|
| 1 | `anchored_span_days` | number | **PROVEN** | Days (UTC date diff) between earliest and latest published anchor-event `date`. Verifiable from public artifacts + OTS proofs alone; grows from the first anchor (2026-07-08) forward. |
| 2 | `ledger_span_days` | number | ANCHORED | Days between first and last ledger row `ts`. Capture-time claim: `ts` is when rows were appended (backfilled history collapses to its capture date — stated honestly; see caveat field). |
| 3 | `active_days` | integer | ANCHORED | Count of distinct UTC dates over session rows' `ts`. Same capture-time basis as #2. |
| 4 | `sessions_total` | integer | ANCHORED | Count of distinct `session_id` among session rows. Distinctness is a ledger-metadata fact, not anchor-verifiable (a session may grow across batches). |
| 5 | `anchored_capture_events` | integer | **PROVEN** | Sum of `session_count` over published date-only anchor events. The verifiable companion to #4: counts capture events, deliberately NOT deduplicated (a grown session anchors more than once). |
| 6 | `items_total` | integer | ANCHORED | Sum of `item_count` over latest rows. Item counts live only in ledger rows, not anchor artifacts. |
| 7 | `sessions_per_week_distribution` | object | ANCHORED | Histogram over weekly session counts: for each ISO week in [first, last] row ts, count sessions (by latest-row week of first appearance); publish the distribution of those weekly counts in buckets `00 / 01-05 / 06-15 / 16-40 / 41+`. A distribution over weeks — NOT a week-keyed time series. |
| 8 | `session_size_distribution` | object | ANCHORED | Latest-row `item_count` per session, bucketed `0001-0010 / 0011-0100 / 0101-1000 / 1001+`. The coarse-histogram disclosure decision made concrete. |
| 9 | `source_breakdown` | object | ANCHORED | Distinct sessions per `source` (`claude-code` / `codex` / `synthetic`; synthetic must be zero in a real report — schema-checked by the scorer). |
| 10 | `binding_coverage` | object | **PROVEN** | Per enrolled repo (opt-in naming): bound commits (binding rows whose `commit_hash` ∈ repo history since enrollment) ÷ commits since enrollment, at the pinned tip recorded alongside. Binding rows are chain-tip-anchored; the denominator is publicly recomputable. |
| 11 | `anchor_latency_distribution` | object | ANCHORED | For every row covered by a date-only anchor event with a matching private `anchor_receipt`, compute `receipt_ts - covered_row.ts`; count only coarse half-open buckets `00_under_5m` = [0, 5m), `01_5m_to_1h` = [5m, 1h), `02_1h_to_24h` = [1h, 24h), `03_1d_to_7d` = [1d, 7d), and `04_7d_plus` = [7d, ∞). A covered row whose event has no receipt increments `05_unknown`. Negative intervals fail closed. `receipt_ts` is the local instant after the first successful OTS-calendar response; the receipt row's later envelope `ts` is never substituted. This is ANCHORED/self-attested, not the PROVEN Bitcoin block-header upper-bound clock. |
| 12 | `evidence_provenance_split` | object | **PROVEN** | Percentages over the union of row indices named by supplied anchor events. At and after the ledger v3 `schema_version` boundary, an explicit row `provenance` (`IMPORTED` or `LIVE`) wins and an absent field on a frozen v1/v2 row defaults to `LIVE`; before that boundary, the legacy rule remains reproducible (first event's range is `IMPORTED`, later ranges are `LIVE`). Duplicate coverage is counted once and the first supplied range wins for legacy rows. Values are rounded to four decimal places and emitted under the fixed keys `IMPORTED / LIVE`; no row identifiers or counts publish. Unanchored private rows are excluded because their presence is not publicly verifiable; freshness and continuity surface the anchored boundary separately. With no anchored rows both shares are `0.0`, meaning “no anchored denominator,” not zero local activity. |
| 13 | `anchor_chain_continuity` | boolean | **PROVEN** | `true` iff the supplied ledger rows form a valid `i`/`prev`/`h` hash chain with genesis exactly at row 0, at least one anchor exists, the first range begins at 0, every anchor range begins at the prior range's `row_end`, and every event `chain_tip` equals the `h` of its last covered row. A trailing valid ledger suffix may remain unanchored without making the anchored ranges discontinuous. |

(#4/#5 refine the approved "sessions_total (PROVEN)" line: the PROVEN batch
sum counts capture events, not distinct sessions — shipping both under
precise names beats shipping one subtly-wrong number.)

## Evidence-coverage header

`anchored_through` is the maximum supplied anchor-event `date`; it is omitted
from JSON when no anchor exists and rendered as “not yet anchored.” It is
credential freshness metadata, not a metric, so it carries no trust-tier field.
The header also emits `input_schema_versions.ledger` and
`input_schema_versions.anchor` as sorted distinct version strings. These fields
contain no timestamps, identifiers, paths, or per-row values.

## Plain-language descriptions (MYB-5.5)

Every metric's public one-line explanation lives in
`src/mybench/report/descriptions.py`, versioned WITH this document: adding
or changing a metric updates both, and the page build fails on a metric
without a description.

## Required caveats (report fields, not documentation)

- Metrics #2/#3/#4 (capture-time basis): the report carries a
  `backfill_note` stating that history captured by backfill is anchored as
  of anchor time (OQ #5 decision).
- Metric #11 carries its calendar-clock caveat in the report row itself: local
  first-response time is self-attested and must not be described as verified
  Bitcoin time. Exact per-row latency values never enter the report.
- JUDGED is excluded from v0; the schema keeps the tier enum
  version-extensible (future TEE-VERIFIED sits between ANCHORED and
  JUDGED — end-state notes §3) — new tiers arrive via schema_version bump,
  never by loosening validation.

## Exclusions (deliberate, test-guarded where possible)

Per-session and per-episode point values; exact per-day/per-week counts;
hour-of-day anything; ordered per-session event or phase sequences at any
grain (corpus-level phase-transition aggregates over the pinned taxonomy
are a distinct, separately admitted class — THREAT_MODEL §3.2, per-session
ban restated in §3.5; adopted v0.2.0, 2026-07-14); repo names without
per-repo opt-in confirmation; model/provider strings outside the pinned
public vocabulary; orchestration file names, paths, and contents. Token
counts publish only in MYB-13.6's log-bucket form under the §3 token/cost
class.
