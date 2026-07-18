# Session duration and agent-hours profile

`transcript.agent_hours` v1.0.0 is the first implementation of the
THREAT_MODEL v0.2.1 **Lifecycle-derived duration and agent-hours profile**
class. It is a measured, R1, full-preset `catalog_metrics` descriptor with an
ANCHORED ceiling. It never emits an exact duration total or a per-session
point.

## Private timing normalization

`mybench.normalizer.session_timing` v1.0.0 consumes explicit,
subject-filtered `VerifiedSession` inputs and returns an in-memory timing
record without a session id, content, filename, or path. Exact timestamps in
that record are private scorer inputs only.

- Claude open and close boundaries come from observed capture lifecycle
  timestamps, falling back only to timestamped structural `session_start` and
  `session_end` records.
- Codex open is the timestamped structural `session_meta` record when no
  capture observation exists.
- Codex v0 has no `session_end`. A Codex close is `scan-inferred` only from the
  timestamp on the last structural `event_msg.task_complete` record. An
  arbitrary last rollout timestamp is never substituted. If that marker or
  its timestamp is absent or malformed, close is `unknown`.
- `observed_at_status=complete` requires a valid in-boundary timestamp on
  every eligible subject record. Missing/malformed records produce `partial`,
  not a guessed timestamp.

These rules are normalizer-version-bound. Changing a marker or boundary rule
requires a normalizer and descriptor version change.

## Pinned v1 measurement

The scorer operates over one evidence period and has no ambient clock read.
It receives the anchored span as an explicit integer input.

**Wall-clock time** is the sum, across sessions with both boundaries, of
`close - open`. Overlapping sessions are intentionally summed: this is an
agent-hours volume, not a global elapsed-time or cross-session concurrency
claim.

**Active time** is computed only for boundary-covered sessions with complete
`observed_at` coverage. Sort the unique open, structural-record, and close
timestamps. Each adjacent gap of at most 30 minutes contributes its full
length; a gap greater than 30 minutes contributes zero. The rule does not add
a fabricated 30-minute activity tail. Per-session active durations are then
summed, including overlaps.

Both exact sums remain in memory and map to the same registry-owned,
top-coded bands:

| Band | Interval |
|---|---|
| `unknown` | no eligible session |
| `under-1h` | 0 to under 1 hour |
| `1h-to-under-8h` | 1 to under 8 hours |
| `8h-to-under-40h` | 8 to under 40 hours |
| `40h-to-under-160h` | 40 to under 160 hours |
| `160h-plus` | 160 hours or more; top-coded |

The descriptor requires at least five admitted sessions. Below that support
floor the scorer returns no descriptor, never a zero-valued claim.

## Coverage, backfill, and publication

Two coarse coverage cells travel with every output:

- `observed_boundary_coverage_band`: sessions with an open and observed or
  versioned scan-inferred close divided by all admitted sessions;
- `active_time_coverage_band`: sessions also having complete `observed_at`
  coverage divided by all admitted sessions.

Both use `<25%`, `25–<50%`, `50–<75%`, `75–<90%`, and `90–100%` bands.
The backfill annotation is `under-14-days` or `14-days-plus`; the exact anchor
span is not included. Required controlled caveats are
`capture-dependent-and-inflatable` and
`observed-at-coverage-limits-backfill`. Older or selectively captured history
can lower coverage, and locally generated lifecycle activity can inflate the
totals, so neither band is a completeness or productivity claim.

Publication was blocked until the MYB-19.7 owner ruling. That ruling is now
landed in THREAT_MODEL v0.2.1, and the descriptor supplies the ruling's exact
bands, support, caveats, risk, and `fingerprint.catalog_metrics` location.
Publication still requires registry conformance, anchor coverage, the `full`
preset, owner preview/action, and the report leak gate. Exact totals,
per-session points, identifiers, and timestamps remain inadmissible.

Local-unattested derivation is **ANCHORED and never PROVEN** under ADR-0014.
The metric describes lifecycle volume only; it is not raw-compute metering,
pricing, utility, quality, or effectiveness.
