# Private anchor receipts

`anchor cut` keeps an exact, machine-local observation of calendar acceptance
without widening the public anchor event. Immediately after the first
configured OpenTimestamps calendar response successfully deserializes and
merges, the client samples a UTC clock into `receipt_ts`. It continues later
calendar attempts, stages the unchanged date-only event and pending proof, and
only then appends one `anchor_receipt` row to the private hash-chained ledger.

The receipt row's envelope `ts` is the later append time. It is never used as
the measurement endpoint. For an event covering ledger rows
`[anchor_row_start, anchor_row_end)`:

- per-row latency = `receipt_ts - covered_row.ts`
- batch latency = `receipt_ts - max(covered_row.ts)`

Every interval must be non-negative or derivation fails closed. The exact
latencies are private inputs for MYB-6.1; only its approved bucketed
distribution may enter a report.

This calendar latency is **ANCHORED/self-attested**: it is a local wall-clock
observation linked by a typed HMAC to the signed staged event. It is not the
**PROVEN** Bitcoin upper-bound clock, which comes separately from an upgraded
OpenTimestamps block height checked against a pinned header source.

If a process stops after staging but before the receipt append, the observation
is `unknown`. Recovery does not reconstruct it from the event date, file mtime,
Git metadata, or the recovery clock. Re-running the cut cannot create a second
event for the same identity/date, and replaying an exact receipt is idempotent.
