# scorer

**Single responsibility:** deterministically compute activity metrics (history
length, cadence, session statistics, commit↔session binding coverage) over the
local ledger, tagging each metric with its trust tier (PROVEN / ANCHORED /
JUDGED). Deterministic and open-source so anyone can reproduce the numbers from
the same ledger. Reads only the local ledger; emits no content.

`evidence_coverage.py` defines the Workflow Fingerprint coverage contribution
contract and deterministic private aggregate. See
`docs/evidence-coverage.md`. It accepts only fixed classes, integer rates,
honesty labels, pinned ambiguity counts, and the shipped PROVEN v1 coverage
metrics; raw or identifying evidence is not an input.

`wave1.py` implements the six registry-governed Wave-1 transcript scorers and
their signed, local-only claim set. It accepts normalized v5 structure plus
an offline harness-currency snapshot and per-event MCP category assertions
bound to normalized event-leaf commitments. It proves exact MCP-event coverage
and derives the identifier-free recurrence aggregate itself. Its outputs
contain only registry bands/booleans and the registry-admitted R1 harness
inventory; content, paths, session/event identifiers, tool/server names, and
ordered streams are absent. See
`docs/wave1-transcript-scorers.md`.

`token_cost.py` implements the MYB-13.6 Workflow Fingerprint profile over
normalized token/model/phase/outcome structure. `pricing.py` loads one
immutable, effective-dated, checksummed in-package price-card snapshot; the
scorer performs integer micro-USD arithmetic and has no clock, environment, or
network dependency. Missing or ambiguous price dimensions remain `UNKNOWN`.
Dollar estimates are local-report-only and explicitly labelled public
list-price equivalents, never invoices or actual spend. See
`docs/token-cost-profile.md`.
