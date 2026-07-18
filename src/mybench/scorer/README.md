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
content-addressed offline harness-currency and MCP-recurrence snapshots. Its
outputs contain only registry bands/booleans and the registry-admitted R1
harness inventory; content, paths, session/event identifiers, tool/server
names, and ordered streams are absent. See
`docs/wave1-transcript-scorers.md`.
