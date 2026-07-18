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
