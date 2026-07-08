# scorer

**Single responsibility:** deterministically compute activity metrics (history
length, cadence, session statistics, commit↔session binding coverage) over the
local ledger, tagging each metric with its trust tier (PROVEN / ANCHORED /
JUDGED). Deterministic and open-source so anyone can reproduce the numbers from
the same ledger. Reads only the local ledger; emits no content.
