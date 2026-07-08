# report

**Single responsibility:** render the scorer's metrics into a versioned JSON
report (validated against `schemas/report.schema.json`) and a static HTML page
that carries each metric's trust tier plus step-by-step verification
instructions. Publishes only metrics, Merkle roots, and timestamps — never
content (privacy invariant #1).
