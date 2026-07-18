# Wave-1 transcript scorers v1

MYB-10.6 implements six deterministic `measured` descriptors over normalized
corpus v5. The production entry point is `score_wave1_claims`; it returns a
closed, local-only set of individually signed and registry-validated claims.
Nothing in this task publishes or uploads that set.

Every scorer uses the matching ACTIVE registry entry as its authority for
output shape, band labels, entry version, derivation class, and minimum session
support. Below the entry's support floor, the claim is absent. A zero-valued
claim is never substituted for thin evidence. Numeric boundaries are parsed
from `band_definitions`; changing a boundary is a registry change, not a
scorer-code change.

## Pinned measurements

All session counts refer to the normalized manifest's admitted sessions.
Intermediate grouping keys are used only in memory and never enter output.

| Registry descriptor | Deterministic measurement |
|---|---|
| `transcript.wellformed` | The normalized artifact must first pass its canonical schema, identity, and corpus-commitment checks. Available event timestamps must be nondecreasing in normalized order. Every tool call must have exactly one later linked result and every linked result must target a call. Each observed record chain must start at a root and later records must link to an earlier observed record; unresolved session lineage is a splice finding. Harness parse/authorship/block/metadata anomalies in manifest coverage conservatively make `wellformed` false because normalized v5 does not retain a safe per-session anomaly attribution. `wellformed` is the conjunction of clean harness coverage, monotonic timestamps, intact pairing, and no splice finding. |
| `transcript.tool_mix` | Within each tool-bearing session, read is `read`; write is `write` or `edit`; execute is `execute`; browse is `search` or `web`. Each share uses all tool calls in that session as its denominator. The corpus value is the session-equal mean, so one very long session cannot dominate. Unlisted families remain in the denominator but not in these four numerators. |
| `transcript.autonomy_band` | An agent action is an agent-authored `turn` or `tool-call`; derived test/reference/forge events do not double-count the invocation. A human turn after a started run closes that run and counts one intervention; initial or consecutive human turns do not. The run statistic is the lower median of all completed/end-of-session runs. The second statistic is the exact rational `1000 * interventions / agent_actions`. These are neutral delegating/interactive workflow shapes, not error or effectiveness measures. |
| `transcript.verification_ratio` | Share of admitted sessions containing at least one normalized `test` event. This is session-local test presence only; it does not claim commit linkage, test outcome, or code quality. |
| `transcript.orchestrators` | Sorted unique adapter sources from the normalized manifest, plus the least-current band across them. The caller supplies a closed, content-addressed harness-version snapshot. Same-major versions no more than one minor behind are `within-one-minor`; versions no more than one major behind are `within-one-major`; larger gaps are `older`. A missing or stale snapshot fails closed. Harness names are operational metadata and never trust anchors. |
| `transcript.mcp_breadth` | A closed auxiliary snapshot carries only fixed category labels and distinct-session counts for the source corpus. A category contributes to breadth only when its recurrence meets the descriptor's registry session floor. A one-off category therefore cannot inflate breadth. Counts cannot exceed corpus sessions, their sum cannot exceed normalized MCP calls, and a mismatched corpus root or snapshot digest fails closed. Raw installation/invocation counts, tool/server names, and per-session category rows are not admitted. |

The MCP taxonomy v1 is `browser`, `communications`, `database`, `deploy`,
`observability`, `other`, `planning`, and `vcs`. Normalized corpus v5 retains
only `tool_family=mcp`, not a server name. The auxiliary recurrence snapshot is
therefore the narrow aggregate handoff between a local category counter and
this scorer; it contains no content, identifier, or event order.

## Offline snapshots and claim binding

`harness_currency_snapshot.schema.json` and
`mcp_recurrence_snapshot.schema.json` are closed whitelists. Their builders
canonicalize rows, domain-separate the bytes, and attach a SHA-256 digest.
Scoring verifies the schema, canonical row order/uniqueness, and digest. No
clock, environment variable, filesystem discovery, subprocess, or network
call is available to the scorer.

Every emitted claim binds the normalized corpus commitment and registry digest.
The orchestrator claim also carries the currency-snapshot digest as an anchor
reference. The MCP claim carries the recurrence-snapshot digest both as an
evidence root and as an anchor reference. `signed_at`, evidence-window bounds,
the Ed25519 key, and signer kind are explicit caller inputs.

## Privacy and granularity boundary

The claim-set schema admits no raw evidence lane. Outputs contain registry
bands, booleans, and the full-preset-only R1 harness list. They contain no
transcript text or substring, prompt, code, filename/path, session/event id,
tool/server name, per-session point, timestamped series, or ordered stream.
The MCP snapshot is aggregate and identifier-free. The harness snapshot holds
only public operational version metadata.

This local scoring surface traces to THREAT_MODEL §2 A7/A8/A10, §3.2's
aggregate report classes, §3.3's banding/min-support/pinned-vocabulary controls,
§3.5's content/identifier/ordered-stream exclusions, §3.6's conformance and
canary obligations, §6's trust ceilings, and ADV-1/ADV-2/ADV-4/ADV-6. It adds
no report placement or publication authorization.

Synthetic tests cover all six registry outputs, independent support floors,
neutral copy, snapshot tamper/staleness/corpus-binding failures, recurrence
spam resistance, well-formedness firing cases, signed-claim conformance,
negative canary scans, and a planted-canary firing test. The production claim
set is registered in the two-run perturbed-process determinism gate.
