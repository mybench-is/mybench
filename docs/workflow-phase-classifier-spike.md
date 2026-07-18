# Workflow-phase classifier structural spike (MYB-13.2)

Status: implementation complete for private A8-derived evidence. The go/no-go
table below is the implementation proposal for owner review; it does not claim
owner approval. Until that review, the draft PR remains the review surface.

## Contract

Classifier version `1.0.0` maps normalized events, in their canonical corpus
order, to `TASK|PLAN|BUILD|TEST|DEBUG|REVIEW|COMMIT|UNKNOWN`. Every output
record carries the classifier version, a fixed confidence band, a local
ordinal, and a closed rule id. Reclassification after any rule change requires
a version bump.

The classifier reads only `event_kind`, `authorship`, `reference_kind`,
`tool_family`, `result_status`, and `forge_action_kind`. It does not inspect
pointers, commitments, content shape, message text, command text, tool
arguments/results, paths, filenames, session ids, record coordinates,
timestamps, model/provider fields, or ambient state. UNKNOWN is an ordinary
output whenever no approved structural rule fires.

## Candidate markers and proposed phase decisions

| Phase | Available normalized marker | Proposed decision | Confidence and boundary |
|---|---|---|---|
| TASK | `event_kind=turn` plus `authorship=human-turn` | GO | MEDIUM. This is a human task/steering boundary, not a claim about request meaning or completeness. |
| PLAN | `event_kind=reference` plus `reference_kind=plan`; the `instruction` class is a weaker alternative | GO | HIGH for `plan`, MEDIUM for `instruction`. This observes a classified reference, not the semantics of its bytes. |
| BUILD | `event_kind=tool-call` plus `tool_family=write|edit` | GO | HIGH as structural mutation activity. Target file class and code-vs-document meaning remain unknown. |
| TEST | `event_kind=test` | GO | HIGH as an exact normalized test-runner observation. Scope/status do not change the phase label. |
| DEBUG | `event_kind=tool-result` plus `result_status=error` | GO | MEDIUM. The label means an observed error boundary; it does not prove diagnosis quality or intent. |
| REVIEW | `event_kind=forge-action` plus `forge_action_kind=pr-comment|pr-review-request` | GO | MEDIUM as an agent-mediated review boundary. It does not prove that a human review occurred or completed. |
| COMMIT | No normalized event proves creation of a commit. `forge_action_kind=push` and `pr-merge-attempt` are delivery attempts, not commit observations. | NO-GO in v1 | Emit UNKNOWN. Revisit only after an explicit versioned commit marker or a separately reviewed join exists. |
| UNKNOWN | Missing, new, malformed, or structurally insufficient markers | GO | UNKNOWN. Never infer from prose, commands, paths, provider metadata, or adjacency. |

The owner-review question is therefore explicit: approve the six operational
GO rules above and the v1 COMMIT no-go, or request a narrower rule before this
classifier becomes the base for MYB-13.3/13.5/13.6. No implementation result is
represented as owner approval.

## Marker availability and stability

| Candidate from the task brief | Current A8 availability | Cross-version treatment |
|---|---|---|
| Tool events | Closed `event_kind`, `tool_family`, and `result_status` fields shared by Claude Code and Codex adapters | Consume normalized values only. A schema or adapter-rule change requires review and, when it changes classification, a classifier-version bump. |
| File class touched | Not present on normalized transcript events. Commitment-only reference joins identify a verified target without exporting a filename, but do not provide an event-local touched-file class. | NO-GO; never recover a class from a pointer, path, command, or filename. |
| Test-runner invocation | Closed `event_kind=test`; raw harness commands have already been reduced by the versioned adapters | GO; unknown tool signatures simply produce no test event and therefore UNKNOWN here. |
| Plan-file edits | `reference_kind=plan` exists, but write/edit target class does not. A plan reference and a mutation must not be joined by proximity. | GO only for PLAN reference activity; NO-GO for the narrower claim that a plan file was edited. |
| Commit event | Episode closure can carry corpus-level bound-commit evidence, and forge events can show push/merge attempts, but neither is an event-local commit-creation marker. | NO-GO for COMMIT in v1; do not substitute delivery or episode closure. |
| Review boundary | Exact normalized forge-action classes for PR comments and review requests | GO at MEDIUM confidence; newly added forge actions remain UNKNOWN until the rule table is versioned. |

The stability boundary is the normalized contract rather than raw Claude Code
or Codex field names. Provider-specific raw fields are never fallback evidence.

## Deferred to JUDGED

Semantic planning, whether a mutation implements the task, whether an error led
to debugging, review quality, commit intent, and phase assignment from prose
all require interpretation beyond these markers. They are deferred to a future
JUDGED classifier. Version 1 does not use keywords, fuzzy matching, LLM calls,
or provider-specific heuristics to approximate them.

## Storage and publication boundary

The canonical stream is identifier-free and stored only below
`normalized/workflow-phases/` in the mode-0700 mybench data directory, with
mode-0600 content-addressed files. It is local A8-derived evidence covered by
THREAT_MODEL §2 A8, §2.1, §3.2–3.6, §4, ADV-1, ADV-4, and ADV-6. Tests scan
synthetic canaries in raw and common encodings and prove the scanner fires on a
planted canary.

This task adds no report, claim, registry, badge, or publication field.
THREAT_MODEL v0.2.1 admits only support-qualified, banded corpus-level phase
aggregates; ordered phase streams never publish.
