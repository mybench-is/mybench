# Transcript-derived forge-action contract (MYB-19.11)

Status: implemented for private A8 normalized evidence only. There is no forge
API observation, report field, registry field, publication field, or trust-tier
change in this task. MYB-19.7 admitted no forge-action publication class; any
published form needs a future owner class revision plus a separately reviewed
ACTIVE descriptor.

## Versioned exact classifier

Normalized-corpus schema v5 adds `forge-action` events and pins
`forge_action_classifier_version=1.0.0` in both every event and the manifest.
The classifier reads only the already-admitted subject-agent tool name and tool
invocation bytes. Its outputs are either a recognized forge action or explicit
UNKNOWN. UNKNOWN produces no event; it is never coerced to `other` unless an
exact `gh` invocation was recognized but has no more specific action rule.

The v1 rule table is ordered and exact:

| Exact invocation signature | `forge_action_kind` |
|---|---|
| shell tokens `gh pr create ...` | `pr-open` |
| shell tokens `gh pr comment ...` | `pr-comment` |
| shell tokens `gh pr edit ... --add-reviewer ...` | `pr-review-request` |
| shell tokens `gh pr merge ...` | `pr-merge-attempt` |
| shell tokens `git push ...` | `push` |
| any other exact `gh ...` invocation | `other` |
| `mcp__github__create_pull_request` | `pr-open` |
| `mcp__github__add_pull_request_comment` | `pr-comment` |
| `mcp__github__request_pull_request_review` or `request_copilot_review` | `pr-review-request` |
| `mcp__github__merge_pull_request` | `pr-merge-attempt` |
| `mcp__github__push_files` | `push` |
| pinned GitHub-MCP review/update signatures without a narrower v1 kind | `other` |

Shell parsing uses POSIX tokens. It does not search substrings, autocorrect
misspellings, resolve aliases, infer intent from prose, or inspect tool-result
content. Tool names and MCP signatures come from a closed table. A rule change
requires a classifier-version and normalized-schema review.

## Closed event and structural outcome join

Each event contains only:

- the closed `forge_action_kind`;
- `classifier_version`;
- `outcome` (`success`, `error`, or `unknown`);
- a pointer to the committed invocation and a relation to its normalized
  `tool-call`; and
- `repo_id` only when the trusted session boundary already observed the
  existing 16-hex keyed-HMAC repo identity.

The normalizer computes `outcome` after ordinary tool normalization. Exactly
one linked `tool-result.result_status` is copied into the forge event. Missing,
dangling, ambiguous, or duplicate result relations yield `unknown`. The join
does not open or parse the result bytes. Missing repo evidence stays absent;
the normalizer never guesses it from command arguments, paths, URLs, or names.

## Retroactive derivation and privacy boundary

The derivation runs whenever the versioned normalizer replays authenticated A9
records, so sessions committed before schema v5 gain the same events without a
capture hook, network call, or retroactive A3 observation. If an invocation
pointer can no longer resolve, the already-derived structural event remains
bound to the committed record; any future reclassification that needs bytes
degrades through the existing A8/A9 UNKNOWN coverage contract.

Invocation titles, bodies, review text, repo names, commands, and tool-result
bytes never enter the event. PR numbers, PR URLs, and authoritative merge
confirmation are structurally absent from schema v5. Extracting them from
tool-result bytes is rung 2 and remains gated on the OQ #61 structural-residue
and ADR-0018-successor ruling. Tests prove equal-shape result-byte changes are
artifact-invisible and that attempted rung-2 fields fail the closed schema.

Coverage is incomplete by construction: browser actions, colleague actions,
forge automation, auto-merge, and agent actions absent from retained sessions
are invisible. This private event is not a complete forge history and makes no
claim that a merge attempt landed. Any future class revision must make that
agent-mediated-coverage caveat mandatory; this task adds no publishable
representation.
