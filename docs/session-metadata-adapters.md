# Capture-time session metadata adapters

MYB-12.5 adds a closed structural projection from complete transcript JSONL
records to private ledger `type="session"` rows. The projection is local-only:
it does not widen anchor events, reports, or any publication path.

This is a format contract pinned by synthetic fixtures against Claude Code
2.1.211 and Codex CLI 0.144.4 on 2026-07-16. OpenAI's public Codex docs describe
model/provider/reasoning configuration but do not specify the private rollout
JSONL row schema. Accordingly, rollout field paths below are adapter-versioned
implementation inputs, not claims of public API stability. Unknown records and
future fields degrade to absent metadata.

## Shared ledger projection

New session observations use ledger schema version `"2"`. Version-1 rows remain
valid and are never rewritten. The only additive session fields are:

- `models_seen`: sorted unique model identifiers observed anywhere in the
  complete session prefix;
- `provider`, `effort`, and `harness_version`: last structurally valid
  observation in record order;
- `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, and
  `cache_read_input_tokens`: non-negative provider-reported aggregates.

Absent or malformed data omits the field: absent means unknown. It never
becomes zero and is never inferred from a model name, harness name, message
shape, or another token counter. An explicit provider-reported integer zero is
preserved because it is an observation, not the unknown sentinel. Token counts
are provider-reported and inflatable; they are evidence of scale, not proof of
work. Their eventual report form remains the separate MYB-13.6 work and must be
order-of-magnitude/log-bucketed, top-coded, and carry that caveat.

Every complete JSONL record remains a commitment item. Metadata extraction
deserializes that item but reads only the paths listed below. In particular it
never reads `content`, thinking blocks, tool inputs/results, paths, filenames,
instructions, summaries, or unknown keys.

## Claude Code adapter

| Ledger value | Whitelisted source path | Rule |
|---|---|---|
| model set | assistant record `.message.model` | Accept identifier-shaped strings; sorted unique set. |
| provider | assistant record `.message.provider` | Accept the closed provider vocabulary; last valid value. Never infer Anthropic from a Claude model name. |
| effort | none | Unobservable in the pinned format. Omit it; thinking-block presence is not an effort signal. |
| harness version | any record `.version` | Accept identifier-shaped strings; last valid value. |
| input tokens | assistant record `.message.usage.input_tokens` | Sum valid assistant usage observations. |
| output tokens | assistant record `.message.usage.output_tokens` | Sum valid assistant usage observations. |
| cache-create tokens | assistant record `.message.usage.cache_creation_input_tokens` | Sum valid assistant usage observations. |
| cache-read tokens | assistant record `.message.usage.cache_read_input_tokens` | Sum valid assistant usage observations. |

A usage object with any malformed mapped value is ignored as one observation;
other assistant messages remain usable. A missing usage object contributes
nothing and does not create zero-valued fields.

## Codex adapter

| Ledger value | Whitelisted source path | Rule |
|---|---|---|
| model set | `turn_context.payload.model`; `event_msg` `session_configured.payload.model`; `event_msg` `thread_settings_applied.payload.thread_settings.model` | Accept identifier-shaped strings; sorted unique set. |
| provider | `session_meta.payload.model_provider` (fallback `model_provider_id`); corresponding settings `model_provider`/`model_provider_id` | Closed vocabulary; last valid value. |
| effort | turn/session settings `.effort` or `.reasoning_effort`; thread settings `.reasoning_effort` | Closed effort vocabulary; last valid value. Missing remains unknown. |
| harness version | `session_meta.payload.cli_version` | Accept identifier-shaped strings; last valid value. |
| input tokens | `event_msg(type=token_count).payload.info.total_token_usage.input_tokens` | Take the latest valid cumulative snapshot. |
| output tokens | `...total_token_usage.output_tokens` | Take the latest valid cumulative snapshot. |
| cache-read tokens | `...total_token_usage.cached_input_tokens` | Rename to `cache_read_input_tokens`; take the latest valid cumulative snapshot. |
| cache-create tokens | none | Unobservable; omit. |

`last_token_usage` is deliberately not used for session totals, and cumulative
`total_token_usage` snapshots are never summed. Either choice would over- or
under-count a grown rollout. Provider-only session metadata and model/effort
settings may arrive in different records; the aggregate joins only these
whitelisted observations.

## Re-scan semantics

The daemon recomputes the projection over the complete committed prefix only
when that session grows and a new session row is required. An unchanged scan
appends nothing. The newest row for an opaque `session_id` therefore contains
the latest complete-prefix aggregate and is authoritative by the existing
largest-`item_count` rule. Earlier rows remain in the hash chain; no row is
updated or deleted.

## Reserved private anchor-receipt branch

The same ledger-v2 review reserves exactly one non-lifecycle row kind,
`type="anchor_receipt"`, for MYB-9.5. Its closed fields are the normal envelope
plus `anchor_row_start`, `anchor_row_end`, `anchor_root`, `anchor_chain_tip`,
`receipt_ts`, and `receipt_id`. `receipt_ts` is the first successful calendar
response time; envelope `ts` remains append time.

`receipt_id` is the first 16 lowercase hexadecimal characters of HMAC-SHA256
under the existing 32-byte session scope key over:

```text
b"anchor-receipt:v1:" || canonical_compact_sorted_json({
  identity_id, date, row_start, row_end, root, chain_tip
})
```

There is no new key, nonce, commitment domain, lifecycle event, or public
field. Append validation verifies the signed event and recomputes its range,
root, chain tip, session/item counts, and the ordering
`newest covered row ts <= receipt_ts <= append ts`. The cut/stamp path remains
MYB-9.5's responsibility and is not wired by MYB-12.5.
