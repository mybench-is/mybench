# Context-management profile v1

MYB-13.4 implements the eight roadmap bullets as nine atomic measurements
(manual and automatic compactions are separate fields). The scorer consumes
only the private MYB-10.4 normalized session/event projection and the closed
MYB-12.4 lifecycle event-row projection. Opaque session and episode identities
exist only as in-memory join keys.

## Structural definitions

| Roadmap field | Named marker and formula | Coverage basis |
|---|---|---|
| Fresh-session rate | `session_start(trigger=startup)` sessions divided by sessions with one unambiguous known `session_start` trigger | sessions with a known start trigger / eligible sessions |
| Resume rate | `session_start(trigger=resume)` sessions over the same known-trigger denominator | sessions with a known start trigger / eligible sessions |
| Clear rate | generations whose observed trigger is `clear` divided by generations with an observed `startup|resume|clear|compact` trigger | generations with a known trigger / structurally observed generations |
| Manual compactions | Count of `compact_pre(trigger=manual)` after joining a normalized `context-boundary` and live event row by opaque session plus context generation | compaction candidates classified `manual|auto` / observed compaction candidates |
| Automatic compactions | Count of `compact_pre(trigger=auto)` under the same join | same as manual compactions |
| Context generations per task | For every fully covered explicit `task_episode_id`, sum each member session's observed generation prefix (`max(context_generation_id)+1`); aggregate into pinned `count_band` cells | episodes whose every member session has a reliable generation marker / eligible episodes |
| Tasks completed in one context | Fully generation-covered episodes whose summed generation count is one divided by fully covered episodes | same episode-generation coverage |
| Fresh planning versus implementation sessions | First known MYB-13.2 phase in a startup-triggered session: `PLAN`, `IMPLEMENTATION` (`BUILD|TEST|DEBUG|REVIEW|COMMIT`), or `UNKNOWN`; corpus shares only | fresh sessions with a known PLAN or implementation phase / fresh sessions |
| Model changes across context boundaries | A normalized `context-boundary` whose nearest private model observations on both sides differ, divided by boundaries with model coverage on both sides | model-covered boundaries / observed context boundaries |

The v1 rate function is
`floor((10000*numerator + floor(denominator/2))/denominator)`, capped at
10000 basis points. A zero denominator is `UNKNOWN`. Missing observations do
not enter an activity numerator or denominator. Conflicting trigger/model
evidence is also excluded and reported through the MYB-13.8 pinned
`conflicting-evidence` category.

The two compaction counts are exact only when every observed compaction
candidate has a known manual/automatic trigger. Partial trigger coverage makes
both local counts `UNKNOWN`; an observed subtotal is never presented as the
total. A live `compact_pre` row is eligible only after an exact opaque-session
plus context-generation join to a normalized `context-boundary`; any unjoined
row makes both counts and their coverage `UNKNOWN` and suppresses both public
atoms. No observed compaction candidate also remains `UNKNOWN`, because the
current inputs do not carry a whole-window capture-completeness proof that
would justify a zero.

## Disclosure boundary

Local output contains exact corpus aggregates plus per-field coverage. The
registry-governed public atoms contain only share/count bands, distribution
cells, coverage bands, confidence labels, controlled versions, and the
ANCHORED tier. Model strings are compared privately and never emitted.

Neither form admits a session/episode identifier, boundary position,
timestamp, filename, path, content value, or ordered lifecycle sequence.
Fields below the registry support floor are absent from the publishable map,
never zero-filled. The scorer contributes exactly one `context-lifecycle`
observation to the MYB-13.8 coverage contract: sessions with at least one
reliable lifecycle marker divided by eligible sessions.

This surface is covered by THREAT_MODEL v0.2.1 §2 A8/A10, §3.2's
context-boundary/context-management class, §3.3 controls, §3.5 exclusions, §6
tier ceiling, and ADV-1/ADV-2/ADV-4. It performs no publication or network
action; publication still requires the separate preview and owner action.
