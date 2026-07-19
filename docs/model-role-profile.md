# Model-role profile scorer v1

MYB-13.5 joins the private normalized metadata stream to the pinned workflow
phase classifier. It is a pure local scorer: callers provide normalized events
explicitly, and the scorer reads no clock, environment, filesystem, network,
ledger, transcript, or publication destination.

## Role phases and metadata vocabularies

The v1 display taxonomy is the roadmap's five-role projection over the
classifier taxonomy:

| Role phase | Classifier phases |
|---|---|
| `planning` | `TASK`, `PLAN` |
| `implementation` | `BUILD`, `TEST`, `COMMIT` |
| `debugging` | `DEBUG` |
| `review` | `REVIEW` |
| `unknown` | `UNKNOWN` |

Model carrier rows update the latest observed model, provider, and effort
fields for their normalized session. Partial carriers update only fields they
actually contain. Carrier rows are not workflow activity. Every other
structural event is eligible, including an event whose phase is `unknown`.
The session identity is used only as an in-memory routing key and never enters
an output.

Models reduce to the pinned public model vocabulary, with an unrecognized
nonempty value becoming `other` and an absent value becoming `UNKNOWN`.
Providers use the normalized public vocabulary plus `other|UNKNOWN`.
Effort uses `low|medium|high|max|UNKNOWN`: `none|minimal|low` reduce to `low`,
and `xhigh` reduces to `max`. An absent or invalid effort is `UNKNOWN`, never a
guess.

## Distribution and evidence-quality rules

For each observed role phase and each of `model|provider|effort`, the exact
local share is:

`bp(events in value cell, all eligible events in the role phase)`

The local section retains every nonempty cell, including `UNKNOWN`. Each local
cell carries the corresponding coverage rate, confidence, and evidence state.
Coverage is metadata-bearing eligible events divided by all eligible events in
that role phase. Complete coverage is `available`, incomplete known coverage
is `partial`, and a missing denominator is `unknown`.

Registry atoms use a five-event floor independently per value cell. Below the
floor, the exact local-report atom and public band cell are absent rather than
zero. The public evidence-quality atom uses five eligible events per role
phase. All cell arrays are sorted lexicographically by their dimension tuple.
As with the current workflow-map scorer, these cell-list atoms are registry
validated but do not infer a report-v2 location; the claim assembler must add
an explicit compatible binding before the reserved section can be activated.

The scorer also emits the MYB-13.8 `model-role-profile` contribution. Model and
effort coverage use the shared contract exactly; only the pinned
`missing-model` and `missing-effort` category counts travel with it. Provider
coverage remains in this section because MYB-13.8 does not define a provider
input class.

## Trust and privacy boundary

Provider names are operational metadata only. The section's trust-basis label
is fixed to signatures, commitments, and timestamps; no provider or substrate
name can become trust copy. Every registry output is ANCHORED and describes
observed configuration, never capability, quality, effectiveness, or a person.

The output schemas admit only pinned role phases, pinned metadata values,
integer basis points, coarse bands, controlled evidence labels, versions, and
trust tier. They admit no transcript content, prompt text, code, filename,
path, repository/session/episode identifier, timestamp, ordered stream, raw
unrecognized metadata string, or free text. Synthetic canary tests scan the
section and captured logs in raw and common encodings, with a planted companion
test proving the scanner fires.
