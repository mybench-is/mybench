# Token and cost profile

MYB-13.6 computes a deterministic local profile from normalized v5 token,
model, episode-outcome, and workflow-phase structure. It does not widen token
capture, import a bill, contact a provider, or price Mybench compute.

## Immutable pricing input

Pricing snapshots are effective-dated JSON files packaged under
`mybench.registry`. A scoring run receives an owned `PricingSnapshot` value;
the scorer does not read the clock, environment, or network. The snapshot's
semantic version and SHA-256 digest travel with every cost claim, the report's
`pricing_snapshot` reference, and the evidence manifest's `versions.pricing`
reference.

A provider price-card refresh adds a new `pricing_snapshot_<semver>.json` in an
ordinary reviewed change. Existing files are never rewritten. Reproducing an
old report uses the exact recorded version and digest.

Snapshot v1.0.0 was transcribed on 2026-07-19 from the official
[GPT-5 model price card](https://developers.openai.com/api/docs/models/gpt-5)
and [Claude Platform pricing](https://platform.claude.com/docs/en/about-claude/pricing).
The sources are metadata inside the snapshot. They are never fetched during
scoring.

## Estimate semantics

The cost is labelled
`estimated-public-list-price-equivalent-not-invoice`. It is an integer
micro-USD token-rate estimate under the snapshot's ordinary public API tier,
not actual historical spend, an invoice, a provider contract price, a measure
of raw compute, or a Mybench price. Reasoning effort is never a multiplier.
Reasoning tokens affect the estimate only when they are already included in a
provider-reported billable token field.

For one usage observation, the scorer multiplies each reported token dimension
by its integer micro-USD-per-million-token rate, sums the integer products, and
rounds half-up once after the sum. It handles a provider's declared
input/cache-read overlap before multiplication. Floats are forbidden.

The snapshot distinguishes resolved model/SKU, provider, ordinary service
tier, context tier, token/cache dimensions, reasoning treatment, tool-charge
treatment, currency, and effective interval. The normalized v5 contract does
not retain cache-write duration, provider service-tier selection, regional
routing, or separately billed provider-tool counts. A positive cache-write
count with differing 5-minute and 1-hour prices is therefore `UNKNOWN`.
Unmapped models, missing provider/model/date evidence, out-of-interval events,
and any other ambiguous mapping are also `UNKNOWN`; the scorer never chooses a
convenient rate.

Provider-tool charges are outside this token-rate equivalent because the
normalized contract does not capture their billable usage dimensions. The
snapshot records that limitation explicitly. Actual billing imports and a
remote or independently refreshed pricing catalog remain out of scope for v0.

## Attribution and disclosure

Token usage inherits the last known public model class and last known
structural phase in the same normalized session. Usage before either marker is
`UNKNOWN`. Rework tokens are those attributed to the phase entered by the
pinned BUILD/TEST/DEBUG-to-PLAN/BUILD backward-edge set. Abandoned-session
tokens use only normalized episode-outcome classifier v1; unknown outcomes are
excluded from numerator and denominator.

Exact token aggregates and all dollar estimates remain in the private A10
intermediate. Dollar descriptors are `local-report-only` and belong to no
publication preset. The only publication-eligible outputs are
support-qualified, top-coded token bands and coarse ratio/share bands. Every
token and cost output carries `provider-reported-inflatable`. Session and
episode identifiers, timestamps, raw model strings, paths, filenames, and
per-episode points are absent from the closed output schema.

The scorer also emits the MYB-13.8 `token-cost-profile` coverage contribution:
sessions with structurally valid token metadata divided by eligible normalized
sessions, plus only pinned missing/ambiguity-category counts.
