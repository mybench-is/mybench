# Evidence-coverage contract v1

MYB-13.8 defines the content-free contract shared by the workflow-map,
model-role, context-management, and token/cost scorers. The machine-readable
input and aggregate whitelists are:

- `fingerprint_coverage_input.schema.json`
- `evidence_coverage_section.schema.json`

The aggregate is private A10 intermediate state. It is not a report-v2 section
and it is not a publication artifact. Report v2 continues to represent
`fingerprint.evidence_coverage` as `not-supported` until the sibling scorers
emit their atomic claims and the claim assembler can verify and place those
claims without reinterpretation. A raw aggregate is deliberately rejected by
the report-v2 schema; this prevents missing atomic integration from looking
like a supported report section.

## Producer contract

Every build supplies exactly one contribution for each producer. A producer
whose denominator is not supported emits the required input class with
`coverage_basis_points: UNKNOWN`; omission is not an alternative.

| Producer | Required input coverage |
|---|---|
| `workflow-map` | none; it may contribute ambiguity counts such as `unknown-phase` |
| `model-role-profile` | `model`, `effort` |
| `context-management-profile` | `context-lifecycle` |
| `token-cost-profile` | `token-data` |

The public builder is `build_coverage_contribution`. It accepts only covered
and eligible counts in memory, then emits the deterministic rate and honesty
labels. Counts do not travel in the observation. `None` means the denominator
is unsupported. `(0, eligible)` means a known denominator with no covered
markers: it emits zero *coverage* with `evidence_state: partial`; it never
emits a zero activity value.

The input bases are fixed:

- model: events with recognized model or `other` divided by model-eligible
  events;
- effort: events with recognized effort divided by effort-eligible events;
- context lifecycle: sessions with at least one reliable lifecycle marker
  divided by eligible sessions; and
- token data: sessions with structurally valid token metadata divided by
  token-eligible sessions.

Changing an input class, basis, rate formula, confidence threshold, producer
assignment, or taxonomy is a contract-version change.

## Deterministic rate and UNKNOWN semantics

Rates use the report-v2 formula:

`floor((10000 * covered + floor(eligible / 2)) / eligible)`

The result is capped at 10000 basis points. An absent denominator
(`eligible = 0`) is `UNKNOWN`. Confidence is `LOW` below 5000, `MEDIUM` from
5000 through 7499, `HIGH` from 7500 through 10000, and `UNKNOWN` when the rate
is unknown.

`UNKNOWN` means the evidence cannot support the downstream value. It never
means no activity occurred. Missing markers lower coverage; section scorers
must not place missing observations into activity numerators or denominators.

## PROVEN compatibility inputs

The aggregator consumes, rather than reimplements, the shipped schema-v1
metrics:

- `evidence_provenance_split` supplies the anchor-coverage-derived
  IMPORTED/LIVE split. Its values are converted losslessly from the v1
  four-decimal representation to integer basis points. A zero/zero split has
  no anchored denominator and becomes UNKNOWN/UNKNOWN.
- `binding_coverage` supplies the temporary Git/session-linkage stand-in and
  is always labeled `binding-coverage-based-stand-in`. One repo-level value,
  or several identical values, can be retained verbatim. Heterogeneous
  multi-repo values cannot be soundly aggregated because v1 omits their
  denominators; that case remains UNKNOWN until MYB-10.10 supplies the actual
  session-to-commit association.

Imported history is an annotation, not a tier. The two compatibility inputs
remain PROVEN; content-adjacent coverage inputs remain ANCHORED.

## Missing and ambiguous evidence taxonomy

Only these identifiers and positive counts may enter the aggregate:

- `missing-marker`
- `missing-pointer-target`
- `conflicting-evidence`
- `unsupported-harness-version`
- `unlinked-session`
- `unknown-phase`
- `missing-model`
- `missing-effort`
- `missing-token-data`

Entries are sorted and duplicate producer counts are summed. Zero counts are
omitted when a denominator is not established. No free text, source name,
filename, path, repository name, session id, timestamp, or ordered evidence
stream exists in either schema.

## Privacy and testing boundary

The contract traces to THREAT_MODEL §3.2's evidence-coverage class, §3.5's
forbidden identifier/sequence surfaces, §6's tier ceilings, and ADV-2's
never-overclaim rule. Tests use seeded synthetic fixtures only. They enforce
the closed schemas, marker-free UNKNOWN semantics, shipped-metric consistency,
determinism, a negative raw/common-encoding canary scan, and a companion
planted-canary firing test.
