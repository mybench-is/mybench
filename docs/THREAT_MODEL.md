# Mybench Threat Model

**Version:** 0.2.0
**Status:** Living document. Every feature must be justifiable against this model.
If a proposed change isn't covered here, work stops and this document is updated first.

---

## 1. Purpose & Security Goal

Mybench produces verifiable claims about a developer's AI-assisted work history
**without disclosing the content of that work**. The system's entire value rests on
two properties holding simultaneously:

- **P1 (Privacy):** No transcript content, prompt text, code, or filenames
  ever leaves the user's machine or enters any repository. Content-DERIVED
  data is local by default and leaves the machine only as an artifact of a
  class admitted in §3, at §3's granularity ceilings and controls, through
  a user-initiated publication act. Anything content-derived outside §3's
  classes does not leave, full stop.
- **P2 (Integrity):** Published claims cannot be fabricated, backdated, or
  selectively edited after the fact without detection.

A failure of P1 is a product-ending event. A failure of P2 degrades the product
to unverified self-reporting.

---

## 2. Assets

| ID | Asset | Location | Sensitivity |
|----|-------|----------|-------------|
| A1 | Agent session transcripts (Claude Code / Codex JSONL) | `~/.claude/projects/`, Codex log dirs; byte-exact archived copy: A9 | HIGH — contains prompts, code, secrets, filenames |
| A2 | Commitment nonces | mybench data dir (default `~/.local/share/mybench/nonces/`) | CRITICAL — leaking a nonce enables dictionary attack on its commitment |
| A3 | Local ledger (commitments, Merkle trees, metadata). Also holds capture-time event rows and additive session-row fields (lifecycle events, git provenance, model/provider/effort/token metadata) per the capture-evidence-model-v2 ADR (ADR-0013) — structural metadata only, never content or content-derived values | mybench data dir (`ledger.db`) | MEDIUM — contains no plaintext, but timing metadata is private-by-default |
| A4 | Git signing keys | user's SSH/GPG keyring | HIGH — standard key hygiene applies |
| A5 | Published anchors (Merkle roots + timestamps) | public `mybench-anchors` repo, OpenTimestamps | PUBLIC by design |
| A6 | Report JSON + rendered page | public, user-controlled | PUBLIC by design |
| A7 | The scorer code itself | public repo | PUBLIC; integrity matters (supply chain) |
| A8 | Normalized event store — derived, parser-versioned structure from A1/A9 and enrolled git repos: turn/tool/test structure and other parser output, episode stitching, plan/instruction/orchestration-file *structure*. Content-like fields (plan files, instruction files, test output, orchestration files) enter A8 as pointers plus commitments ONLY — never byte copies; no span-copy class exists. Pointers resolve against the live source dirs or the A9 archive; when the pointed-to bytes are gone from both, the derived evidence degrades honestly — a coverage drop / UNKNOWN under the MYB-13.8 evidence-coverage semantics — never a pipeline failure and never a fabricated or reconstructed value. (Capture-time observations — lifecycle events, model/provider/effort/token metadata, keyed-HMAC repo & worktree ids, git HEADs — are ledger rows per ADR-0013's locus split: see the A3 addendum above) | mybench data dir (layout & locus per ADR-0013 — hybrid split by evidentiary role) | HIGH — content-derived; handled as A1-equivalent |
| A9 | Raw-transcript retention archive — the exact committed bytes of captured sessions, preserved before harness retention cleanup deletes them. Append-only per session; archived bytes must recompute the session's ledger commitments; retained indefinitely (ADR-0002 §6 — retention is load-bearing for disclosure and recomputation) | mybench data dir (`archive/<source>/<session-id>`), 0600 files | HIGH — plaintext copy of A1 |
| A10 | Local report bundles and publication-preview staging — rendered fingerprint output and the sanitized candidate-publication bundle | mybench data dir (`reports/<report-id>/`; preview staging area) | HIGH — the local report may contain private details that are never uploaded; only a previewed bundle governed by §3 may ever leave the machine |

The "mybench data dir" is a single dedicated directory outside all repos,
created mode 0700; its exact location is an implementation choice recorded in
an ADR, but it MUST NOT be inside any repository, synced folder, or backup
that leaves the machine unencrypted. A8–A10 live inside it without exception;
none of their contents, paths, or filenames may appear in any repo, log line,
or test output.

### 2.1 Reviewed widening (procedure for new local data classes)

Any new locally stored field class or store beyond the rows above (MYB-6.4
precedent, generalized) requires, before code exists: (a) an asset-table row
or an explicit rejection recorded in the planning repo's OPEN_QUESTIONS —
never a silent addition; (b) a named location inside the 0700 data dir;
(c) a statement of whether it holds pointers, commitments, or copies, and
why a pointer cannot serve if it copies; (d) leak-scan obligations inherited
by every implementing task (synthetic canary fixtures over logs, ledger rows,
and anchor staging, plus a firing test proving the scanner catches a planted
canary). Ledger-row widening additionally follows the schema_version
discipline (absent = unknown; old rows never rewritten).

---

## 3. Public vs. Private Artifacts

Publication is class-based: §3.2 admits artifact CLASSES with granularity
ceilings and required controls (§3.3, §3.4). The descriptor registry
(`src/mybench/registry/`; serialization ratified JSON, ADR-0016) implements
instance-level membership — band edges, min-support values, risk classes,
presets — UNDER these ceilings; its git history is the audit trail. Adding a
metric within an admitted class is a registry/schema version bump with
review; adding a CLASS is an owner revision of this section (invariant #4).
Report artifacts leave the machine only through a user-initiated publication
act, never by default.

### 3.1 Trust-substrate artifacts (published)
- Daily Merkle roots over session commitments
- OpenTimestamps proofs for those roots
- Commit trailer hashes (session-root references) in repos the user opted in
- Scorer, classifier, schema, registry, and pricing-snapshot versions;
  registry file + digest (descriptor definitions and rejected-claims list
  only — never user data); verification instructions

### 3.2 Report artifact classes (published only within an admitted class)
| Class | Granularity ceiling + required controls | Tier |
|---|---|---|
| Counts, durations, cadence histograms, coverage percentages, streak lengths (the v0 set) | Ledger metadata; aggregates + coarse histograms per docs/metrics-v0.md | per metrics-v0 |
| Corpus-level phase-transition aggregates | First-order transition shares over the pinned coarse phase taxonomy (≤8 symbols, versioned); banded; cell min-support; aggregated over the full evidence period; NEVER per-session | ANCHORED |
| Recurring phase-sequence n-grams | Same taxonomy; length ≤ 5; corpus support k ≥ 5; top-N listing; banded shares | ANCHORED |
| Human-vs-agent activity shares | Banded shares, per phase or corpus-wide; authorship-tag derived; subject-type-neutral wording | ANCHORED |
| Rework-loop rates | Pinned structural loop definitions; banded rates; min-support; neutral copy (banned framings apply) | ANCHORED |
| Context-boundary and context-management rates | Aggregate counts/rates and banded distributions only; no boundary positions inside any session; per-field coverage required | ANCHORED |
| Model/provider/effort role profile | Banded shares per phase cell; model/provider strings from a pinned public vocabulary, unrecognized → "other"; provider names are operational metadata, never trust language (ADR-0009) | ANCHORED |
| Orchestration-topology aggregates + archetype gallery | Counts, depths, presence booleans, canonicalized shapes only; k ≥ 5 suppression (firing-tested); no names, paths, or file contents | ANCHORED |
| Token/cost profile | Order-of-magnitude totals + log-buckets, top-coded; pinned pricing snapshot; REQUIRED caveats: provider-reported/inflatable; token-per-line "diagnostic, not quality" | ANCHORED |
| Task-episode totals + bucketed per-episode distributions | Totals exact above min-support; per-episode POINT values never publish | ANCHORED |
| Evidence-coverage section | Percentages + pinned ambiguity taxonomy (category identifiers, never filenames); missing evidence — including pointer targets deleted from both source and archive (A8) — reports as honest coverage drop / UNKNOWN, never a fabricated value | ANCHORED (binding_coverage: PROVEN) |
| Blame-survival cohorts | Bucketed rates; quarter cohorts; per-cohort min-support; pinned public-repo tip recorded; REQUIRED caveat: persistence, not quality; no per-commit values, no revert counts | PROVEN |
| Badge / static-card claims | Verbatim projections of fields already published under an admitted class; fail-closed whitelist; below-min-support numbers suppressed; never an effectiveness or composite score | inherits |

Every published metric carries exactly one §6 tier label (unchanged rule).

### 3.3 Controls vocabulary (normative)
- **Banding:** coarse bands, not point values; band edges versioned
  (registry/schema bump to change).
- **Min-support:** below threshold ⇒ the claim is ABSENT, never zero-valued.
- **k-suppression (k ≥ 5):** shapes/sequences/structures occurring fewer
  than 5 times are suppressed or generalized (rare-pattern fingerprinting,
  ADV-1); enforced by firing test.
- **Top-coding** on open-ended distributions.
- **Pinned taxonomies/vocabularies:** phase taxonomy, model/provider name
  vocabulary, pricing snapshot — versioned inputs, never network reads.
- **Inference-risk classes R0/R1/R2** per descriptor; the default
  (employer-safe) preset is R0-only; R1/R2 require individual opt-in with a
  plain-language risk note. Enforced structurally by the registry loader.
- **Required-caveat fields** are report fields, not documentation.

### 3.4 Temporal granularity (normative)
- Evidence-period endpoints: UTC date grain (day-grain existence is already
  public via A5 daily roots).
- All other published temporal data: ISO-week grain or coarser, as
  distributions over periods, never period-keyed time series. Sole
  exception: the quantized weekly activity strip (4-bin, top-coded,
  recovery-resistance-tested).
- Hour-of-day granularity: never.
- Per-session / per-episode timestamps: never.
- Backfill floor: while anchored_span_days < 14, capture-time metrics carry
  an in-cell backfill annotation and weekly-cadence surfaces are suppressed.
- Longitudinal cohorts: quarter grain; below-support cohorts merge or
  suppress.

### 3.5 Never published, never leaves machine
- Transcript content or any substring, embedding, or summary of it
- Prompt text, code, and orchestration-file contents (no opt-in path in v0)
- Nonces; the ledger (A3); the normalized event store (A8); the retention
  archive (A9); per-session phase streams and any ordered per-session event
  or phase sequence, at any grain
- Filenames, repo names (except repos the user explicitly opts in), project
  names, orchestration file/skill/agent names and paths
- Per-session or per-episode point values
- Timestamps finer than §3.4 permits
- Model/provider strings outside the pinned public vocabulary
- Effectiveness scores, composite scores, tokens-per-line rankings (see the
  registry rejected: section)

### 3.6 Enforcement
Every code path that writes to a repo, network socket, or report file must
pass negative tests: fixtures containing known plaintext markers are run
through the full pipeline and published artifacts are scanned for those
markers, their hashes-without-nonce, and their common encodings. In
addition: registry conformance is fail-closed (claims must cite an active
entry and validate against its closed output schema); k-suppression and
min-support carry companion firing tests; the publication preview's
redaction manifest derives from registry disclosure flags and must list
inclusions and exclusions explicitly before any upload.

---

## 4. Commitment Scheme

Per content item `m` (a session chunk):

```
nonce  = CSPRNG(32 bytes)                    # unique per item, never reused
commit = SHA-256(nonce || len(m) || m)
```

- Nonces stored only in A2 (mode 0700 dir, 0600 files). Never in the ledger's
  publishable views, never in any repo.
- Length-prefix prevents ambiguity/concatenation games.
- Session Merkle tree: leaves are item commitments; root published daily.
- Domain separation: all hashes prefixed with a context string
  (`mybench:v1:leaf`, `mybench:v1:node`, `mybench:v1:session`,
  `mybench:v1:day`) to prevent cross-context replay (leaf presented as root,
  etc.). Exact encodings, tree shape, and test vectors: ADR-0002
  (`../../mybench-ops/decisions/ADR-0002-salted-commitment-scheme.md`).

### Dictionary-attack analysis
Unsalted hashes of short/predictable content (common prompts like "fix the
tests", small diffs, well-known file headers) are trivially reversible by
enumeration: an adversary hashes candidate strings and matches against
published values. The 32-byte random nonce makes each commitment
independently unguessable regardless of content entropy — the adversary must
guess the nonce (2^256) even for a one-word prompt. Residual risks:
- **Nonce reuse** would let an adversary correlate identical content across
  items. Mitigation: nonces are generated per item, uniqueness enforced by test.
- **Weak RNG** breaks everything. Mitigation: OS CSPRNG only; no seeding,
  no fallback paths.
- **Selective disclosure leaks by choice:** opening item `m` reveals `m` and its
  nonce for that item only; sibling Merkle nodes reveal nothing about other
  items. This is by design but users must understand disclosure is per-item
  irreversible.

---

## 5. Adversaries & Attacks

### ADV-1: Curious/malicious verifier (reads all public artifacts)
Wants to learn content, work patterns, client names, or identity details.
- **Attack:** dictionary attack on commitments → defeated by salting (§4).
- **Attack:** traffic analysis of anchor timing → daily-granularity roots leak
  only "worked that day." Finer-grained cadence appears ONLY in the report,
  which the user chooses to publish, at histogram granularity defined in the
  schema. Residual: publishing any report leaks the patterns it contains.
  Accepted; user-controlled.
- **Attack:** correlating opted-in commit trailers with public repo activity.
  Residual: opt-in per repo is the control. Marker-file design prevents
  accidental enrollment.

### ADV-2: Fabricator (wants a credential without doing the work)
- **Attack:** backdating — generate a year of fake ledger today. Defeated by
  anchoring: roots must exist in OpenTimestamps/anchors-repo history at claimed
  times. Cost of collusion: rewriting Bitcoin history + GitHub history.
- **Attack:** real-time synthetic history — run a script that emits plausible
  transcripts daily. NOT cryptographically defeated. Mitigations are
  economic/statistical: months of sustained cost per identity, cross-signal
  coherence (commit binding to real repos, stylometric continuity in later
  phases, live exam in later phases). **The report must never claim more than
  this.** All content-dependent claims are labeled ANCHORED or JUDGED, never
  PROVEN.
- **Attack:** borrowing history — buy/rent someone's ledger. Binding to git
  signing identity raises cost; full defeat requires later-phase identity
  measures (exam + continuity). Documented limitation.

### ADV-3: Compromised or malicious scorer supply chain
(Shai-Hulud/Megalodon-class attacks demonstrated attestation-bearing malicious
artifacts via hijacked build pipelines in May 2026.)
- **Attack:** malicious scorer release exfiltrates ledger/nonces or emits
  inflated scores that still verify.
- Mitigations: reproducible builds; pinned, minimal, audited dependencies;
  releases signed + published to a transparency log; scorer runs with no
  network access by default (v0 scorer needs none — enforce with tests and,
  where available, sandboxing); nonce directory readable only by daemon and
  disclosure tool, not scorer (scorer consumes ledger metadata views only).

### ADV-4: Local malware / other users on the machine
Out of scope to fully defend (a compromised host loses A1 regardless of
Mybench), but Mybench must not *worsen* the position:
- Ledger and nonces at 0700/0600; no service listening on network ports;
  daemon runs as user, not root.
- Mybench necessarily concentrates content-adjacent data locally: pointers to
  transcripts (A1), a byte-exact retention archive (A9), a derived event
  store (A8), and rendered reports (A10). Every content-bearing store exists
  ONLY as an enumerated §2 row inside the 0700 data dir, admitted via the
  §2.1 procedure — nothing content-bearing accretes outside those rows.
- Content-like fields are pointers-only: where derived structure references
  plan files, instruction files, test output, or orchestration files, A8
  stores the pointer and the commitment, never the bytes — no span-copy
  exception class exists. Copies exist only where a row's whole purpose
  requires bytes: A9 exists to preserve preimages the harness would delete
  (ADR-0002 §6).
- Graceful degradation is a hard requirement, not a courtesy: pointers
  resolve against the live source or the A9 archive; when the pointed-to
  bytes are gone from both, the affected evidence reports as missing — an
  honest coverage drop / UNKNOWN (MYB-13.8 semantics) — never a failure,
  never reconstructed or fabricated content.
- Still forbidden outright: plaintext search indexes over content; caches
  outside the enumerated rows; any content, filename, or data-dir path in
  logs or test output (log lines carry event names and counts only).
- Accepted residual: A9 concentrates A1-class plaintext, and A8 concentrates
  content-derived structure, on a compromised host — consistent with this
  section's premise that a compromised host loses A1 regardless. Mitigation:
  same-or-tighter permissions than the source dirs (0700/0600); at-rest
  encryption of the archive is an open implementation choice, not assumed
  here.

### ADV-5: The Mybench operator (future hosted phases)
For v0 (local-only) this is vacuous. Recorded now as a design constraint:
hosted scoring must be architected so the operator cannot read plaintext
(enclave-terminated encryption) and cannot silently alter scores
(attestation + reproducibility). No design decision in v0 may assume a
trusted operator. Any future phase that sends content off-machine (TEE-hosted
scoring included) contradicts privacy invariant #1 as written and requires an
explicit owner-approved ADR amending that invariant before design work
proceeds — no such phase is treated as already covered by this document.

### ADV-6: The user themselves (self-serving edits)
- **Attack:** deleting unflattering history. Detection: ledger rows are
  hash-chained and daily roots are anchored; gaps and chain breaks are
  visible in verification ("427/427 roots, 0 gaps" is a claim verifiers check).
  Selective *non-publication* of entire identities remains possible and is
  acknowledged: Mybench proves what happened, not that nothing else did.

---

## 6. PROVEN vs. ANCHORED vs. JUDGED — guarantee ladder

| Tier | Meaning | Verifier trust required |
|------|---------|------------------------|
| PROVEN | Verifiable from public artifacts + open code alone (anchor continuity, timestamps, signature validity, binding coverage) | None |
| ANCHORED | Timing/volume proven; content properties asserted by user, spot-checkable via random-audit disclosure | Statistical |
| TEE-VERIFIED | Environment semantics (ADR-0014): labels a deterministic (measured) claim whose execution-environment attestation verifies against the composite evidence schema (MYB-7.18). Judge claims in attested environments render JUDGED(attested), never TEE-VERIFIED. Unreachable until MYB-7.18 + MYB-10.14 land | Attestation verification |
| JUDGED | Output of a pinned model/rubric (out of scope v0) | Trust in rubric validity |

- **Qualifier grammar:** an execution environment qualifies a base tier as a
  parenthetical — `TIER(qualifier)` (ADR-0014). The label slots
  **JUDGED(unattested)** and **JUDGED(attested)** are reserved; no claim may
  carry either until the MYB-7.7 taxonomy ADR activates them.
- **IMPORTED** is an in-cell annotation for backfilled evidence windows, not
  a metric tier label; it never substitutes for the per-metric tier.

Every metric in the report schema MUST carry exactly one tier label. A metric
whose tier cannot be justified from this document does not ship.

---

## 7. Scope (v0)

**In scope:** v0 is self-hosted, single-user, and has zero content egress by
construction — raw content never leaves the machine; content-derived data
leaves only as artifacts of §3-admitted classes (the §3.1 trust substrate and
§3.2 report classes), through a user-initiated publication act.

**Local-store widening (v0.1.3) changes no egress rule:** assets A8–A10 are
local-only. P1's raw-content core, the §3 whitelist, this section's
zero-content-egress statement, and CLAUDE.md invariant #1 were not widened by
that revision; nothing stored in A8–A10 leaves the machine except as an
artifact of a §3-admitted class through a user-initiated publication act —
the class rulings themselves are the v0.2.0 §3 revision, adopted at the same
sitting.

**Out of scope:**

- Defending a compromised host OS
- Proving content quality of undisclosed work
- Proving single-human authorship (later: exam + continuity)
- Hosted/multi-user operation, payments, identity linking
- Codex/other-tool ingestion beyond a documented adapter interface
- Real-time anchoring finer than daily (batch is the availability hedge)

## 8. Invariant Test Matrix (must exist before Phase 3 completes)

| Invariant | Test |
|-----------|------|
| No plaintext in published artifacts | Marker-string fixtures → full pipeline → scan outputs |
| No nonce leaves A2 | fs-watch test + grep of all writes outside A2 |
| Nonce uniqueness | Property test over generated nonces |
| Ledger append-only + chained | Tamper a row → verification fails |
| Scorer purity | Same ledger twice → byte-identical report |
| Scorer no-network | Socket-blocking harness → scorer completes |
| Crash safety | Kill daemon mid-write → ledger verifies, no partial rows |

---

*Changelog: 0.1.0 — initial model (owner-authored seed, adopted 2026-07-08).
0.1.1 — owner-approved additions per mybench-ops OPEN_QUESTIONS #15: positive
v0 scope statement (§7) and invariant-#1 amendment-ADR requirement (ADV-5).
Pending owner text: explicit trust-assumptions section (OPEN_QUESTIONS #16).
0.1.2 — §4 domain-tag list gains `mybench:v1:session` (root-finalization
wrapper) per accepted ADR-0002; mechanism unchanged.
0.1.3 — local evidence-store widening (MYB-16.1; owner-decided at ADR
sitting 2, 2026-07-14): §2 gains A8 (normalized event store), A9
(raw-transcript retention archive), A10 (local report + preview staging), an
A1 archived-copy cross-reference, an A3 description addendum (capture-time
event rows and session fields — structural metadata, no content), and the
§2.1 reviewed-widening procedure; ADV-4 rescoped from a blanket no-copies
rule to enumerated 0700-data-dir stores with a pointers-only rule for
content-like fields (no span-copy class) and a hard graceful-degradation
requirement (pointed-to bytes gone from source and archive ⇒ honest coverage
drop / UNKNOWN, never failure, never fabrication); §7 records that no egress
rule changed. Local-only revision; the publication surface was ruled
separately by 0.2.0 at the same sitting.
0.2.0 — owner-approved MYB-16.2 revision (expanded mybench-ops
OPEN_QUESTIONS #17; owner-decided at ADR sitting 2, 2026-07-14): §3 rewritten
as a class-based publication surface with normative controls (§3.3) and
temporal-granularity rules (§3.4) covering the Workflow Fingerprint sections,
topology aggregates/gallery, token/cost profile, episode counts,
blame-survival cohorts, and badge/card claims; corpus-level phase-transition
aggregates admitted as a class distinct from the still-banned per-session
ordered sequences; raw orchestration-file contents rejected for v0 (no
opt-in path); P1 split into raw-content core and §3-governed derived margin.
OQ #18 backfill floor (14 days) and OQ #35 cohort grain (quarter) pinned in
§3.4. §6 synced to the sitting's tier-mapping decisions (ADR-0014/ADR-0015:
TEE-VERIFIED environment semantics; reserved
JUDGED(unattested)/JUDGED(attested) qualifier slots via the TIER(qualifier)
grammar; IMPORTED annotation line).*
