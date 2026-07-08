# Mybench Threat Model

**Version:** 0.1.1
**Status:** Living document. Every feature must be justifiable against this model.
If a proposed change isn't covered here, work stops and this document is updated first.

---

## 1. Purpose & Security Goal

Mybench produces verifiable claims about a developer's AI-assisted work history
**without disclosing the content of that work**. The system's entire value rests on
two properties holding simultaneously:

- **P1 (Privacy):** No transcript content, prompt text, code, filenames, or any
  content-derived data leaves the user's machine or enters any repository.
- **P2 (Integrity):** Published claims cannot be fabricated, backdated, or
  selectively edited after the fact without detection.

A failure of P1 is a product-ending event. A failure of P2 degrades the product
to unverified self-reporting.

---

## 2. Assets

| ID | Asset | Location | Sensitivity |
|----|-------|----------|-------------|
| A1 | Agent session transcripts (Claude Code / Codex JSONL) | `~/.claude/projects/`, Codex log dirs | HIGH — contains prompts, code, secrets, filenames |
| A2 | Commitment nonces | mybench data dir (default `~/.local/share/mybench/nonces/`) | CRITICAL — leaking a nonce enables dictionary attack on its commitment |
| A3 | Local ledger (commitments, Merkle trees, metadata) | mybench data dir (`ledger.db`) | MEDIUM — contains no plaintext, but timing metadata is private-by-default |
| A4 | Git signing keys | user's SSH/GPG keyring | HIGH — standard key hygiene applies |
| A5 | Published anchors (Merkle roots + timestamps) | public `mybench-anchors` repo, OpenTimestamps | PUBLIC by design |
| A6 | Report JSON + rendered page | public, user-controlled | PUBLIC by design |
| A7 | The scorer code itself | public repo | PUBLIC; integrity matters (supply chain) |

The "mybench data dir" is a single dedicated directory outside all repos,
created mode 0700; its exact location is an implementation choice recorded in
an ADR, but it MUST NOT be inside any repository, synced folder, or backup
that leaves the machine unencrypted.

---

## 3. Public vs. Private Artifacts

### Published (and ONLY these)
- Daily Merkle roots over session commitments
- OpenTimestamps proofs for those roots
- Commit trailer hashes (session-root references) in repos the user opted in
- Versioned report JSON: counts, durations, cadence histograms, coverage
  percentages, streak lengths — all derived from ledger *metadata*, never content
- Scorer version, schema versions, verification instructions

### Never published, never leaves machine
- Transcript content or any substring, embedding, or summary of it
- Nonces
- Filenames, repo names (except repos the user explicitly opts in), project names
- Per-session timestamps at finer granularity than the report schema specifies
- The ledger itself

**Enforcement:** every code path that writes to a repo, network socket, or
report file must pass negative tests: fixtures containing known plaintext
markers are run through the full pipeline and published artifacts are scanned
for those markers, their hashes-without-nonce, and their common encodings.

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
  (`mybench:v1:leaf`, `mybench:v1:node`, `mybench:v1:day`) to prevent
  cross-context replay (leaf presented as root, etc.).

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
- Mybench centralizes pointers to sensitive transcripts — it must never
  centralize the *content* (no copies, no caches, no indexes of plaintext).

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

## 6. PROVEN vs. ANCHORED vs. CLAIMED — guarantee ladder

| Tier | Meaning | Verifier trust required |
|------|---------|------------------------|
| PROVEN | Verifiable from public artifacts + open code alone (anchor continuity, timestamps, signature validity, binding coverage) | None |
| ANCHORED | Timing/volume proven; content properties asserted by user, spot-checkable via random-audit disclosure | Statistical |
| JUDGED | Output of a pinned model/rubric (out of scope v0) | Trust in rubric validity |

Every metric in the report schema MUST carry exactly one tier label. A metric
whose tier cannot be justified from this document does not ship.

---

## 7. Scope (v0)

**In scope:** v0 is self-hosted, single-user, and has zero content egress by
construction — nothing content-derived leaves the machine except the salted
commitments, roots, and timestamps listed in §3.

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
Pending owner text: explicit trust-assumptions section (OPEN_QUESTIONS #16).*
