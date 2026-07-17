# Threat-model traceability (implementation surfaces → controls)

This is the product-side companion to `THREAT_MODEL.md` **v0.2.0**. It maps
landed implementation surfaces to the security and privacy controls they must
enforce. Product changes that add an asset, data flow, publication class, or
trust claim must update the threat model first and then update this map.

Planning traceability—epics, future work, owner questions, and release
sections—belongs in the
[`mybench-ops` planning map](https://github.com/mybench-is/mybench-ops/blob/master/docs/threat-model-traceability.md).
It is intentionally not copied into this repository.

| Product surface | Implementation | Threat-model coverage | Enforced boundary |
|---|---|---|---|
| Private storage and commitment state | `paths.py`, `nonces.py`, `ledger.py`, `ledger_entry.schema.json` | §2 A2–A3, §2.1, §3.5, §4, ADV-4, ADV-6 | Secrets and ledger state stay outside repositories in the mode-0700 data directory; nonce files are mode 0600 and durable before a ledger row can reference them; ledger rows are content-free and hash-chained. Ledger v2 closes session metadata to model/provider/effort/version and four provider-reported token aggregates, and admits one private anchor-receipt branch whose signed-event/range/root/tip/time semantics are checked before append. Ledger v3 adds only the closed `IMPORTED`/`LIVE` provenance enum and its one-time version boundary; historical Git rows retain exactly commit hash, committer timestamp, and keyed-HMAC repo id. Frozen v1/v2 rows remain unchanged. |
| Transcript capture and commitments | `daemon/`, `commitments.py`, `docs/session-metadata-adapters.md` | §2 A1–A3, §2.1, §4, §8, ADV-1, ADV-2, ADV-4, ADV-6 | Only complete transcript records are committed; every item uses a fresh secret nonce and typed commitment; transcript text and filenames never enter the ledger or logs. Claude/Codex metadata adapters inspect only documented JSON paths, omit unknowns rather than zeroing or guessing, and never turn thinking/content/tool/path fields into observations. |
| Normalized structural evidence | `normalizer/`, `normalized_store.py`, `commitment_tree.py`, `normalized_corpus.schema.json`, `repo_evidence.schema.json` | §2 A8–A9, §2.1, §3.5–3.6, §4, ADV-1, ADV-4, ADV-6 | The ADR-0018 consent filter runs before A8 derivation. Transcript adapters admit subject records; the enrolled-Git loader admits only declared-subject commits, keeps merge-tree structure UNKNOWN, and reduces names/paths to fixed structural classes plus opaque object pointers. A8 stores closed-schema structure and commitment-verified pointers, never content copies; missing live/A9/Git targets become UNKNOWN. Both artifact classes reuse the exact normalized-corpus Merkle contract and live only under the private mode-0700 data directory with mode-0600 files. |
| Anchoring, identity, and opted-in hook observations | `anchor/`, `identity.py`, `hooks/`, `capture_identity.py` | §2 A3–A5, §2.1, §3.1, §3.4–3.6, §4, ADV-1, ADV-2, ADV-4, ADV-6 | Signed daily roots and proofs expose only admitted trust-substrate fields; commit binding is marker-file opt-in; Claude lifecycle hooks are explicit machine-local opt-in, reduce raw cwd/Git paths to keyed-HMAC repo/worktree ids, retain only boundary HEAD shas, discard all other raw payload fields before a private queue write, and enter the same hash chain; public time remains day-grained. |
| Deterministic scoring and claims | `scorer/`, `claims/`, `registry/` | §2 A7, §3.1–3.3, §3.6, §6, ADV-3, ADV-4, ADV-6 | Scoring is local and deterministic; claims are closed-schema and registry-bound; unpublished or unregistered classes fail closed; trust labels follow §6. Conditioned entries pin a taxonomy id/version, require the claim's condition, and declare a positive support floor for every admitted cell so thin cells are absent, never zero. Conditional denominator sources are explicit; the registry pins severity class ids while numeric weighting remains versioned judge-rubric behavior. |
| Reports and privacy enforcement | `report/`, `leakscan.py`, `report.schema.json` | §2 A6/A10, §3.2–3.6, §6, ADV-1, ADV-3, ADV-6 | Rendered output is schema-validated and class-whitelisted; required controls and tier labels travel with claims; leak checks reject content and disallowed identifiers before publication. |
| Public verification | `verify/`, `schemas/` | §2 A5–A7, §3.1–3.2, §6, ADV-1, ADV-2, ADV-6 | Verification checks signatures, proofs, schemas, and declared trust tiers without an account or network-only trust dependency; malformed or overstated evidence fails closed. |

This table is an implementation index, not evidence that a proposed feature is
safe. Reviewers must still inspect the actual data flow and stop when
`THREAT_MODEL.md` does not cover it.
