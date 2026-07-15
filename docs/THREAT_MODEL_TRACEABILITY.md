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
| Private storage and commitment state | `paths.py`, `nonces.py`, `ledger.py`, `ledger_entry.schema.json` | §2 A2–A3, §2.1, §3.5, §4, ADV-4, ADV-6 | Secrets and ledger state stay outside repositories in the mode-0700 data directory; nonce files are mode 0600 and durable before a ledger row can reference them; ledger rows are content-free and hash-chained. |
| Transcript capture and commitments | `daemon/`, `commitments.py` | §2 A1–A3, §2.1, §4, §8, ADV-1, ADV-4, ADV-6 | Only complete transcript records are committed; every item uses a fresh secret nonce and typed commitment; transcript text and filenames never enter the ledger or logs. |
| Normalized structural evidence | `normalizer/`, `normalized_store.py`, `commitment_tree.py`, `normalized_corpus.schema.json` | §2 A8–A9, §2.1, §3.5–3.6, §4, ADV-1, ADV-4, ADV-6 | The ADR-0018 consent filter runs before A8 derivation; A8 stores closed-schema structure and commitment-verified pointers, never content copies; missing live/A9 targets become UNKNOWN; canonical artifacts are root-bound and stored only under the private mode-0700 data directory with mode-0600 files. |
| Anchoring, identity, and opted-in hook observations | `anchor/`, `identity.py`, `hooks/`, `capture_identity.py` | §2 A3–A5, §2.1, §3.1, §3.4–3.6, §4, ADV-1, ADV-2, ADV-4, ADV-6 | Signed daily roots and proofs expose only admitted trust-substrate fields; commit binding is marker-file opt-in; Claude lifecycle hooks are explicit machine-local opt-in, discard raw payload fields before a private queue write, and enter the same hash chain; public time remains day-grained. |
| Deterministic scoring and claims | `scorer/`, `claims/`, `registry/` | §2 A7, §3.1–3.3, §3.6, §6, ADV-3, ADV-4, ADV-6 | Scoring is local and deterministic; claims are closed-schema and registry-bound; unpublished or unregistered classes fail closed; trust labels follow §6. |
| Reports and privacy enforcement | `report/`, `leakscan.py`, `report.schema.json` | §2 A6/A10, §3.2–3.6, §6, ADV-1, ADV-3, ADV-6 | Rendered output is schema-validated and class-whitelisted; required controls and tier labels travel with claims; leak checks reject content and disallowed identifiers before publication. |
| Public verification | `verify/`, `schemas/` | §2 A5–A7, §3.1–3.2, §6, ADV-1, ADV-2, ADV-6 | Verification checks signatures, proofs, schemas, and declared trust tiers without an account or network-only trust dependency; malformed or overstated evidence fails closed. |

This table is an implementation index, not evidence that a proposed feature is
safe. Reviewers must still inspect the actual data flow and stop when
`THREAT_MODEL.md` does not cover it.
