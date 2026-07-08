# Threat-model traceability (epics → sections)

Companion to `THREAT_MODEL.md` (v0.1.1), maintained per privacy invariant #4:
every feature must trace to the threat model. Epics live in
`../../mybench-ops/epics/`; review record in
`../../mybench-ops/reviews/2026-07-08-threat-model-v0.1.0-review.md`.

| Epic | Threat-model sections | Notes |
|---|---|---|
| MYB-1 Phase 0 — threat model + commitment scheme | §4 (scheme + dictionary-attack analysis); ADV-1 | Analysis: `analysis/short-content-dictionary-attack.md`; ADR-0002 pins §4's encodings, domains, nonce policy |
| MYB-2 Phase 1 — capture daemon + ledger | §2 A1–A3; §3 enforcement (negative tests); ADV-4 (perms, no ports); ADV-6 (hash-chained ledger); §8 rows 1–4, 7 | |
| MYB-3 Phase 2 — anchoring + commit binding | §2 A5; §3 published-artifacts list; ADV-1 (trailer correlation, opt-in control); ADV-2 (backdating defeat); ADV-6 (gap visibility) | Daily root cadence per §3/§4 |
| MYB-4 Phase 3 — scorer + privacy self-audit | §2 A7; ADV-3 (supply chain, no-network, nonce isolation); §6 (tier labels); §8 rows 5–6 | §8 matrix must exist before Phase 3 completes |
| MYB-5 Phase 4 — report + publish | §2 A6; §3 report whitelist; §6 (one tier per metric); ADV-1 (report-granularity residual); ADV-6 (verification claims) | Verify CLI is the PROVEN-tier checker |

Gaps flagged (not filled): explicit trust-assumptions section pending owner
text — `mybench-ops/backlog/OPEN_QUESTIONS.md` #16.
