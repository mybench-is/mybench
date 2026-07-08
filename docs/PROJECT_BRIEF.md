# mybench — Project Brief

## Summary

Mybench anchors a developer's AI-agent sessions (Claude Code / Codex local JSONL
transcripts) and git commits to public timestamp authorities (OpenTimestamps and
a public anchors repo) in real time, using salted commitments so that content
stays private. A deterministic, open-source scorer computes activity metrics over
the local ledger and produces a versioned JSON report, rendered as a static page
with verification instructions.

## How privacy is preserved

Only salted commitments `H(nonce||len||content)`, Merkle roots, and timestamps
are ever published. Transcript content, prompt text, code, and filenames never
leave the machine or enter a git repo. Nonces and the ledger live in a dedicated
local data directory (mode 0700) outside all repos.

## Metrics

The scorer computes, over the local ledger:

- history length
- cadence
- session statistics
- commit↔session binding coverage

## Trust tiers

Every metric carries a trust tier:

- **PROVEN** — cryptographically verifiable.
- **ANCHORED** — timing/volume proven, content claimed.
- **JUDGED** — reproducible model opinion (out of scope for v0).

## Later phases

TEE-based scoring service, attested LLM judgment, and a proctored exam.

## v0 goal

Run mybench on my own machine, pass a privacy self-audit, and publish my own
report.

---

See `../mybench-ops/ROADMAP.md` for the phase breakdown and `THREAT_MODEL.md`
(owner-supplied) for the threat model every feature must trace to.
