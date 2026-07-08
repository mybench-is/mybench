# Test fixtures — synthetic only

**Privacy invariant #3: real transcripts are NEVER used as test data.**
Everything in and under this package is synthetic by construction: the
generator (`synthetic.py`) is the only source of fixture transcripts, its
content is seeded and clearly marked (`MYBENCH-CANARY-*`, `synthetic …`),
and it mimics only the *structure* of Claude Code / Codex JSONL logs.

Do not copy, paraphrase, or "anonymize" a real transcript into a fixture —
regenerate from the generator instead.

- `synthetic.py` — deterministic fixture generator; embeds content canaries,
  fake-filename canaries, low-entropy lines (MYB-1.3), and provides 32-byte
  nonce canaries (ADR-0002) for nonce-leak tests.
- `leakscan.py` — `assert_no_canaries(paths, canaries)`: raw / hex / base64
  (all byte phases) / gzip scanning. Every story that writes to disk or
  network must run its published artifacts through this (invariant #1,
  threat model §3 Enforcement).
