# mybench

Privacy-preserving developer attestation system.

Mybench anchors your AI-agent sessions (Claude Code / Codex local JSONL
transcripts) and git commits to public timestamp authorities in real time, using
**salted commitments** so content never leaves your machine. A deterministic,
open-source scorer computes activity metrics over the local ledger and produces a
versioned JSON report rendered as a static page with verification instructions.

See [`docs/PROJECT_BRIEF.md`](docs/PROJECT_BRIEF.md) for the full brief and
[`CLAUDE.md`](CLAUDE.md) for the non-negotiable privacy invariants. Planning,
roadmap, and decisions live in the sibling repo `../mybench-ops`.

## Layout

- `src/mybench/<component>/` — one package per single responsibility:
  `daemon`, `anchor`, `hooks`, `scorer`, `judge` (placeholder), `verify`, `report`.
- `schemas/` — versioned JSON Schemas (`ledger_entry`, `report`).
- `tests/` — pytest smoke tests (synthetic fixtures only).

## Verify someone's anchors (zero trust required)

```
python -m venv .venv && . .venv/bin/activate
pip install -e .
python -m mybench.verify <anchors repo URL or local clone path>
```

Checks anchor schema/signatures, chain continuity (no gaps or rewrites),
and OpenTimestamps proofs. Network use: cloning the anchors repo, plus
Bitcoin block-header cross-checks against blockstream.info and
mempool.space (two independent sources must agree). Add `--offline` to skip
the header check — attested block heights are then printed for independent
verification via any Bitcoin node or explorer. Proofs newer than a few
hours may report as "pending (calendar-attested, not yet
Bitcoin-confirmed)" — re-run later for full confirmation.

## Develop

```
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-ci.txt && pip install -e .
ruff check .
pytest tests/
```
