# CLAUDE.md — mybench

Thin project guide: project-specific facts and the non-negotiable privacy
invariants only. This machine has no user-level `CLAUDE.md`, so the detected
local conventions are summarized once at the bottom as the reference point —
follow them, don't reinvent them.

## What this is

mybench: a privacy-preserving developer attestation system. Full brief in
[`docs/PROJECT_BRIEF.md`](docs/PROJECT_BRIEF.md). Companion planning repo:
`../mybench-ops` (roadmap, ADRs, backlog).

## Privacy invariants (NON-NEGOTIABLE for all future work)

1. No transcript content, prompt text, code, or filenames ever leaves the
   machine or enters a git repo. Only salted commitments H(nonce||len||content),
   Merkle roots, and timestamps are publishable.
2. Nonces and the ledger live in a dedicated local data directory (0700, outside
   all repos), never in any repo, test output, or logs.
3. Real transcripts are never used as test data — synthetic fixtures only.
4. Every feature must be justifiable against docs/THREAT_MODEL.md; if the model
   doesn't cover it, stop and flag rather than proceeding.

## Project-specific facts

- **Local data directory** (invariant #2): `${XDG_DATA_HOME:-$HOME/.local/share}/mybench`,
  mode 0700, OUTSIDE every repo. Resolve it in code via `mybench.paths` — never
  hardcode a repo-relative path, never write ledger/nonce data into a repo.
- **Trust tiers** on every metric: PROVEN (cryptographically verifiable),
  ANCHORED (timing/volume proven, content claimed), JUDGED (reproducible model
  opinion — out of scope for v0).
- **Components** (single responsibility each; see each package's README):
  `daemon`, `anchor`, `hooks`, `scorer`, `judge` (placeholder — README only),
  `verify`, `report`.
- **Commit-binding git hooks are STRICTLY OPT-IN per repo** via a marker file
  (`.mybench/commit-binding-enabled`). NEVER install a global git hook or set
  `core.hooksPath`. See `src/mybench/hooks/README.md` and
  `../mybench-ops/decisions/ADR-0001-workspace-structure.md`.
- `docs/THREAT_MODEL.md` v0.1.1 adopted 2026-07-08 (owner-authored). Invariant
  #4 is live: trace every feature to it (`docs/THREAT_MODEL_TRACEABILITY.md`);
  if it doesn't cover something, stop and flag — the doc gets updated first.

## Local conventions (detected on this machine — follow, don't reinvent)

- Package manager: **pip + venv** (no uv/poetry). Split `requirements.txt` +
  `requirements-ci.txt`.
- Layout: `src/` layout, top-level `tests/` tree.
- Lint/format: **ruff only** (line-length 100, target py311). No black/mypy/isort.
- Tests: **pytest**, `pytest.ini` with `testpaths = tests`.
- Default branch: **master**. Python: **3.11+**.
