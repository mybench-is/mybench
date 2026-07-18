# Test fixtures — synthetic only

**Privacy invariant #3: real transcripts are NEVER used as test data.**
Everything in and under this package is synthetic by construction: the
generator (`synthetic.py`) is the only source of fixture transcripts,
lifecycle events, Git evidence, and planning/orchestration trees. Its content
comes only from constants plus a seeded `random.Random`, is clearly marked
(`MYBENCH-CANARY-*`, `synthetic …`), and mimics only input *structure*.

Do not copy, paraphrase, or "anonymize" a real transcript, repository, plan,
instruction, orchestration file, filename, or local path into a fixture.
Regenerate from the seeded generator instead. Equal seeds produce equal
relative paths and bytes even under differently named destination directories;
the determinism test is the proof that ambient local data is not a source.

- `synthetic.py` — deterministic fixture generator; embeds content canaries,
  fake-filename canaries, low-entropy lines (MYB-1.3), and provides 32-byte
  nonce canaries (ADR-0002) for nonce-leak tests. Codex fixtures use the
  rollout-v1 session-meta, turn-context, response-item, event-message, tool,
  token, and compaction envelopes; nonce canaries remain separate pipeline
  inputs and never appear in transcript bytes. It also writes Claude hook and
  Codex structural-lifecycle streams, a Git-evidence snapshot, and synthetic
  plan/instruction/orchestration file trees.
- `leakscan.py` — `assert_no_canaries(paths, canaries)`: raw / hex / base64
  (all byte phases) / gzip scanning of both artifact bytes and path names.
  `assert_no_canaries_in_directory(directory, canaries)` is the whole-report /
  whole-preview helper and refuses a missing, non-directory, or empty target.
  Every story that writes to disk or network must scan the complete produced
  surface (invariant #1, threat model §3 Enforcement).

## Canary class inventory

`FixtureSet.new_canaries` exposes the stable class names below as planted
`bytes`; `FixtureSet.canary(class_name)` retrieves one value and
`FixtureSet.all_canaries()` includes the entire v1 + v2 catalog.

| Class | Planted synthetic surface | Privacy exclusion exercised |
|---|---|---|
| `repo_name` | Git snapshot and lifecycle cwd | Repository name |
| `worktree_name` | Git snapshot and lifecycle cwd | Worktree name |
| `branch_name` | Git snapshot | Branch name |
| `local_path` | Git snapshot and lifecycle records | Absolute/local path |
| `plan_filename` | Plan path and orchestration reference | Plan filename |
| `plan_content` | Plan body | Plan content |
| `instruction_filename` | Instruction path and plan/orchestration references | Instruction filename |
| `instruction_content` | Instruction body and Claude `PreCompact` shape | Instruction content |
| `orchestration_filename` | Orchestration path | Orchestration filename |
| `orchestration_content` | Orchestration body | Orchestration content |
| `employer_name` | Git snapshot | Employer identity string |
| `client_name` | Git snapshot | Client identity string |
| `private_url` | Git snapshot remote | Private URL |
| `secret_token` | Git snapshot credential-shaped field | Secret-shaped token |
| `full_precision_timestamp` | Claude/Codex lifecycle streams | Exact timestamp |
| `test_command` | Codex function-call shape | Test command |
| `test_result` | Codex function-result shape | Test result/output |

Every class has a planted-canary firing test and a disjoint clean-pass test
over raw, lower/upper hex, standard and URL-safe base64 at every byte phase,
and gzip-contained forms. These companion tests prevent a vacuous green scan.
