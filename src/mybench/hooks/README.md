# hooks

**Single responsibility:** provide opt-in, local capture-hook ingress without
ever blocking the developer's harness.

- Git commit binding is activated per repo via
  `.mybench/commit-binding-enabled`; mybench never installs a global git hook
  or sets `core.hooksPath`. Only commitments and timestamps are recorded —
  never diff content or filenames.
- Claude lifecycle capture is activated per machine by explicit user-settings
  install. Raw hook JSON is reduced in memory to a closed tuple, queued under
  the private data dir, then flushed by the normal scan into hash-chained event
  rows. Start/end boundaries add only keyed-HMAC repo/worktree ids and the
  observed Git HEAD from a timeout-bounded probe; raw cwd, branch, remote, and
  Git paths are discarded. It never implies publication. See
  [`docs/claude-lifecycle-hooks.md`](../../../docs/claude-lifecycle-hooks.md).

See `../../../../mybench-ops/decisions/ADR-0001-workspace-structure.md` and
ADR-0013 in the same planning repository.
