# Claude Code lifecycle capture

MYB-12.4 adds an opt-in, machine-local adapter for lifecycle observations that
the transcript scanner cannot reconstruct. It does not publish anything and it
does not install itself during package installation.

## Pinned harness contract

The adapter was built and synthetically verified on 2026-07-15 against the
installed Claude Code **2.1.210** and the official
[hooks reference](https://code.claude.com/docs/en/hooks). The registered event
surface is:

| Hook event | Official event-specific input | Stored mapping |
|---|---|---|
| `SessionStart` | `source`: `startup`, `resume`, `clear`, `compact`; optional `model` | `event_kind=session_start`; the known source becomes `trigger` |
| `SessionEnd` | `reason`: `clear`, `resume`, `logout`, `prompt_input_exit`, `bypass_permissions_disabled`, `other` | `event_kind=session_end`; `clear`/`resume` are retained and other reasons become `unknown` |
| `PreCompact` | `trigger`: `manual`, `auto`; `custom_instructions` | `event_kind=compact_pre`; the trigger is retained |

All three payloads also carry `session_id`, `transcript_path`, `cwd`, and
`hook_event_name`. The transcript path is immediately reduced to the daemon's
existing opaque session id using the private scope key; the raw path is never
queued. For start/end only, `cwd` is passed in memory to the bounded Git probe
described below and then discarded. Claude's raw session id, model, compact
instructions, and every unknown field are dropped before the first write.
Unknown future enum values become `unknown`; they are never guessed.

Claude Code 2.1.210 exposes the active model at `SessionStart`, but its documented
lifecycle surface does not expose a mid-session model-change event or predecessor
session id. Those observations remain absent. Model/effort/token extraction is
MYB-12.5; no model change or lineage is fabricated here.

## Git boundary provenance

MYB-12.6 extends the same installed command without changing Claude settings.
At `SessionStart` and `SessionEnd`, three local Git commands are each bounded
at 0.2 seconds and the whole handler remains under Claude's one-second external
timeout. The probe observes only:

- whether the worktree is non-bare and HEAD is attached;
- the worktree top and Git common directory, reduced immediately to separate
  16-hex keyed HMAC identifiers under the existing private scope key; and
- the 40/64-hex HEAD object id, stored as `head_before` on start or
  `head_after` on end.

The repo id uses the Git common-dir hierarchy, so a main and linked worktree
share one repo id while retaining distinct worktree ids. For ordinary repos,
the common-dir base preserves the existing canonical-worktree repo id, so
commit-binding enrollment and lifecycle observations stay joinable.

Non-repository cwd, bare repositories, detached HEAD, probe timeout, and
missing Git all produce an event with the provenance fields absent. They never
guess a value or lose the lifecycle boundary. The private hook log receives
only a closed absence reason and `count=1`; no command output, path, branch,
remote, or exception message is logged. `PreCompact` never invokes Git.

## Data flow and failure behavior

```text
Claude stdin JSON + bounded Git facts (memory only)
  -> closed structural tuple (optional HMAC ids + HEAD at start/end)
  -> <data-dir>/queue/claude-lifecycle.jsonl (0600)
  -> next capture scan
  -> schema-v2 event row in the hash-chained ledger
```

The handler is installed as an async command with a one-second external timeout.
It always exits zero, emits no stdout/stderr, and records failures only as an
integer count plus an exception class in the private metadata-only hook log. If
the mybench data directory does not exist, it is a silent no-op.

Queue lines are appended under `flock` and fsynced. The scan processes complete
lines before compacting the queue, preserves an incomplete tail, and deduplicates
replays by `(session_id, event_kind, ts)`. A kill after a ledger append but before
queue compaction therefore replays safely; a kill during the ledger append uses
the existing torn-tail recovery path. Queue version 2 carries the optional Git
tuple; a version-1 lifecycle line already present during upgrade remains
flushable without invented provenance.

Context generations are observation-only: generation zero is the default,
`PreCompact` increments it, and the following `SessionStart(source=compact)`
shares that new generation. Resume and end events retain the latest observed
generation. Missing boundaries remain absent rather than inferred.

## Explicit install and removal

The adapter modifies only the current user's `~/.claude/settings.json`, preserving
unrelated settings and hooks:

```sh
python -m mybench.hooks lifecycle install
python -m mybench.hooks lifecycle uninstall
```

Both commands print the exact event entries changed. Install is idempotent;
uninstall removes only handlers with mybench's exact exec arguments. Neither
command touches ledger publication, report state, repository hooks, project
settings, or managed settings.

The supervised first enable completed on the owner machine on 2026-07-15 and is
recorded in `mybench-ops/SETUP_TODO.md`. MYB-12.6 reuses that installed command;
it requires no additional settings change and does not broaden publication.
