# `mybench` command reference

Installing the Python wheel provides one channel-agnostic command:

```sh
pip install mybench
mybench --help
```

The current surface is fully noninteractive. Commands never prompt and every
operation with machine-consumed output accepts `--json` after the subcommand.
JSON output is one compact object with sorted keys. It deliberately reports
counts, state, and opaque report IDs—not transcript paths, filenames, content,
nonces, or key material.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | The operation completed, or verification passed. |
| `1` | The operation failed, or verification returned a failing verdict. |
| `2` | The command line is invalid; emitted by `argparse`. |
| `3` | The named surface is reserved but honestly unavailable in this version. |

## Local workflow

`mybench init [--local-first] [--json]` creates or validates the private 0700
data tree and the four local key roles. `--local-first` is explicit spelling
for the current default. `--detect` proposes only the requested Claude, Codex,
and explicitly rooted Git sources; it writes the private scan config only after
`--accept-all` or interactive confirmation. `--decline` writes nothing.

`mybench scan [--watch DIR:SOURCE ...] [--repo PATH ...] [--archive]
[--upgrade] [--quiet] [--json]` performs one capture pass. It also flushes the lifecycle
queue and reconciles missed commits in each enrolled repo. With no `--watch`,
the owner-machine Claude Code location and an exists-guarded Codex location are
used. With no `--repo`, the current directory is reconciled. Transcript
retention remains off unless `--archive` is explicit.

Plain `scan` is offline. `--upgrade` is the sole scan flag that permits network
calls, and only to refresh already-staged OpenTimestamps proofs; it never
publishes them.

`--quiet` suppresses successful output for OS-scheduled use. The installed
jobs add an internal `--scheduled` marker so a private schedule receipt records
the attempt result; it does not widen capture inputs or network access.

`mybench report [--format html,json] [--generated-at UTC-RFC3339]
[--report-version VERSION] [--enrolled-repo NAME=PATH --public NAME ...]
[--handle HANDLE] [--anchors-url URL] [--json]` builds the current scorer JSON
and static no-JavaScript page in one step. Reports live only under the private
data directory at `reports/<report-id>/`; output names are `report.json` and
`index.html`, mode 0600. The opaque ID is content-derived, so the same ledger,
arguments, and explicit `--generated-at` produce byte-identical artifacts and
the same ID. No report is published. `--open` and `--serve` are reserved and
exit 3.

`mybench capture enable --repo PATH [--repo PATH ...]
[--schedule|--no-schedule] [--json]` opts only the named repos into the local
commit-binding hook and, by default, registers an OS-native daily scan. The
scheduled form requires the accepted private scan config to contain every
named repo, so the unit/plist embeds no repo or transcript path. It supports a
systemd user timer on Linux and launchd on macOS. `--no-schedule` is the
explicit hook-only/manual fallback when neither user scheduler is reachable.

`mybench capture disable --repo PATH [--repo PATH ...] [--json]` removes only
mybench-owned hooks, markers, enrollment records, schedule state, and the
systemd/launchd job. Both enable and disable are idempotent. They never touch a
foreign post-commit hook or scheduler file, global Git configuration, or a
resident process.

`mybench status [--json]` is the read-only/offline local health view. JSON v2
adds scheduler backend, registration state, and last scheduled attempt/result
to the v1 data/key/ledger/scan/proof fields.

`mybench verify SOURCE [--offline] [--json]` verifies a public anchors tree.
Online verification may clone the supplied URL and cross-check Bitcoin headers;
`--offline` disables those network checks. The older
`python -m mybench.verify` entry point remains supported.

## Honest reserved surfaces

`mybench publish` and `mybench publish --preview` exit 3 and say “not yet
available; nothing published.” They have no publication or network code path.
Installing, initializing, scanning, scheduling, checking status, and building a
report never imply publication.

The component entry points (`python -m mybench.daemon`, `.hooks`, `.anchor`,
`.scorer`, `.report`, `.verify`, and `.normalizer`) remain available for
compatibility and focused operations.
