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
for the current default. `--detect` is reserved for source discovery and exits
3 without changing state.

`mybench scan [--watch DIR:SOURCE ...] [--repo PATH ...] [--archive]
[--upgrade] [--json]` performs one capture pass. It also flushes the lifecycle
queue and reconciles missed commits in each enrolled repo. With no `--watch`,
the owner-machine Claude Code location and an exists-guarded Codex location are
used. With no `--repo`, the current directory is reconciled. Transcript
retention remains off unless `--archive` is explicit.

Plain `scan` is offline. `--upgrade` is the sole scan flag that permits network
calls, and only to refresh already-staged OpenTimestamps proofs; it never
publishes them.

`mybench report [--format html,json] [--generated-at UTC-RFC3339]
[--report-version VERSION] [--enrolled-repo NAME=PATH --public NAME ...]
[--handle HANDLE] [--anchors-url URL] [--json]` builds the current scorer JSON
and static no-JavaScript page in one step. Reports live only under the private
data directory at `reports/<report-id>/`; output names are `report.json` and
`index.html`, mode 0600. The opaque ID is content-derived, so the same ledger,
arguments, and explicit `--generated-at` produce byte-identical artifacts and
the same ID. No report is published. `--open` and `--serve` are reserved and
exit 3.

`mybench capture enable --repo PATH [--repo PATH ...] [--json]` opts only the
named repos into the existing local commit-binding hook. It installs no global
hook, lifecycle integration, background process, or OS scheduler.

`mybench verify SOURCE [--offline] [--json]` verifies a public anchors tree.
Online verification may clone the supplied URL and cross-check Bitcoin headers;
`--offline` disables those network checks. The older
`python -m mybench.verify` entry point remains supported.

## Honest reserved surfaces

`mybench status`, `mybench publish`, and `mybench publish --preview` exit 3.
Both publication spellings say “not yet available; nothing published” and have
no publication or network code path. Installing, initializing, scanning, and
building a report never imply publication.

The component entry points (`python -m mybench.daemon`, `.hooks`, `.anchor`,
`.scorer`, `.report`, `.verify`, and `.normalizer`) remain available for
compatibility and focused operations.
