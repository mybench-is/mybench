# Local status contract (MYB-11.6)

`mybench status` is a strictly read-only, always-offline view of local capture
health. It never initializes, scans, repairs permissions, upgrades proofs, or
writes output to disk. Human output and the stable `--json` object go only to
stdout.

## Exit codes and health

- `0` / `health=healthy`: initialized local state has no detected issue.
- `1` / `health=attention`: action is useful (for example an unrun/stale scan,
  missing source, unbound commit, pending proof, or unmapped legacy enrollment).
- `1` / `health=error`: local integrity cannot be trusted (for example loose
  permissions, a corrupt ledger/config/receipt/proof, or invalid enrollment).
- `2`: argparse command-line usage error.

An installation without a data directory returns attention with
`not_initialized`. A plain fresh `mybench init` returns healthy empty state.
After consented sources are configured, a missing scan receipt is honestly
`scan_never_completed`; no timestamp is inferred or manually backfilled.

## Successful-scan time

Successful daemon capture passes and unified `mybench scan` runs atomically
update `scan-health.json` under the private 0700 data directory. The canonical
0600 receipt contains only UTC completion times and HMAC fingerprints for the
actual watch/repository locations covered. It contains no paths, names,
content, or key bytes. A failed scan does not advance completion state.

Status matches the current private scan config against those fingerprints.
Each configured source therefore has its own `last_scanned_at`; newly added or
uncovered sources remain `null`. Any configured source older than seven days,
or never covered, makes scan health stale and prints `run mybench scan`.

## JSON v1

The output is validated against packaged `schemas/status.schema.json`, closed
with `additionalProperties: false` at every object. Top-level fields are:

- `schema_version`, `command`, `health`, `exit_code`;
- `data_dir` and four private-key role states;
- ledger integrity and row count;
- scan config/receipt state, last completion, staleness, configured watches,
  repos, exclusions, and unmapped opaque enrollment count;
- anchored-through date and confirmed/pending/invalid proof counts;
- a sorted, closed list of machine-readable issue codes.

Paths and exclusion patterns are displayed because this is an explicit local
diagnostic surface. Transcript content, filenames discovered inside watched
trees, nonces, private keys, session ids, raw repo identities, Git messages,
and proof bytes have no output field.
