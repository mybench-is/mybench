# Capture daemon

The daemon records privacy-preserving evidence from local Claude Code and
Codex transcripts. For each complete transcript record it saves a fresh secret
nonce and appends only a salted commitment and metadata to a private local
ledger. Transcript text does not enter the ledger.

## What it stores

| Plain-language name | Threat-model label | Contents and purpose |
|---|---|---|
| Saved nonce records | A2 | One secret random value per committed transcript record. These secrets make the commitments resistant to guessing. |
| Private commitment ledger | A3 | Salted commitments, counts, timestamps, and hash-chain metadata. It does not contain transcript text. |
| Private transcript archive | A9 | An optional byte-for-byte plaintext copy of committed transcript records, kept so later verification or selective disclosure is possible after the agent harness deletes its original log. |

All three stores live outside repositories in the mode-0700 mybench data
directory; their files are mode 0600.

## How optional archiving works

Archiving is **off by default**. It runs only with `--archive` or an explicit
`DaemonConfig(..., archive_enabled=True)` setting, so installing or restarting
the daemon cannot silently copy an existing transcript corpus.

When archiving is enabled, each scan follows this order:

1. Save and flush the nonce records, then append the commitment-ledger row.
2. Copy the exact committed transcript records into the private transcript
   archive.
3. Flush and reread the archive, then verify that its bytes reproduce the
   commitment already recorded in the ledger.

The archive contains transcript bytes only. It does not contain or replace the
nonce store or ledger. Those two stores are used to verify the archive. If
archiving fails, the commitment remains recorded and a later enabled scan
retries the archive without creating duplicate ledger rows. An enabled scan
can also backfill visible sessions committed while archiving was off.

## Safety boundaries

- Archive files are append-only per session; verified history is never
  truncated or replaced when a live transcript shrinks or changes.
- Concurrent daemon processes serialize the complete nonce, ledger, and
  optional archive update.
- Files and their containing directories are flushed in crash-safe order
  before later state may rely on them.
- Raw content, transcript filenames, archive paths, and data-directory paths
  never enter logs, ledger rows, anchor staging, or any repository.

The A2/A3/A9 labels above are cross-references to `THREAT_MODEL.md` §2; the
plain-language store names describe the runtime behavior.
