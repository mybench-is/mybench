# daemon

**Single responsibility:** preserve capture evidence from local AI-agent transcript
sources (Claude Code / Codex JSONL). The daemon first appends salted commitments —
`H(nonce||len||content)` — to the local hash-chained ledger, then extends A9, the
session-addressed byte-exact retention archive. A9 is local-only under the 0700 data
directory (0600 files), append-only, and verified on read-back against the ledger;
failure never blocks commitment capture. Raw content, transcript filenames, archive
paths, and data-directory paths never enter logs, ledger rows, anchor staging,
or any repository (privacy invariants #1–#4; THREAT_MODEL §2 A9 / ADV-4).
