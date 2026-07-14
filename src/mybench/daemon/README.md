# daemon

**Single responsibility:** preserve capture evidence from local AI-agent transcript
sources (Claude Code / Codex JSONL). The daemon first appends salted commitments —
`H(nonce||len||content)` — to the local hash-chained ledger. A9 transcript archiving
is **disabled by default** for every configuration and CLI invocation; it activates
only with `--archive` (or `DaemonConfig(..., archive_enabled=True)`) so installing or
restarting a daemon cannot silently copy an existing corpus. When explicitly enabled,
the daemon extends the session-addressed byte-exact archive only after capture. A9 is
local-only under the 0700 data directory (0600 files), append-only, and verified on
read-back against the ledger; failure never blocks commitment capture. Whole scans are
serialized across daemon processes, and every new nonce is file-fsynced (plus a parent
directory fsync for a new nonce file); immediately before a ledger append, the whole
nonce file, nonce directory, and data directory are re-fsynced in order. Fresh managed
directories are durably bootstrapped through their first existing parent. A later
enabled scan archives visible sessions already committed while archiving was off,
without new ledger rows. Raw content, transcript filenames, archive paths, and
data-directory paths never enter logs, ledger rows, anchor staging, or any repository
(privacy invariants #1–#4; THREAT_MODEL §2 A9 / ADV-4).
