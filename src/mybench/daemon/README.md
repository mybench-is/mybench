# daemon

**Single responsibility:** watch local AI-agent transcript sources (Claude Code /
Codex JSONL) in real time and append salted commitments — `H(nonce||len||content)`
— to the local append-only ledger. It never copies, transmits, or logs raw
transcript content, prompt text, code, or filenames; only commitments, lengths,
and timestamps reach the ledger, and nonces/ledger live in the 0700 data
directory outside every repo (privacy invariants #1 and #2).
