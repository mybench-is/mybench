"""Plain-language metric descriptions — versioned WITH docs/metrics-v0.md.

Every metric the scorer can emit MUST have an entry here; the page build
fails on a metric without one (MYB-5.5 — the whitelist discipline, inverted:
nothing ships unexplained). Wording owner-reviewed 2026-07-09. Adding or
changing a metric means updating docs/metrics-v0.md AND this map together.
"""

INTRO = (
    "This page attests to a developer's AI-agent work history. A session is "
    "one working session with a coding agent (Claude Code or Codex), recorded "
    "locally as a transcript. mybench fingerprints every transcript line with "
    "salted commitments and anchors Merkle roots of them to Bitcoin and a "
    "public git repository — so when the work happened is provable by anyone, "
    "while what the work was stays private. Every metric below is computed by "
    "an open-source, deterministic scorer and carries a trust tier."
)

METRIC_DESCRIPTIONS = {
    "anchor_chain_continuity": (
        "Whether the private ledger hash chain verifies and every supplied "
        "anchor range is contiguous with a matching covered-row chain tip."
    ),
    "anchor_latency_distribution": (
        "How long covered ledger rows waited for the first successful "
        "OpenTimestamps calendar response, shown only in coarse time buckets."
    ),
    "anchored_span_days": (
        "Days between the first and latest public anchor — how long this "
        "publicly verifiable timeline has existed. Needs no trust in the author."
    ),
    "anchored_capture_events": (
        "Session-capture moments attested in the public anchors. A session that "
        "grows and is captured again counts each time — this is what the "
        "anchors literally prove, so it is the PROVEN companion to the "
        "deduplicated session count below."
    ),
    "active_days": "Distinct days on which at least one session was recorded.",
    "items_total": (
        "Every line of every session transcript is individually fingerprinted; "
        "this counts those lines — a proxy for the volume of recorded activity."
    ),
    "ledger_span_days": (
        "Days between the first and last record in the local activity log — the "
        "self-reported timeline length (see the backfill note above)."
    ),
    "sessions_total": (
        "Distinct agent sessions recorded, deduplicated (unlike capture events)."
    ),
    "sessions_per_week_distribution": (
        "How busy the weeks were: the number of calendar weeks whose session "
        "count fell into each bucket."
    ),
    "session_size_distribution": (
        "How long the sessions were, bucketed by transcript line count — exact "
        "per-session sizes are deliberately not published."
    ),
    "source_breakdown": "Which AI coding agent produced each session.",
    "binding_coverage": (
        "For git repositories the author explicitly opted in: the fraction of "
        "commits made while mybench was recording, each carrying a "
        "tamper-evident link into the attested timeline. 1.0 means every "
        "commit since enrollment."
    ),
    "evidence_provenance_split": (
        "Share of ledger rows captured in the first anchor (IMPORTED), covered "
        "by later anchors (LIVE), measured across anchored rows only."
    ),
}

GLOSSARY = (
    ("session", "one working session with an AI coding agent, recorded as a local transcript"),
    ("item", "one line of a session transcript — the unit that gets fingerprinted"),
    ("capture event", "one moment when the recorder noticed and fingerprinted a session's "
                      "current state; growing sessions produce several"),
    ("anchor", "a published Merkle-root fingerprint of the activity log, timestamped via "
               "Bitcoin (OpenTimestamps) and a public git repo — proves existence at a "
               "point in time without revealing content"),
    ("ledger", "the local, hash-chained, append-only log of commitments; it never leaves "
               "the author's machine — only its roots do"),
)
