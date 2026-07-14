"""The deterministic scorer — a pure function per docs/metrics-v0.md (MYB-4.2).

Inputs are plain data supplied by the caller: ledger rows, anchor batches,
optional enrolled-repo facts, and ``generated_at``. This module never reads
a clock, the environment, or the filesystem (test-enforced), so the same
inputs produce byte-identical report bytes on any machine. A skeptic audits
this file: no cleverness.

Formulas, tiers, bucket edges, and exclusions are pinned in
docs/metrics-v0.md; changing any of them is a schema_version event.
"""

from __future__ import annotations

import json
from datetime import date, timedelta

SCHEMA_VERSION = "1"
SCORER_VERSION = "0.1.0"

BACKFILL_NOTE = (
    "History captured by backfill is anchored as of anchor time; "
    "capture-time metrics (ledger_span_days, active_days, sessions_total) "
    "reflect when rows were appended, not when the underlying work happened."
)

# Labels are zero-padded so canonical sorted-JSON order IS numeric order
# (handoff fix #4, 2026-07-09): determinism untouched, every consumer sees
# buckets in order, the page strips padding for display.
# Band-edge note (MYB-10.2): these v1 report-metric buckets predate the
# descriptor registry. Registry-governed scorers (MYB-10.6+) read band edges
# from mybench.registry — never constants; these migrate when their metrics
# become registry entries (fingerprint.* / MYB-13.x, gated on MYB-16.2).
WEEKLY_BUCKETS = (("00", 0, 0), ("01-05", 1, 5), ("06-15", 6, 15), ("16-40", 16, 40),
                  ("41+", 41, None))
SIZE_BUCKETS = (("0001-0010", 1, 10), ("0011-0100", 11, 100),
                ("0101-1000", 101, 1000), ("1001+", 1001, None))


class ScoreError(ValueError):
    pass


def _day(ts: str) -> date:
    return date.fromisoformat(ts[:10])


def _bucket(value: int, buckets) -> str:
    for label, lo, hi in buckets:
        if value >= lo and (hi is None or value <= hi):
            return label
    raise ScoreError(f"value {value} fits no bucket")


def _distribution(values, buckets) -> dict:
    counts = {label: 0 for label, _lo, _hi in buckets}
    for v in values:
        counts[_bucket(v, buckets)] += 1
    return counts


def _latest_session_rows(rows: list[dict]) -> dict:
    """Latest row per session_id (highest i) — the only item-count that counts."""
    latest: dict = {}
    for row in rows:
        if row["type"] != "session":
            continue
        held = latest.get(row["session_id"])
        if held is None or row["i"] > held["i"]:
            latest[row["session_id"]] = row
    return latest


def _first_seen_week(rows: list[dict]) -> dict:
    """ISO (year, week) of each session's FIRST session row."""
    first: dict = {}
    for row in rows:
        if row["type"] != "session":
            continue
        held = first.get(row["session_id"])
        if held is None or row["i"] < held["i"]:
            first[row["session_id"]] = row
    return {sid: _day(r["ts"]).isocalendar()[:2] for sid, r in first.items()}


def _weeks_between(first: date, last: date):
    week, seen = first, []
    while True:
        key = week.isocalendar()[:2]
        if key not in seen:
            seen.append(key)
        if week >= last:
            break
        week = week + timedelta(days=7)
    if last.isocalendar()[:2] not in seen:
        seen.append(last.isocalendar()[:2])
    return seen


def score(
    rows: list[dict],
    batches: list[dict],
    *,
    generated_at: str,
    report_version: str = "v0",
    enrolled: dict[str, dict] | None = None,
    allow_synthetic: bool = False,
) -> bytes:
    """Compute the v0 report; returns canonical report bytes.

    ``enrolled`` (optional): per opted-in repo name, ``{"tip": <commit hash>,
    "commits": [<hashes since enrollment>], "public": True}`` — gathered by the
    caller so this function stays pure. ``public: True`` marks the repo as
    public+named; every entry must carry it or the report is refused
    (MYB-6.11 fail-closed guard, see below). ``allow_synthetic`` permits
    fixture ledgers in tests; a real report must never contain
    synthetic-source sessions.
    """
    latest = _latest_session_rows(rows)
    if not latest:
        raise ScoreError("no session rows — nothing to report")
    if not allow_synthetic and any(r["source"] == "synthetic" for r in latest.values()):
        raise ScoreError("synthetic-source sessions present — not a real report")

    all_ts = [r["ts"] for r in rows]
    session_dates = {_day(r["ts"]) for r in rows if r["type"] == "session"}

    week_of = _first_seen_week(rows)
    weeks = _weeks_between(_day(min(all_ts)), _day(max(all_ts)))
    per_week = {w: 0 for w in weeks}
    for w in week_of.values():
        per_week[w] = per_week.get(w, 0) + 1

    sources: dict = {}
    for r in latest.values():
        sources[r["source"]] = sources.get(r["source"], 0) + 1

    metrics = [
        {
            "name": "anchored_span_days",
            "value": (max(_day(b["ts"]) for b in batches)
                      - min(_day(b["ts"]) for b in batches)).days if batches else 0,
            "trust_tier": "PROVEN",
        },
        {
            "name": "ledger_span_days",
            "value": (_day(max(all_ts)) - _day(min(all_ts))).days,
            "trust_tier": "ANCHORED",
        },
        {"name": "active_days", "value": len(session_dates), "trust_tier": "ANCHORED"},
        {"name": "sessions_total", "value": len(latest), "trust_tier": "ANCHORED"},
        {
            "name": "anchored_capture_events",
            "value": sum(b["session_count"] for b in batches),
            "trust_tier": "PROVEN",
        },
        {
            "name": "items_total",
            "value": sum(r["item_count"] for r in latest.values()),
            "trust_tier": "ANCHORED",
        },
        {
            "name": "sessions_per_week_distribution",
            "value": _distribution(per_week.values(), WEEKLY_BUCKETS),
            "trust_tier": "ANCHORED",
        },
        {
            "name": "session_size_distribution",
            "value": _distribution((r["item_count"] for r in latest.values()), SIZE_BUCKETS),
            "trust_tier": "ANCHORED",
        },
        {"name": "source_breakdown", "value": sources, "trust_tier": "ANCHORED"},
    ]

    report = {
        "schema_version": SCHEMA_VERSION,
        "report_version": report_version,
        "generated_at": generated_at,
        "scorer_version": SCORER_VERSION,
        "backfill_note": BACKFILL_NOTE,
    }
    if enrolled:
        bound = {r["commit_hash"] for r in rows if r["type"] == "binding"}
        coverage = {}
        tips = {}
        for repo, facts in sorted(enrolled.items()):
            # MYB-6.11 fail-closed guard: PROVEN binding_coverage and a RAW
            # commit tip are only sound for a public, named repo — PROVEN means
            # "verifiable from public artifacts alone" (false for a private
            # repo, whose commits aren't public) and a raw private tip is a
            # deanonymization oracle (anyone holding the repo can hash-compare).
            # Require the caller to explicitly flag each entry public+named; if
            # any entry lacks it, refuse the whole report rather than silently
            # downgrade or leak. Superseded by MYB-6.10 (the metric split +
            # HMAC pseudonyms + salted-commitment tips), which absorbs this.
            if facts.get("public") is not True:
                raise ScoreError(
                    f"enrolled repo {repo!r} is not marked public+named — "
                    "refusing to emit PROVEN binding_coverage / raw tip "
                    "(fail-closed; MYB-6.11, superseded by MYB-6.10)"
                )
            if not facts["commits"]:
                raise ScoreError(f"enrolled repo {repo!r} supplied no commits")
            hits = sum(1 for c in facts["commits"] if c in bound)
            coverage[repo] = round(hits / len(facts["commits"]), 4)
            tips[repo] = facts["tip"]
        metrics.append({"name": "binding_coverage", "value": coverage, "trust_tier": "PROVEN"})
        report["binding_tips"] = tips

    report["metrics"] = sorted(metrics, key=lambda m: m["name"])
    return json.dumps(report, sort_keys=True, separators=(",", ":")).encode() + b"\n"
