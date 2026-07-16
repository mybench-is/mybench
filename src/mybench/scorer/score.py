"""The deterministic scorer — a pure function per docs/metrics-v0.md (MYB-4.2).

Inputs are plain data supplied by the caller: ledger rows, date-only anchor events,
optional enrolled-repo facts, and ``generated_at``. This module never reads
a clock, the environment, or the filesystem (test-enforced), so the same
inputs produce byte-identical report bytes on any machine. A skeptic audits
this file: no cleverness.

Formulas, tiers, bucket edges, and exclusions are pinned in
docs/metrics-v0.md; changing any of them is a schema_version event.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, timedelta

from mybench.anchor.receipt import ReceiptError, derive_receipt_latencies

SCHEMA_VERSION = "1"
SCORER_VERSION = "0.2.0"
DOMAIN_ROW = b"mybench:v1:ledgerrow"

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
LATENCY_BUCKETS = (
    ("00_under_5m", 0, 5 * 60),
    ("01_5m_to_1h", 5 * 60, 60 * 60),
    ("02_1h_to_24h", 60 * 60, 24 * 60 * 60),
    ("03_1d_to_7d", 24 * 60 * 60, 7 * 24 * 60 * 60),
    ("04_7d_plus", 7 * 24 * 60 * 60, None),
)
LATENCY_UNKNOWN_BUCKET = "05_unknown"
LATENCY_CAVEAT = (
    "Local wall-clock time after the first successful OTS calendar response; "
    "self-attested, not the independently verified Bitcoin block time."
)
PROVENANCE_CAVEAT = (
    "Percentages cover only ledger rows named by supplied anchor events; "
    "unanchored local rows are excluded."
)


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


def _canonical_row(row: dict) -> bytes:
    return json.dumps(
        {key: value for key, value in row.items() if key != "h"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _row_hash(row: dict) -> str:
    return hashlib.sha256(DOMAIN_ROW + _canonical_row(row)).hexdigest()


def _ordered_rows(rows: list[dict]) -> list[dict]:
    if any(type(row.get("i")) is not int for row in rows):
        raise ScoreError("ledger rows require integer i fields")
    return sorted(rows, key=lambda row: row["i"])


def _normalized_anchors(anchors: list[dict], row_count: int) -> list[dict]:
    required = (
        "schema_version",
        "date",
        "row_start",
        "row_end",
        "session_count",
        "root",
        "chain_tip",
    )
    normalized = []
    for anchor in anchors:
        missing = [name for name in required if name not in anchor]
        if missing:
            raise ScoreError(f"anchor event missing required fields: {', '.join(missing)}")
        if type(anchor["row_start"]) is not int or type(anchor["row_end"]) is not int:
            raise ScoreError("anchor event row range must use integers")
        if type(anchor["session_count"]) is not int or anchor["session_count"] < 0:
            raise ScoreError("anchor event session_count must be a non-negative integer")
        if (
            anchor["row_start"] < 0
            or anchor["row_end"] <= anchor["row_start"]
            or anchor["row_end"] > row_count
        ):
            raise ScoreError("anchor event range is outside the supplied ledger")
        try:
            date.fromisoformat(anchor["date"])
        except (TypeError, ValueError) as exc:
            raise ScoreError("anchor event date is invalid") from exc
        if not all(isinstance(anchor[name], str) for name in ("schema_version", "root", "chain_tip")):
            raise ScoreError("anchor event schema/root/chain-tip fields must be strings")
        if len(anchor["date"]) != 10 or anchor["date"][4:5] != "-" or anchor["date"][7:8] != "-":
            raise ScoreError("anchor event date must use YYYY-MM-DD")
        if any(
            len(anchor[name]) != 64
            or any(character not in "0123456789abcdef" for character in anchor[name])
            for name in ("root", "chain_tip")
        ):
            raise ScoreError("anchor event root/chain-tip must be lowercase 64-hex")
        if anchor["session_count"] > anchor["row_end"] - anchor["row_start"]:
            raise ScoreError("anchor event session_count exceeds its covered range")
        normalized.append(anchor)
    return sorted(
        normalized,
        key=lambda anchor: (
            anchor["row_start"],
            anchor["row_end"],
            anchor["date"],
            anchor["root"],
            anchor["chain_tip"],
        ),
    )


def _ledger_chain_valid(rows: list[dict]) -> bool:
    for index, row in enumerate(rows):
        if row.get("i") != index:
            return False
        if (row.get("type") == "genesis") != (index == 0):
            return False
        expected_prev = "0" * 64 if index == 0 else rows[index - 1].get("h")
        if row.get("prev") != expected_prev or row.get("h") != _row_hash(row):
            return False
    return bool(rows)


def _anchor_chain_continuity(rows: list[dict], anchors: list[dict]) -> bool:
    if not anchors or not _ledger_chain_valid(rows) or anchors[0]["row_start"] != 0:
        return False
    previous_end = 0
    for anchor in anchors:
        if anchor["row_start"] != previous_end:
            return False
        if anchor["chain_tip"] != rows[anchor["row_end"] - 1].get("h"):
            return False
        previous_end = anchor["row_end"]
    return True


def _latency_bucket(seconds: float) -> str:
    for label, lower, upper in LATENCY_BUCKETS:
        if seconds >= lower and (upper is None or seconds < upper):
            return label
    raise ScoreError(f"negative anchor latency {seconds} seconds")


def _anchor_latency_distribution(rows: list[dict], anchors: list[dict]) -> dict:
    counts = {label: 0 for label, _lower, _upper in LATENCY_BUCKETS}
    counts[LATENCY_UNKNOWN_BUCKET] = 0
    for anchor in anchors:
        try:
            derived = derive_receipt_latencies(rows, anchor)
        except ReceiptError as exc:
            raise ScoreError(f"anchor latency derivation failed: {exc}") from exc
        if derived is None:
            counts[LATENCY_UNKNOWN_BUCKET] += anchor["row_end"] - anchor["row_start"]
            continue
        for _row_index, latency in derived.per_row:
            counts[_latency_bucket(latency.total_seconds())] += 1
    return counts


def _evidence_provenance_split(anchors: list[dict]) -> dict:
    imported: set[int] = set()
    live: set[int] = set()
    if anchors:
        imported.update(range(anchors[0]["row_start"], anchors[0]["row_end"]))
        for anchor in anchors[1:]:
            live.update(range(anchor["row_start"], anchor["row_end"]))
    live -= imported
    total = len(imported | live)
    if total == 0:
        return {"IMPORTED": 0.0, "LIVE": 0.0}
    imported_share = round(len(imported) / total, 4)
    live_share = round(len(live) / total, 4)
    return {"IMPORTED": imported_share, "LIVE": live_share}


def _input_schema_versions(rows: list[dict], anchors: list[dict]) -> dict:
    def versions(values) -> list[str]:
        unique = {str(value) for value in values}
        return sorted(unique, key=lambda value: (len(value), value))

    return {
        "ledger": versions(row.get("schema_version", "unknown") for row in rows),
        "anchor": versions(anchor["schema_version"] for anchor in anchors),
    }


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
    anchors: list[dict],
    *,
    generated_at: str,
    report_version: str = "v0",
    enrolled: dict[str, dict] | None = None,
    allow_synthetic: bool = False,
) -> bytes:
    """Compute the v0 report from ledger rows and date-only anchor events.

    ``enrolled`` (optional): per opted-in repo name, ``{"tip": <commit hash>,
    "commits": [<hashes since enrollment>], "public": True}`` — gathered by the
    caller so this function stays pure. ``public: True`` marks the repo as
    public+named; every entry must carry it or the report is refused
    (MYB-6.11 fail-closed guard, see below). ``allow_synthetic`` permits
    fixture ledgers in tests; a real report must never contain
    synthetic-source sessions.
    """
    rows = _ordered_rows(rows)
    anchors = _normalized_anchors(anchors, len(rows))
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
            "value": (max(_day(anchor["date"]) for anchor in anchors)
                      - min(_day(anchor["date"]) for anchor in anchors)).days if anchors else 0,
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
            "value": sum(anchor["session_count"] for anchor in anchors),
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
        {
            "name": "anchor_latency_distribution",
            "value": _anchor_latency_distribution(rows, anchors),
            "trust_tier": "ANCHORED",
            "caveat": LATENCY_CAVEAT,
        },
        {
            "name": "evidence_provenance_split",
            "value": _evidence_provenance_split(anchors),
            "trust_tier": "PROVEN",
            "caveat": PROVENANCE_CAVEAT,
        },
        {
            "name": "anchor_chain_continuity",
            "value": _anchor_chain_continuity(rows, anchors),
            "trust_tier": "PROVEN",
        },
    ]

    report = {
        "schema_version": SCHEMA_VERSION,
        "report_version": report_version,
        "generated_at": generated_at,
        "scorer_version": SCORER_VERSION,
        "input_schema_versions": _input_schema_versions(rows, anchors),
        "backfill_note": BACKFILL_NOTE,
    }
    if anchors:
        report["anchored_through"] = max(anchor["date"] for anchor in anchors)
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
