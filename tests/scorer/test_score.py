"""MYB-4.2: deterministic scorer — golden bytes, properties, purity, leaks."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mybench.ledger import GENESIS_PREV, row_hash
from mybench.schemas import load_validator
from mybench.scorer import score as score_mod
from mybench.scorer.score import ScoreError, score
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger

GOLDEN = Path(__file__).with_name("golden_report_v0.json")


def session_row(i, sid, ts, items, source="synthetic"):
    return {
        "schema_version": "1", "i": i, "type": "session", "ts": ts, "prev": "0" * 64,
        "h": f"{i:064x}", "session_id": sid, "session_root": "c" * 64,
        "item_count": items, "source": source,
    }


def binding_row(i, commit_hash, ts):
    return {
        "schema_version": "1", "i": i, "type": "binding", "ts": ts, "prev": "0" * 64,
        "h": f"{i:064x}", "commit_hash": commit_hash, "commit_ts": ts,
        "repo_id": "ab" * 8,
    }


def rechain(rows):
    result = []
    for index, source in enumerate(rows):
        row = {key: value for key, value in source.items() if key != "h"}
        row["i"] = index
        row["prev"] = GENESIS_PREV if index == 0 else result[-1]["h"]
        row["h"] = row_hash(row)
        result.append(row)
    return result


def anchor_event(rows, row_start, row_end, date_value, root_digit):
    return {
        "schema_version": "2",
        "date": date_value,
        "row_start": row_start,
        "row_end": row_end,
        "session_count": sum(
            row["type"] == "session" for row in rows[row_start:row_end]
        ),
        "root": root_digit * 64,
        "chain_tip": rows[row_end - 1]["h"],
    }


def receipt_row(event, receipt_ts, append_ts, receipt_digit):
    return {
        "schema_version": "2",
        "i": -1,
        "type": "anchor_receipt",
        "ts": append_ts,
        "prev": "0" * 64,
        "h": "0" * 64,
        "anchor_row_start": event["row_start"],
        "anchor_row_end": event["row_end"],
        "anchor_root": event["root"],
        "anchor_chain_tip": event["chain_tip"],
        "receipt_ts": receipt_ts,
        "receipt_id": receipt_digit * 16,
    }


GENESIS = rechain([
    {"schema_version": "1", "i": 0, "type": "genesis",
     "ts": "2026-01-01T00:00:00Z", "prev": GENESIS_PREV}
])[0]

_FIRST_PREFIX = rechain([
    GENESIS,
    session_row(1, "s-alpha", "2026-01-01T08:00:00Z", 4),
    session_row(2, "s-beta", "2026-01-02T09:00:00Z", 40),
])
_FIRST_ANCHOR = anchor_event(_FIRST_PREFIX, 0, 3, "2026-01-02", "a")
_SECOND_PREFIX = rechain([
    *_FIRST_PREFIX,
    receipt_row(
        _FIRST_ANCHOR,
        "2026-01-02T09:30:00Z",
        "2026-01-02T09:31:00Z",
        "1",
    ),
    session_row(3, "s-alpha", "2026-01-08T10:00:00Z", 12),  # growth supersedes row 1
    session_row(4, "s-gamma", "2026-02-01T11:00:00Z", 1500, source="synthetic"),
    binding_row(5, "a" * 40, "2026-02-02T12:00:00Z"),
])
_SECOND_ANCHOR = anchor_event(_SECOND_PREFIX, 3, 7, "2026-02-02", "b")
FIXED_ROWS = rechain([
    *_SECOND_PREFIX,
    receipt_row(
        _SECOND_ANCHOR,
        "2026-02-02T12:30:00Z",
        "2026-02-02T12:31:00Z",
        "2",
    ),
])
FIXED_BATCHES = [_FIRST_ANCHOR, _SECOND_ANCHOR]
# public: True is the MYB-6.11 public+named flag; it gates PROVEN coverage /
# a raw tip but is NOT written to the report, so golden bytes are unaffected.
FIXED_ENROLLED = {
    "synthetic/repo": {"tip": "b" * 40, "commits": ["a" * 40, "f" * 40], "public": True}
}


def fixed_report_bytes():
    return score(
        FIXED_ROWS, FIXED_BATCHES,
        generated_at="2026-07-09T00:00:00Z",
        enrolled=FIXED_ENROLLED,
        allow_synthetic=True,
    )


# --- Golden vector (AC #2) -------------------------------------------------------


def test_golden_report_bytes():
    assert fixed_report_bytes() == GOLDEN.read_bytes()


def test_golden_values_spot_check():
    report = json.loads(fixed_report_bytes())
    m = {x["name"]: x for x in report["metrics"]}
    assert m["sessions_total"]["value"] == 3  # alpha counted once
    assert m["items_total"]["value"] == 12 + 40 + 1500  # latest rows only
    assert m["anchored_capture_events"]["value"] == 4
    assert m["anchored_span_days"]["value"] == 31
    assert m["session_size_distribution"]["value"] == {
        "0001-0010": 0, "0011-0100": 2, "0101-1000": 0, "1001+": 1
    }
    # Sortable-label rule (handoff #4): canonical key order IS numeric order.
    assert list(m["session_size_distribution"]["value"]) == sorted(
        m["session_size_distribution"]["value"])
    assert m["binding_coverage"]["value"] == {"synthetic/repo": 0.5}
    assert report["binding_tips"] == {"synthetic/repo": "b" * 40}
    assert m["binding_coverage"]["trust_tier"] == "PROVEN"
    assert m["anchor_latency_distribution"]["value"] == {
        "00_under_5m": 0,
        "01_5m_to_1h": 2,
        "02_1h_to_24h": 0,
        "03_1d_to_7d": 3,
        "04_7d_plus": 2,
        "05_unknown": 0,
    }
    assert m["evidence_provenance_split"]["value"] == {
        "IMPORTED": 0.4286,
        "LIVE": 0.5714,
    }
    assert m["anchor_chain_continuity"]["value"] is True
    assert report["anchored_through"] == "2026-02-02"
    assert report["input_schema_versions"] == {"anchor": ["2"], "ledger": ["1", "2"]}
    assert "not a completeness claim" in report["backfill_note"]


# --- Determinism properties (AC #1) --------------------------------------------------


@st.composite
def ledgers(draw):
    n = draw(st.integers(1, 12))
    rows, i = [GENESIS], 1
    for k in range(n):
        day = draw(st.integers(0, 90))
        rows.append(session_row(
            i, f"s-{draw(st.integers(0, 5))}", f"2026-0{1 + day // 31}-{1 + day % 28:02d}T00:00:00Z",
            draw(st.integers(1, 3000)),
        ))
        i += 1
    rows = rechain(rows)
    anchors = []
    if draw(st.booleans()):
        anchors.append(anchor_event(rows, 0, len(rows), max(r["ts"] for r in rows)[:10], "c"))
    return rows, anchors


@settings(max_examples=60, deadline=None)
@given(ledgers(), st.randoms())
def test_repeat_and_shuffle_invariance(data, rng):
    rows, batches = data
    a = score(rows, batches, generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)
    b = score(rows, batches, generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)
    assert a == b
    shuffled_rows, shuffled_batches = list(rows), list(batches)
    rng.shuffle(shuffled_rows)
    rng.shuffle(shuffled_batches)
    c = score(shuffled_rows, shuffled_batches,
              generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)
    assert a == c  # input ordering independence, as the spec declares


def test_byte_identity_across_process_boundary():
    script = (
        "from tests.scorer.test_score import fixed_report_bytes; import hashlib;"
        "print(hashlib.sha256(fixed_report_bytes()).hexdigest())"
    )
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                         cwd=Path(__file__).parents[2], timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == hashlib.sha256(fixed_report_bytes()).hexdigest()


def test_latency_bucket_edges_and_no_exact_or_ordered_values():
    prefix = rechain([
        {**GENESIS, "ts": "2026-01-01T12:00:00Z"},
        session_row(1, "s-day", "2026-01-07T12:00:00Z", 1),
        session_row(2, "s-hour", "2026-01-08T11:00:00Z", 1),
        session_row(3, "s-five-minutes", "2026-01-08T11:55:00Z", 1),
        session_row(4, "s-under-five", "2026-01-08T11:55:01Z", 1),
    ])
    anchor = anchor_event(prefix, 0, len(prefix), "2026-01-08", "d")
    rows = rechain([
        *prefix,
        receipt_row(anchor, "2026-01-08T12:00:00Z", "2026-01-08T12:01:00Z", "3"),
    ])
    report_bytes = score(
        rows, [anchor], generated_at="2026-07-09T00:00:00Z", allow_synthetic=True
    )
    report = json.loads(report_bytes)
    metric = next(
        item for item in report["metrics"] if item["name"] == "anchor_latency_distribution"
    )
    assert metric["value"] == {
        "00_under_5m": 1,
        "01_5m_to_1h": 1,
        "02_1h_to_24h": 1,
        "03_1d_to_7d": 1,
        "04_7d_plus": 1,
        "05_unknown": 0,
    }
    assert metric["trust_tier"] == "ANCHORED" and "self-attested" in metric["caveat"]
    for forbidden in (b"receipt_ts", b"anchor_row_start", b"2026-01-08T12:00:00Z"):
        assert forbidden not in report_bytes
    assert isinstance(metric["value"], dict)  # histogram only; no ordered row sequence


def test_missing_receipt_is_unknown_and_negative_latency_fails_closed():
    prefix = rechain([GENESIS, session_row(1, "s", "2026-01-02T00:00:00Z", 1)])
    anchor = anchor_event(prefix, 0, len(prefix), "2026-01-02", "e")
    report = json.loads(
        score(prefix, [anchor], generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)
    )
    latency = next(
        item for item in report["metrics"] if item["name"] == "anchor_latency_distribution"
    )
    assert latency["value"]["05_unknown"] == len(prefix)

    rows = rechain([
        *prefix,
        receipt_row(anchor, "2025-12-31T23:59:59Z", "2026-01-02T00:01:00Z", "4"),
    ])
    with pytest.raises(ScoreError, match="predates covered row"):
        score(rows, [anchor], generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)


def test_continuity_checks_ledger_ranges_and_anchor_tips():
    def continuity(rows, anchors):
        report = json.loads(
            score(
                rows,
                anchors,
                generated_at="2026-07-09T00:00:00Z",
                allow_synthetic=True,
            )
        )
        return next(
            item["value"]
            for item in report["metrics"]
            if item["name"] == "anchor_chain_continuity"
        )

    assert continuity(FIXED_ROWS, FIXED_BATCHES) is True

    broken_chain = [dict(row) for row in FIXED_ROWS]
    broken_chain[1]["h"] = "f" * 64
    assert continuity(broken_chain, FIXED_BATCHES) is False

    gapped = [FIXED_BATCHES[0], {**FIXED_BATCHES[1], "row_start": 4}]
    assert continuity(FIXED_ROWS, gapped) is False

    wrong_tip = [{**FIXED_BATCHES[0], "chain_tip": "f" * 64}, FIXED_BATCHES[1]]
    assert continuity(FIXED_ROWS, wrong_tip) is False


def test_no_anchors_reports_empty_provenance_denominator_without_freshness_claim():
    report = json.loads(
        score(FIXED_ROWS, [], generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)
    )
    metrics = {item["name"]: item for item in report["metrics"]}
    assert metrics["evidence_provenance_split"]["value"] == {
        "IMPORTED": 0.0,
        "LIVE": 0.0,
    }
    assert metrics["anchor_chain_continuity"]["value"] is False
    assert report["input_schema_versions"]["anchor"] == []
    assert "anchored_through" not in report


def test_provenance_split_uses_explicit_rows_and_live_default_after_v3_boundary():
    imported = {
        **session_row(2, "s-imported", "2026-01-02T00:00:00Z", 3),
        "schema_version": "3",
        "provenance": "IMPORTED",
    }
    live_explicit = {
        **binding_row(4, "a" * 40, "2026-01-04T00:00:00Z"),
        "schema_version": "3",
        "provenance": "LIVE",
    }
    rows = rechain(
        [
            GENESIS,
            {
                "schema_version": "3",
                "i": 1,
                "type": "schema_version",
                "ts": "2026-01-01T01:00:00Z",
                "prev": "0" * 64,
                "h": "0" * 64,
                "previous_schema_version": "2",
                "new_schema_version": "3",
                "provenance": "IMPORTED",
            },
            imported,
            session_row(3, "s-live-default", "2026-01-03T00:00:00Z", 4),
            live_explicit,
        ]
    )
    anchor = anchor_event(rows, 0, len(rows), "2026-01-04", "f")
    report = json.loads(
        score(rows, [anchor], generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)
    )
    metric = next(
        item for item in report["metrics"] if item["name"] == "evidence_provenance_split"
    )
    # Genesis keeps the legacy first-anchor label; the boundary and imported
    # session are explicit; the absent post-boundary v1 row defaults LIVE.
    assert metric["value"] == {"IMPORTED": 0.6, "LIVE": 0.4}
    assert report["input_schema_versions"]["ledger"] == ["1", "3"]


def test_provenance_split_rejects_unknown_explicit_value():
    rows = [dict(row) for row in FIXED_ROWS]
    rows[1]["provenance"] = "MAYBE"
    with pytest.raises(ScoreError, match="provenance is invalid"):
        score(
            rows,
            FIXED_BATCHES,
            generated_at="2026-07-09T00:00:00Z",
            allow_synthetic=True,
        )


# --- Purity guard (AC #3) --------------------------------------------------------------


def test_scorer_module_is_pure():
    import ast

    source = Path(score_mod.__file__).read_text()
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= {"__future__", "hashlib", "json", "datetime", "mybench"}, (
        f"impure imports: {imports}"
    )
    # And no clock accessors even via the allowed datetime import.
    forbidden = (".now(", ".today(", ".utcnow(", "open(", "os.environ")
    hits = [tok for tok in forbidden if tok in source]
    assert hits == [], f"impure calls in scorer: {hits}"


# --- Schema conformance (AC #4) ----------------------------------------------------------


def test_report_validates_and_whitelist_holds():
    report = json.loads(fixed_report_bytes())
    validator = load_validator("report.schema.json")
    validator.validate(report)
    report["session_ids"] = ["leak"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


def test_synthetic_guard_and_empty_ledger():
    with pytest.raises(ScoreError, match="synthetic"):
        score(FIXED_ROWS, [], generated_at="2026-07-09T00:00:00Z")
    with pytest.raises(ScoreError, match="no session rows"):
        score([GENESIS], [], generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)
    with pytest.raises(ScoreError, match="no commits"):
        score(FIXED_ROWS, [], generated_at="2026-07-09T00:00:00Z", allow_synthetic=True,
              enrolled={"r": {"tip": "b" * 40, "commits": [], "public": True}})


def test_iso_year_boundary_weeks():
    rows = [GENESIS,
            session_row(1, "s-1", "2025-12-29T00:00:00Z", 5),   # ISO week 2026-W01
            session_row(2, "s-2", "2026-01-05T00:00:00Z", 5)]   # ISO week 2026-W02
    report = json.loads(score(rows, [], generated_at="2026-07-09T00:00:00Z",
                              allow_synthetic=True))
    dist = next(m for m in report["metrics"]
                if m["name"] == "sessions_per_week_distribution")["value"]
    assert dist == {"00": 0, "01-05": 2, "06-15": 0, "16-40": 0, "41+": 0}


# --- MYB-6.11 fail-closed binding guard --------------------------------------------------


def test_enrolled_without_public_flag_raises():
    """An enrolled entry missing public+named is refused, never downgraded/leaked."""
    for facts in (
        {"tip": "b" * 40, "commits": ["a" * 40]},            # flag absent
        {"tip": "b" * 40, "commits": ["a" * 40], "public": False},
        {"tip": "b" * 40, "commits": ["a" * 40], "public": "true"},  # not `is True`
    ):
        with pytest.raises(ScoreError, match="public"):
            score(FIXED_ROWS, FIXED_BATCHES, generated_at="2026-07-09T00:00:00Z",
                  allow_synthetic=True, enrolled={"private/repo": facts})


def test_one_unflagged_entry_fails_the_whole_report():
    """Fail-closed: a single unverifiable repo rejects the entire report."""
    enrolled = {
        "synthetic/repo": {"tip": "b" * 40, "commits": ["a" * 40], "public": True},
        "private/repo": {"tip": "c" * 40, "commits": ["a" * 40]},
    }
    with pytest.raises(ScoreError, match="public"):
        score(FIXED_ROWS, FIXED_BATCHES, generated_at="2026-07-09T00:00:00Z",
              allow_synthetic=True, enrolled=enrolled)


def test_public_flag_output_is_byte_identical_to_golden():
    """The guard rejects invalid input only; valid output is unchanged."""
    assert fixed_report_bytes() == GOLDEN.read_bytes()
    # public: True is a gate, not a payload — it must not appear in the report.
    assert b'"public"' not in fixed_report_bytes()
    # Determinism preserved with the flagged entry.
    assert fixed_report_bytes() == fixed_report_bytes()


# --- Leak scan (AC #5) ---------------------------------------------------------------------


def test_report_from_canary_ledger_is_leak_free(tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    from mybench.anchor.batch import build_batch
    from mybench.anchor.event import build_event

    event = build_event(build_batch(led), led.rows(), date="2026-01-02")
    led.append_anchor_receipt(
        staged_event=event,
        receipt_ts="2026-01-02T00:00:00Z",
        ts="2026-01-02T00:01:00Z",
    )
    report_bytes = score(led.rows(), [event],
                         generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)
    out = tmp_path / "report.json"
    out.write_bytes(report_bytes)
    assert assert_no_canaries([out], canaries) == 1
    planted = tmp_path / "planted.json"
    planted.write_bytes(report_bytes + canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], canaries)


# --- CLI wrapper ------------------------------------------------------------------------------


def test_cli_refuses_synthetic_ledger(tmp_path, capsys):
    fx = generate_fixtures(tmp_path / "fx")
    build_canary_ledger(fx)
    from mybench.scorer.__main__ import main

    assert main(["--generated-at", "2026-07-09T00:00:00Z"]) == 1
    assert "synthetic" in capsys.readouterr().err


def test_cli_consumes_staged_date_only_event_and_private_receipt(tmp_path, capsys):
    from mybench import paths
    from mybench.anchor.batch import build_batch
    from mybench.anchor.event import build_event, stage_event
    from mybench.commitments import generate_nonce
    from mybench.ledger import Ledger
    from mybench.scorer.__main__ import main

    ledger = Ledger()
    ledger.append_session(
        session_id="real-evidence-coverage",
        session_root=generate_nonce(),
        item_count=7,
        source="claude-code",
        ts="2026-07-01T00:00:00Z",
    )
    event = build_event(build_batch(ledger), ledger.rows(), date="2026-07-01")
    stage_event(event, b"synthetic-pending-proof", paths.anchors_dir())
    ledger.append_anchor_receipt(
        staged_event=event,
        receipt_ts="2026-07-01T00:10:00Z",
        ts="2026-07-01T00:11:00Z",
    )

    out = tmp_path / "report.json"
    assert main(["--generated-at", "2026-07-09T00:00:00Z", "--out", str(out)]) == 0
    assert capsys.readouterr().err == ""
    report = json.loads(out.read_bytes())
    metrics = {item["name"]: item for item in report["metrics"]}
    assert report["anchored_through"] == "2026-07-01"
    assert report["input_schema_versions"] == {"anchor": ["2"], "ledger": ["1", "2"]}
    assert metrics["anchor_chain_continuity"]["value"] is True
    assert metrics["anchor_latency_distribution"]["value"]["01_5m_to_1h"] == 2


def _enrolled_fixture_repo(tmp_path):
    """One synthetic repo with the live hook + marker and one bound commit,
    plus a session row so the ledger is scoreable."""
    import mybench.commitments as c
    from mybench.hooks import binding
    from mybench.ledger import Ledger

    Ledger().append_session(session_id="real-1", session_root=c.generate_nonce(),
                            item_count=7, source="claude-code", ts="2026-07-01T00:00:00Z")
    repo = tmp_path / "enrolled"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "s@example.invalid"],
                   check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "S"], check=True)
    binding.install(str(repo))
    (repo / ".mybench").mkdir()
    (repo / ".mybench" / "commit-binding-enabled").touch()
    (repo / "f.txt").write_text("synthetic\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "enroll"], check=True)
    return repo


def test_cli_end_to_end_with_enrolled_repo(tmp_path, capsys):
    from mybench.scorer.__main__ import main

    repo = _enrolled_fixture_repo(tmp_path)
    out = tmp_path / "report.json"
    rc = main(["--generated-at", "2026-07-09T00:00:00Z",
               "--enrolled-repo", f"synthetic-name={repo}",
               "--public", "synthetic-name", "--out", str(out)])
    assert rc == 0, capsys.readouterr().err
    report = json.loads(out.read_bytes())
    load_validator("report.schema.json").validate(report)
    cov = next(m for m in report["metrics"] if m["name"] == "binding_coverage")
    assert cov["value"] == {"synthetic-name": 1.0}


def test_cli_refuses_enrolled_repo_not_asserted_public(tmp_path, capsys):
    """MYB-6.11 end to end: enrollment alone must not imply the public+named
    assertion — without --public NAME the guard refuses the whole report."""
    from mybench.scorer.__main__ import main

    repo = _enrolled_fixture_repo(tmp_path)
    out = tmp_path / "report.json"
    rc = main(["--generated-at", "2026-07-09T00:00:00Z",
               "--enrolled-repo", f"synthetic-name={repo}", "--out", str(out)])
    assert rc == 1
    assert "public" in capsys.readouterr().err
    assert not out.exists()  # refused, never written


def test_cli_rejects_public_flag_for_unknown_repo(tmp_path, capsys):
    from mybench.scorer.__main__ import main

    repo = _enrolled_fixture_repo(tmp_path)
    rc = main(["--generated-at", "2026-07-09T00:00:00Z",
               "--enrolled-repo", f"synthetic-name={repo}",
               "--public", "synthetic-name", "--public", "typo-name"])
    assert rc == 1
    assert "typo-name" in capsys.readouterr().err
