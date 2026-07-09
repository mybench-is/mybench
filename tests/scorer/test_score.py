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


GENESIS = {"schema_version": "1", "i": 0, "type": "genesis",
           "ts": "2026-01-01T00:00:00Z", "prev": "0" * 64, "h": "e" * 64}

FIXED_ROWS = [
    GENESIS,
    session_row(1, "s-alpha", "2026-01-01T08:00:00Z", 4),
    session_row(2, "s-beta", "2026-01-02T09:00:00Z", 40),
    session_row(3, "s-alpha", "2026-01-08T10:00:00Z", 12),  # growth supersedes row 1
    session_row(4, "s-gamma", "2026-02-01T11:00:00Z", 1500, source="synthetic"),
    binding_row(5, "a" * 40, "2026-02-02T12:00:00Z"),
]
FIXED_BATCHES = [
    {"ts": "2026-01-02T00:00:00Z", "session_count": 2},
    {"ts": "2026-02-02T00:00:00Z", "session_count": 2},
]
FIXED_ENROLLED = {"synthetic/repo": {"tip": "b" * 40, "commits": ["a" * 40, "f" * 40]}}


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
        "1-10": 0, "11-100": 2, "101-1000": 0, "1000+": 1
    }
    assert m["binding_coverage"]["value"] == {"synthetic/repo": 0.5}
    assert report["binding_tips"] == {"synthetic/repo": "b" * 40}
    assert m["binding_coverage"]["trust_tier"] == "PROVEN"
    assert report["backfill_note"]


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
    batches = [{"ts": r["ts"], "session_count": draw(st.integers(1, 3))}
               for r in rows[1:][: draw(st.integers(0, 3))]]
    return rows, batches


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
    assert imports <= {"__future__", "json", "datetime"}, f"impure imports: {imports}"
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
              enrolled={"r": {"tip": "b" * 40, "commits": []}})


def test_iso_year_boundary_weeks():
    rows = [GENESIS,
            session_row(1, "s-1", "2025-12-29T00:00:00Z", 5),   # ISO week 2026-W01
            session_row(2, "s-2", "2026-01-05T00:00:00Z", 5)]   # ISO week 2026-W02
    report = json.loads(score(rows, [], generated_at="2026-07-09T00:00:00Z",
                              allow_synthetic=True))
    dist = next(m for m in report["metrics"]
                if m["name"] == "sessions_per_week_distribution")["value"]
    assert dist == {"0": 0, "1-5": 2, "6-15": 0, "16-40": 0, "40+": 0}


# --- Leak scan (AC #5) ---------------------------------------------------------------------


def test_report_from_canary_ledger_is_leak_free(tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    from mybench.anchor.batch import build_batch

    report_bytes = score(led.rows(), [build_batch(led)],
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


def test_cli_end_to_end_with_enrolled_repo(tmp_path, capsys):
    import mybench.commitments as c
    from mybench.hooks import binding
    from mybench.ledger import Ledger
    from mybench.scorer.__main__ import main

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

    out = tmp_path / "report.json"
    rc = main(["--generated-at", "2026-07-09T00:00:00Z",
               "--enrolled-repo", f"synthetic-name={repo}", "--out", str(out)])
    assert rc == 0, capsys.readouterr().err
    report = json.loads(out.read_bytes())
    load_validator("report.schema.json").validate(report)
    cov = next(m for m in report["metrics"] if m["name"] == "binding_coverage")
    assert cov["value"] == {"synthetic-name": 1.0}
