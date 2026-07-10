"""MYB-5.2: static report page — determinism, whitelist build, tiers, no JS, leaks."""

import json
from pathlib import Path

import pytest

from mybench.report.page import PageError, render_page
from mybench.scorer.score import score
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger
from tests.scorer.test_score import fixed_report_bytes

ANCHORS = "https://github.com/synthetic/mybench-anchors"


def fixed_report():
    return json.loads(fixed_report_bytes())


# --- Determinism (AC #1) ----------------------------------------------------------


def test_same_report_gives_byte_identical_page():
    a = render_page(fixed_report(), anchors_url=ANCHORS)
    b = render_page(fixed_report(), anchors_url=ANCHORS)
    assert a == b
    # Key order in the input dict must not matter.
    reordered = json.loads(json.dumps(fixed_report(), sort_keys=True))
    assert render_page(reordered, anchors_url=ANCHORS) == a


# --- Tiers, quickstart, anchors link (AC #2) -----------------------------------------


def test_every_metric_renders_with_its_tier_badge():
    report = fixed_report()
    page = render_page(report, anchors_url=ANCHORS).decode()
    for metric in report["metrics"]:
        assert metric["name"].replace("_", " ") in page
    badge_count = page.count('class="badge"')
    legend_badges = 5  # five-rung ladder (handoff #5)
    assert badge_count == len(report["metrics"]) + legend_badges
    for rung in ("IMPORTED", "ANCHORED", "PROVEN", "TEE-VERIFIED", "JUDGED"):
        assert rung in page
    assert "uvx mybench-verify" in page and "python -m mybench.verify" in page
    assert ANCHORS in page
    assert "not in scope in v0" in page  # unused rungs marked, not offered


# --- Whitelist build (AC #3, the strict option) ---------------------------------------


def test_injected_extra_field_fails_the_build():
    report = fixed_report()
    report["private_note"] = "MYBENCH-CANARY-page-0badc0de"
    with pytest.raises(PageError, match="non-conforming"):
        render_page(report, anchors_url=ANCHORS)


def test_injected_metric_field_fails_the_build():
    report = fixed_report()
    report["metrics"][0]["sample"] = "MYBENCH-CANARY-page-1badc0de"
    with pytest.raises(PageError, match="non-conforming"):
        render_page(report, anchors_url=ANCHORS)


def test_free_text_fields_are_escaped():
    report = fixed_report()
    report["metrics"][-1]["caveat"] = '<script>alert("x")</script>'
    page = render_page(report, anchors_url=ANCHORS).decode()
    assert "<script" not in page
    assert "&lt;script&gt;" in page


# --- Plain-language descriptions + glossary (MYB-5.5) --------------------------------------


def test_every_metric_has_a_rendered_description():
    from mybench.report.descriptions import METRIC_DESCRIPTIONS

    report = fixed_report()
    page = render_page(report, anchors_url=ANCHORS).decode()
    assert page.count('class="desc"') == len(report["metrics"])
    for metric in report["metrics"]:
        assert metric["name"] in METRIC_DESCRIPTIONS


def test_metric_without_description_fails_the_build():
    report = fixed_report()
    report["metrics"][0] = dict(report["metrics"][0], name="mystery_metric")
    with pytest.raises(PageError, match="no plain-language description"):
        render_page(report, anchors_url=ANCHORS)


def test_intro_and_glossary_explain_the_jargon():
    page = render_page(fixed_report(), anchors_url=ANCHORS).decode()
    assert "A session is one working session with a coding agent" in page
    for term in ("capture event", "anchor", "ledger", "item"):
        assert f"<strong>{term}</strong>" in page


def test_descriptions_map_matches_the_metrics_v0_spec():
    from mybench.report.descriptions import METRIC_DESCRIPTIONS

    spec = (Path(__file__).parents[2] / "docs" / "metrics-v0.md").read_text()
    for name in METRIC_DESCRIPTIONS:
        assert f"`{name}`" in spec, f"{name} described but not in docs/metrics-v0.md"


# --- Fully static (AC #5) ---------------------------------------------------------------


def test_page_has_no_javascript_and_pinned_references_only():
    import re

    page = render_page(fixed_report(), anchors_url=ANCHORS, handle="ckeenan").decode()
    assert "<script" not in page and "javascript:" not in page
    hrefs = set(re.findall(r'href="([^"]+)"', page))
    canonical = "https://mybench.is/@ckeenan/2026-W28"
    assert hrefs == {ANCHORS, "report.json", "https://mybench.is", canonical}
    assert "src=" not in page  # no images/iframes/external fetches (SVG is inline)


# --- Leak scan (AC #4) --------------------------------------------------------------------


def test_page_from_canary_report_is_leak_free(tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    report = json.loads(
        score(led.rows(), [], generated_at="2026-07-09T00:00:00Z", allow_synthetic=True)
    )
    out = tmp_path / "index.html"
    out.write_bytes(render_page(report, anchors_url=ANCHORS))
    assert assert_no_canaries([out], canaries) == 1
    planted = tmp_path / "planted.html"
    planted.write_bytes(out.read_bytes() + canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], canaries)


# --- CLI ---------------------------------------------------------------------------------


def test_cli_end_to_end(tmp_path, capsys):
    from mybench.report.__main__ import main

    src = tmp_path / "report.json"
    src.write_bytes(fixed_report_bytes())
    out = tmp_path / "index.html"
    assert main(["--report", str(src), "--anchors-url", ANCHORS, "--out", str(out)]) == 0
    assert out.read_bytes().startswith(b"<!DOCTYPE html>")
    bad = tmp_path / "bad.json"
    report = fixed_report()
    report["extra"] = "x"
    bad.write_text(json.dumps(report))
    assert main(["--report", str(bad), "--anchors-url", ANCHORS, "--out", str(out)]) == 1


# --- MYB-5.8: identity, backfill honesty, pretty buckets --------------------------------


def backfill_dominated_report():
    """anchored_span_days = 0 (no batches) → below the OQ #18 floor."""
    from mybench.scorer.score import score
    from tests.scorer.test_score import FIXED_ENROLLED, FIXED_ROWS

    return json.loads(score(FIXED_ROWS, [], generated_at="2026-07-09T00:00:00Z",
                            enrolled=FIXED_ENROLLED, allow_synthetic=True))


def test_backfill_dominated_annotations():
    page = render_page(backfill_dominated_report(), anchors_url=ANCHORS).decode()
    assert page.count("· backfilled") == 3  # ledger_span/active_days/sessions_total
    assert "reflects the history-import event" in page
    # And a healthy span (31 days in the golden report) has neither.
    healthy = render_page(fixed_report(), anchors_url=ANCHORS).decode()
    assert "· backfilled" not in healthy
    assert "reflects the history-import event" not in healthy


def test_identity_canonical_and_og_tags():
    page = render_page(fixed_report(), anchors_url=ANCHORS, handle="ckeenan").decode()
    assert "@ckeenan" in page
    assert '<link rel="canonical" href="https://mybench.is/@ckeenan/2026-W28">' in page
    assert 'property="og:image" content="https://mybench.is/og.png"' in page
    assert 'name="twitter:card" content="summary_large_image"' in page
    assert '<svg class="stamp"' in page and "<text" not in page  # glyph, no font render
    without = render_page(fixed_report(), anchors_url=ANCHORS).decode()
    assert "canonical" not in without and "@ckeenan" not in without


def test_buckets_render_prettified_but_data_stays_sortable():
    report = fixed_report()
    dist = next(m for m in report["metrics"] if m["name"] == "session_size_distribution")
    assert "0011-0100" in dist["value"]  # data layer: sortable
    page = render_page(report, anchors_url=ANCHORS).decode()
    assert "11-100" in page and "0011-0100" not in page  # display layer: human
