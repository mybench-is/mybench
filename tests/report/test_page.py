"""MYB-5.2: static report page — determinism, whitelist build, tiers, no JS, leaks."""

import json

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
    legend_badges = 3  # PROVEN/ANCHORED/JUDGED legend rows
    assert badge_count == len(report["metrics"]) + legend_badges
    assert "python -m mybench.verify" in page
    assert ANCHORS in page
    assert "out of scope in v0" in page  # JUDGED marked, not offered


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


# --- Fully static (AC #5) ---------------------------------------------------------------


def test_page_has_no_javascript_and_one_external_reference():
    page = render_page(fixed_report(), anchors_url=ANCHORS).decode()
    assert "<script" not in page and "javascript:" not in page
    assert page.count("href=") == 1  # the anchors link, nothing else
    assert "src=" not in page  # no images/iframes/external fetches


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
