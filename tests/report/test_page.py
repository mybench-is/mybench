"""MYB-5.2: static report page — determinism, whitelist build, tiers, no JS, leaks."""

import copy
import hashlib
import json
import logging
from pathlib import Path

import pytest

from mybench.claims import build_claim, canonical_bytes, dev_signing_key, sign_claim
from mybench.registry import Registry, _packaged_registry_bytes
from mybench.report.page import PageError, _claim_html, _environment_notice, render_page
from mybench.scorer.score import score
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger
from tests.scorer.test_score import fixed_report_bytes

ANCHORS = "https://github.com/synthetic/mybench-anchors"
SYNTHETIC_CLAIM_KEY = dev_signing_key(bytes(reversed(range(32))))

AGENT_HOURS_VALUE = [
    {"dimensions": ["active_time_band"], "value": "40h-to-under-160h"},
    {"dimensions": ["active_time_coverage_band"], "value": "90-to-100-percent"},
    {
        "dimensions": ["active_time_definition"],
        "value": "sum-observed-gaps-no-greater-than-30m",
    },
    {"dimensions": ["backfill_annotation"], "value": "14-days-plus"},
    {"dimensions": ["close_normalizer_version"], "value": "1.0.0"},
    {
        "dimensions": ["observed_boundary_coverage_band"],
        "value": "90-to-100-percent",
    },
    {
        "dimensions": ["wall_clock_definition"],
        "value": "sum-observed-open-to-observed-or-scan-inferred-close",
    },
    {"dimensions": ["wall_clock_time_band"], "value": "40h-to-under-160h"},
]

TOPOLOGY_VALUE = [
    {"dimensions": ["file_structure_coverage_basis_points"], "value": 10000},
    {"dimensions": ["k_suppression_floor"], "value": 5},
    {"dimensions": ["kind"], "value": "orchestration-topology-aggregate"},
    {"dimensions": ["observed_week"], "value": "2026-W29"},
    {"dimensions": ["schema_version"], "value": "1"},
    {"dimensions": ["state_basis"], "value": "scan-time-state-not-evidence-period"},
    {
        "dimensions": ["transcript_delegation_coverage_basis_points"],
        "value": "UNKNOWN",
    },
]


def fixed_report():
    return json.loads(fixed_report_bytes())


def _output(value, *, trust_tier="ANCHORED", caveats=()):
    return {
        **{cell["dimensions"][0]: cell["value"] for cell in value},
        "trust_tier": trust_tier,
        "caveats": list(caveats),
    }


def signed_v2_claim(
    registry_id="transcript.agent_hours",
    *,
    registry=None,
    value=None,
    key=SYNTHETIC_CLAIM_KEY,
    kind="dev",
    anchor_refs=None,
):
    registry = registry or Registry.load()
    entry = registry.entry(registry_id)
    if value is None:
        value = AGENT_HOURS_VALUE
    caveats = entry["output_schema"]["properties"].get("caveats", {}).get("const", [])
    trust_tier = entry["output_schema"]["properties"].get("trust_tier", {}).get("const", "ANCHORED")
    claim = build_claim(
        claim_type="descriptor",
        registry_id=entry["id"],
        registry_version=entry["version"],
        scorer_name="synthetic.report-v2",
        scorer_version="1.0.0",
        corpus_commitment="c" * 64,
        window_start="2026-07-01T00:00:00Z",
        window_end="2026-07-18T00:00:00Z",
        output=_output(value, trust_tier=trust_tier, caveats=caveats),
        derivation_class=entry["class"],
        signed_at="2026-07-18T00:00:00Z",
        anchor_refs=anchor_refs,
    )
    return sign_claim(claim, key, kind=kind)


def _digest(claim):
    return hashlib.sha256(canonical_bytes(claim)).hexdigest()


def v2_claims(registry=None):
    return [signed_v2_claim(registry=registry)]


def v2_report(registry=None):
    registry = registry or Registry.load()
    claim = signed_v2_claim(registry=registry)
    entry = registry.entry(claim["registry_id"])
    field = {
        "registry_id": claim["registry_id"],
        "registry_version": claim["registry_version"],
        "claim_digest": _digest(claim),
        "derivation_class": claim["derivation_class"],
        "execution_env": claim["execution_env"],
        "trust_tier": claim["output"]["trust_tier"],
        "anchor_state": "covered",
        "disclosure": "PUBLISHABLE",
        "inference_risk": entry["inference_risk"],
        "coverage_basis_points": 9000,
        "confidence": "HIGH",
        "caveats": [
            "capture-dependent-and-inflatable",
            "observed-at-coverage-limits-backfill",
        ],
        "value": copy.deepcopy(AGENT_HOURS_VALUE),
    }
    empty = {"status": "not-supported", "fields": []}
    return {
        "schema_version": "2",
        "report_version": "v0.2.0",
        "generated_at": "2026-07-18T00:00:00Z",
        "scorer_version": "0.3.0",
        "input_schema_versions": {
            "ledger": ["2"],
            "anchor": ["2"],
            "normalized_events": ["1"],
            "phase_classifier": ["1.0.0"],
        },
        "registry": {"version": registry.version, "digest": registry.digest()},
        "evidence_period": {"start": "2026-07-01", "end": "2026-07-18"},
        "metrics": [{"name": "anchored_span_days", "value": 17, "trust_tier": "PROVEN"}],
        "catalog_metrics": [field],
        "fingerprint": {
            "workflow_summary": dict(empty),
            "workflow_map": dict(empty),
            "model_role_profile": dict(empty),
            "context_management_profile": dict(empty),
            "orchestration_topology": dict(empty),
            "token_cost_profile": dict(empty),
            "evidence_coverage": dict(empty),
        },
    }


def render_v2(report=None, *, registry=None, signed_claims=None, **kwargs):
    report = report or v2_report(registry)
    claims = v2_claims(registry) if signed_claims is None else signed_claims
    return render_page(
        report,
        anchors_url=ANCHORS,
        registry=registry,
        signed_claims=claims,
        **kwargs,
    )


def report_for_claim(claim, *, registry=None):
    report = v2_report(registry)
    field = report["catalog_metrics"][0]
    field.update(
        registry_id=claim["registry_id"],
        registry_version=claim["registry_version"],
        claim_digest=_digest(claim),
        derivation_class=claim["derivation_class"],
        execution_env=claim["execution_env"],
    )
    return report


def variant_registry(*, characterization=False, attested=False):
    doc = json.loads(_packaged_registry_bytes())
    entry = next(e for e in doc["entries"] if e["id"] == "transcript.agent_hours")
    if characterization:
        entry["class"] = "characterization"
    if attested:
        entry["output_schema"]["properties"]["trust_tier"] = {"const": "TEE-VERIFIED"}
    return Registry(doc)


def topology_field():
    claim = signed_v2_claim(
        "fingerprint.topology.file_structure",
        value=TOPOLOGY_VALUE,
    )
    return {
        "registry_id": claim["registry_id"],
        "registry_version": claim["registry_version"],
        "claim_digest": _digest(claim),
        "derivation_class": claim["derivation_class"],
        "execution_env": claim["execution_env"],
        "trust_tier": claim["output"]["trust_tier"],
        "anchor_state": "covered",
        "disclosure": "PUBLISHABLE",
        "inference_risk": "R1",
        "coverage_basis_points": 10000,
        "confidence": "HIGH",
        "caveats": ["scan-time-state-not-evidence-period"],
        "value": copy.deepcopy(TOPOLOGY_VALUE),
    }


def topology_claim():
    return signed_v2_claim(
        "fingerprint.topology.file_structure",
        value=TOPOLOGY_VALUE,
    )


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
    badge_count = page.count('class="badge tier--')
    legend_badges = 5  # five-rung ladder (handoff #5)
    assert badge_count == len(report["metrics"]) + legend_badges
    for rung in ("IMPORTED", "ANCHORED", "PROVEN", "TEE-VERIFIED", "JUDGED"):
        assert rung in page
    assert "uvx mybench-verify" in page and "python -m mybench.verify" in page
    assert ANCHORS in page
    assert "unreachable until" in page and "reserved until" in page


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


def test_v2_claim_fields_validate_then_render_from_the_registry():
    report = v2_report()
    page = render_v2(report).decode()
    assert "Workflow fingerprint" in page
    assert "Additional catalog metrics" in page
    assert "Lifecycle duration and agent-hours profile" in page
    assert "Lifecycle volume only; it does not measure utility" in page
    assert "computed locally — unattested" in page
    assert ">MEASURED<" in page
    assert 'class="badge tier--anchored">ANCHORED</span>' in page
    assert "Capture-derived duration bands depend on observed lifecycle markers" in page


def test_v2_missing_envelope_and_arbitrary_digest_fail_closed():
    report = v2_report()
    with pytest.raises(PageError, match="require signed claim envelopes"):
        render_page(report, anchors_url=ANCHORS)

    report["catalog_metrics"][0]["claim_digest"] = "0" * 64
    with pytest.raises(PageError, match="do not exactly match field digests"):
        render_v2(report)


def test_v2_schema_valid_output_and_metadata_substitutions_fail_exact_binding():
    report = v2_report()
    report["catalog_metrics"][0]["value"][0]["value"] = "160h-plus"
    with pytest.raises(PageError, match="output does not match signed claim"):
        render_v2(report)

    report = v2_report()
    report["catalog_metrics"][0]["registry_version"] = "1.0.1"
    with pytest.raises(PageError, match="version"):
        render_v2(report)


def test_v2_invalid_signature_and_wrong_device_trust_binding_fail_closed():
    claim = v2_claims()[0]
    tampered = copy.deepcopy(claim)
    tampered["signature"] = ("0" if claim["signature"][0] != "0" else "1") + claim["signature"][1:]
    with pytest.raises(PageError, match="signed claim verification failed"):
        render_v2(signed_claims=[tampered])

    device_claim = signed_v2_claim(
        key=dev_signing_key(bytes(range(32))),
        kind="device",
    )
    report = report_for_claim(device_claim)
    with pytest.raises(PageError, match="signed claim verification failed"):
        render_v2(
            report,
            signed_claims=[device_claim],
            trusted_device_pubs={"0" * 64},
        )
    page = render_v2(
        report,
        signed_claims=[device_claim],
        trusted_device_pubs={device_claim["signer"]["pub"]},
    )
    assert b"Workflow fingerprint" in page


def test_v2_device_claim_requires_explicit_trust_binding_even_with_a_valid_signature():
    device_claim = signed_v2_claim(
        key=dev_signing_key(bytes(range(32))),
        kind="device",
    )
    with pytest.raises(PageError, match="explicit trusted-device binding"):
        render_v2(report_for_claim(device_claim), signed_claims=[device_claim])


def test_v2_claim_renders_in_its_closed_fingerprint_section():
    report = v2_report()
    report["fingerprint"]["orchestration_topology"] = {
        "status": "available",
        "fields": [topology_field()],
    }
    page = render_v2(report, signed_claims=[*v2_claims(), topology_claim()]).decode()
    assert "Orchestration topology" in page
    assert "File-structure orchestration topology" in page
    assert "This structure snapshot describes scan-time state" in page


def test_v2_unknown_envelope_and_field_metadata_fail_the_build():
    report = v2_report()
    report["private_note"] = "synthetic forbidden widening"
    with pytest.raises(PageError, match="non-conforming"):
        render_v2(report)

    report = v2_report()
    report["catalog_metrics"][0]["display_copy"] = "synthetic forbidden widening"
    with pytest.raises(PageError, match="non-conforming"):
        render_v2(report)


def test_v2_registry_identity_location_caveats_and_reserved_blocks_fail_closed():
    report = v2_report()
    report["registry"]["digest"] = "0" * 64
    with pytest.raises(PageError, match="unpinned registry"):
        render_v2(report)

    report = v2_report()
    field = report["catalog_metrics"].pop()
    report["fingerprint"]["workflow_summary"] = {"status": "available", "fields": [field]}
    with pytest.raises(PageError, match="report location"):
        render_v2(report)

    report = v2_report()
    report["catalog_metrics"][0]["caveats"] = ["capture-dependent-and-inflatable"]
    with pytest.raises(PageError, match="caveats"):
        render_v2(report)

    report = v2_report()
    report["catalog_metrics"][0]["reference_frame"] = {
        "reference_corpus_id": "synthetic.cohort",
        "reference_version": "0.1.0",
        "as_of_date": "2026-07-18",
        "percentile_band": "p50-p74",
    }
    with pytest.raises(PageError, match="reference frames are not active"):
        render_v2(report)

    report = v2_report()
    report["catalog_metrics"][0]["tier_qualifier"] = "attested"
    with pytest.raises(PageError, match="non-conforming"):
        render_v2(report)


def test_characterization_pill_confidence_and_weak_geometry_are_visible():
    registry = variant_registry(characterization=True)
    report = v2_report(registry)
    field = report["catalog_metrics"][0]
    field["confidence"] = "MEDIUM"
    page = render_v2(report, registry=registry).decode()
    assert ">CHARACTERIZATION<" in page
    assert "confidence MEDIUM" in page
    assert 'class="badge tier--characterization">ANCHORED</span>' in page
    assert 'class="claim tier--characterization"' in page


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_local_and_attested_presentations_are_distinct_in_both_themes(theme):
    local_page = render_v2(theme=theme).decode()

    registry = variant_registry(attested=True)
    attested = v2_report(registry)
    field = attested["catalog_metrics"][0]
    field.update(execution_env="tee-attested", trust_tier="TEE-VERIFIED")
    attested_html = _claim_html(field, registry.entry(field["registry_id"]))
    attested_notice = _environment_notice(attested)

    assert f'data-theme="{theme}"' in local_page
    assert "computed locally — unattested" in local_page
    assert 'tier--anchored">ANCHORED' in local_page
    assert "computed in an attested execution environment" in attested_notice
    assert 'tier--tee-verified">TEE-VERIFIED' in attested_html
    assert "provider" not in local_page.split("Trust tiers", 1)[0].lower()


def test_attested_environment_cannot_retain_a_local_tier_label():
    report = v2_report()
    report["catalog_metrics"][0]["execution_env"] = "tee-attested"
    with pytest.raises(PageError, match="attested tier label"):
        render_v2(report)


def test_v2_coverage_keeps_basis_point_precision_without_rounding_up():
    report = v2_report()
    report["catalog_metrics"][0]["coverage_basis_points"] = 9950
    page = render_v2(report).decode()
    assert "coverage 99.5%" in page
    assert "coverage 100%" not in page


def test_v2_public_render_path_is_absent_until_the_preview_gate():
    with pytest.raises(PageError, match="public fingerprint rendering is unavailable"):
        render_v2(public=True)


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
    assert hrefs == {
        ANCHORS,
        "report.json",
        "https://mybench.is",
        "https://mybench.is/how-it-works",
        canonical,
    }
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


def test_v2_signed_claim_input_cannot_leak_local_metadata_or_logs(tmp_path, caplog):
    canary_text = [
        "MYBENCH-CANARY-transcript-content-10-19",
        "MYBENCH-CANARY-private-filename-10-19.py",
        "MYBENCH-CANARY-session-id-10-19",
        "MYBENCH-CANARY-event-id-10-19",
        "MYBENCH-CANARY-private-key-10-19",
        "MYBENCH-CANARY-nonce-10-19",
    ]
    canaries = [value.encode() for value in canary_text]
    claim = signed_v2_claim(anchor_refs=canary_text)
    report = report_for_claim(claim)
    caplog.set_level(logging.INFO)
    out = tmp_path / "index.html"
    out.write_bytes(render_v2(report, signed_claims=[claim]))
    log = tmp_path / "render.log"
    log.write_text(caplog.text)
    assert assert_no_canaries([out, log], canaries) == 2

    poisoned = copy.deepcopy(claim)
    poisoned["private_filename"] = canary_text[1]
    with pytest.raises(PageError) as rejected:
        render_v2(report, signed_claims=[poisoned])
    assert all(canary not in str(rejected.value).encode() for canary in canaries)

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

    # The arbitrary-output compatibility path is public-capable, so the
    # private v2 fingerprint surface must stay structurally unavailable here.
    v2_src = tmp_path / "report-v2.json"
    v2_src.write_text(json.dumps(v2_report()))
    v2_out = tmp_path / "fingerprint.html"
    assert main(["--report", str(v2_src), "--out", str(v2_out)]) == 1
    assert not v2_out.exists()


def test_component_cli_refuses_prebuilt_report_bundle_pairing_and_serve(tmp_path):
    from mybench.report.__main__ import main

    src = tmp_path / "report.json"
    src.write_bytes(fixed_report_bytes())
    with pytest.raises(SystemExit) as missing_out:
        main(["--report", str(src)])
    assert missing_out.value.code == 2
    with pytest.raises(SystemExit) as removed_serve:
        main(["--serve"])
    assert removed_serve.value.code == 2


# --- MYB-5.8: identity, backfill honesty, pretty buckets --------------------------------


def backfill_dominated_report():
    """anchored_span_days = 0 (no batches) → below the OQ #18 floor."""
    from mybench.scorer.score import score
    from tests.scorer.test_score import FIXED_ENROLLED, FIXED_ROWS

    return json.loads(
        score(
            FIXED_ROWS,
            [],
            generated_at="2026-07-09T00:00:00Z",
            enrolled=FIXED_ENROLLED,
            allow_synthetic=True,
        )
    )


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
    assert 'rel="canonical"' not in without and "@ckeenan" not in without


def test_buckets_render_prettified_but_data_stays_sortable():
    report = fixed_report()
    dist = next(m for m in report["metrics"] if m["name"] == "session_size_distribution")
    assert "0011-0100" in dist["value"]  # data layer: sortable
    page = render_page(report, anchors_url=ANCHORS).decode()
    assert "11-100" in page and "0011-0100" not in page  # display layer: human


def test_evidence_coverage_freshness_versions_and_boolean_render():
    page = render_page(fixed_report(), anchors_url=ANCHORS).decode()
    assert "anchored through 2026-02-02" in page
    assert "input schemas ledger 1/2, anchor 2" in page
    assert "anchor chain continuity" in page and "<strong>yes</strong>" in page
    for label in ("under 5m", "5m to 1h", "1h to 24h", "1d to 7d", "7d plus", "unknown"):
        assert label in page


def test_missing_anchor_renders_honest_freshness_state():
    page = render_page(backfill_dominated_report(), anchors_url=ANCHORS).decode()
    assert "not yet anchored" in page
    assert "input schemas ledger 1/2, anchor none" in page


# --- MYB-5.6: brand alignment guards --------------------------------------------------


def test_brand_tokens_and_no_reserved_hues():
    page = render_page(fixed_report(), anchors_url=ANCHORS).decode()
    # Verdigris tokens present; evidence face declared; paper document surface.
    for token in ("--ink:#171A19", "--paper:#F2EFE7", "--accent-display:#4FA095", "IBM Plex Mono"):
        assert token in page
    # Reserved registers/hues absent (BRAND §3.4/§5.3/§9): foil hues, and no
    # filled die (the stamp rect must remain stroke-only, fill="none" root).
    for forbidden in ("#1D9E75", "#7F77DD", "#EF9F27"):
        assert forbidden.lower() not in page.lower()
    assert 'fill="none"><rect' in page  # die body is outline register


def test_stamp_is_outlined_paths_not_font_render():
    page = render_page(fixed_report(), anchors_url=ANCHORS).decode()
    assert '<svg class="stamp"' in page
    assert "<text" not in page
    assert page.count("<path") >= 2  # the outlined m and b glyphs
