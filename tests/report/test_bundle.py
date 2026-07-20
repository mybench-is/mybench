"""MYB-13.9 local bundle: immutability, signing, manifest, viewing, leak scan."""

from __future__ import annotations

import hashlib
import json
import logging
import random
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mybench import paths
from mybench.claims import build_claim, canonical_bytes, dev_signing_key, sign_claim
from mybench.registry import Registry, RegistryError
from mybench.report.cli import (
    BUNDLE_FILES,
    BundleError,
    ReportInputSnapshot,
    assemble_bundle,
    canonical_report_bytes,
    capture_report_inputs,
    content_address,
    derive_report_artifacts,
    evidence_manifest,
    open_report,
    validate_evidence_manifest,
    verify_signature,
)
from mybench.report.page import PageError, render_page
from mybench.scorer.score import score
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger
from tests.report.test_page import report_for_claim, signed_v2_claim, v2_claims, v2_report
from tests.scorer.test_score import fixed_report_bytes
from tests.scorer.test_token_cost import _score as token_cost_score

SYNTHETIC_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TOKEN_COST_CLAIM_KEY = dev_signing_key(b"t" * 32)


def _report() -> dict:
    return json.loads(fixed_report_bytes())


def _manifest(report: dict, rows=()) -> dict:
    dates = [report["anchored_through"]] if "anchored_through" in report else []
    return evidence_manifest(report, list(rows), dates)


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _reordered(value, rng: random.Random):
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {key: _reordered(item, rng) for key, item in items}
    if isinstance(value, list):
        return [_reordered(item, rng) for item in value]
    return value


def _token_cost_report_claims() -> tuple[dict, list[dict]]:
    registry = Registry.load()
    result = token_cost_score()
    outputs = {
        **result["publishable"],
        **result["local"]["cost_claims"],
    }
    claims = []
    fields = []
    disclosure = {"public": "PUBLISHABLE", "local-report-only": "LOCAL_ONLY"}
    for registry_id, output in sorted(outputs.items()):
        entry = registry.entry(registry_id)
        claim = sign_claim(
            build_claim(
                claim_type="descriptor",
                registry_id=registry_id,
                registry_version=entry["version"],
                scorer_name="synthetic.token-cost-report",
                scorer_version="1.0.0",
                corpus_commitment="f" * 64,
                window_start="2026-07-01T00:00:00Z",
                window_end="2026-07-19T00:00:00Z",
                output=output,
                derivation_class=entry["class"],
                signed_at="2026-07-19T00:00:00Z",
            ),
            TOKEN_COST_CLAIM_KEY,
            kind="dev",
        )
        claims.append(claim)
        fields.append(
            {
                "registry_id": registry_id,
                "registry_version": entry["version"],
                "claim_digest": hashlib.sha256(canonical_bytes(claim)).hexdigest(),
                "derivation_class": entry["class"],
                "execution_env": claim["execution_env"],
                "trust_tier": output["trust_tier"],
                "anchor_state": "covered",
                "disclosure": disclosure[entry["disclosure"]],
                "inference_risk": entry["inference_risk"],
                "coverage_basis_points": 10000,
                "confidence": "HIGH",
                "caveats": output["caveats"],
                "value": registry.report_value(registry_id, output),
            }
        )

    report = v2_report(registry)
    report["catalog_metrics"] = []
    report["pricing_snapshot"] = result["pricing_snapshot"]
    report["fingerprint"]["token_cost_profile"] = {
        "status": "available",
        "fields": fields,
    }
    return report, claims


def test_report_id_is_a_stable_property_of_canonical_report_json():
    report = _report()
    expected_bytes = canonical_report_bytes(report)
    expected_id = content_address(expected_bytes)
    for seed in range(32):
        reordered = _reordered(report, random.Random(seed))
        assert canonical_report_bytes(reordered) == expected_bytes
        assert content_address(canonical_report_bytes(reordered)) == expected_id
    changed = dict(report, report_version="different")
    assert content_address(canonical_report_bytes(changed)) != expected_id


def test_private_bundle_accepts_registry_validated_report_v2():
    report = v2_report()
    directory = assemble_bundle(
        report,
        evidence_manifest(report, [], []),
        private_key=SYNTHETIC_KEY,
        signed_claims=v2_claims(),
    )
    assert (directory / "report.json").read_bytes() == canonical_report_bytes(report)
    page = (directory / "index.html").read_text()
    assert "Workflow fingerprint" in page
    assert "computed locally — unattested" in page


def test_every_token_cost_claim_assembles_through_signed_v2_bundle_and_manifest():
    report, claims = _token_cost_report_claims()
    manifest = evidence_manifest(report, [], [])
    directory = assemble_bundle(
        report,
        manifest,
        private_key=SYNTHETIC_KEY,
        signed_claims=claims,
    )
    assert len(claims) == len(report["fingerprint"]["token_cost_profile"]["fields"]) == 7
    assert any(
        cell.get("container") == "array"
        for field in report["fingerprint"]["token_cost_profile"]["fields"]
        for cell in field["value"]
    )
    assert (directory / "report.json").read_bytes() == canonical_report_bytes(report)
    assert (
        manifest["versions"]["pricing"]
        == report["pricing_snapshot"]
        == {
            "version": "1.0.0",
            "digest": "7a54a695e2f0ca6a0c959dfa7c5a51f9c0546c4422c785233269a4eb52939f50",
            "currency": "USD",
        }
    )


@pytest.mark.parametrize("reserved_root", ("trust_tier", "caveats"))
@pytest.mark.parametrize("descendant", (False, True), ids=("root", "root-descendant"))
def test_wrapper_owned_value_paths_fail_before_claim_render_or_bundle_write(
    reserved_root, descendant, monkeypatch
):
    report, claims = _token_cost_report_claims()
    fields = report["fingerprint"]["token_cost_profile"]["fields"]
    assert len(fields) == len(claims) == 7
    field = fields[0]
    marker = (
        f"MYBENCH-CANARY-wrapper-owned-{reserved_root}-"
        f"{'descendant' if descendant else 'root'}-13-6"
    )
    planted = (
        [
            {"dimensions": [reserved_root], "container": "object"},
            {"dimensions": [reserved_root, "synthetic_marker"], "value": marker},
        ]
        if descendant
        else [{"dimensions": [reserved_root], "value": marker}]
    )
    field["value"].extend(planted)
    field["value"].sort(key=lambda cell: cell["dimensions"])

    # The envelope remains schema-valid and sorted: the semantic registry gate
    # owns this rejection before wrapper reconstruction or signed comparison.
    assert marker.encode() in canonical_report_bytes(report)
    claim = next(
        claim
        for claim in claims
        if hashlib.sha256(canonical_bytes(claim)).hexdigest() == field["claim_digest"]
    )
    with pytest.raises(RegistryError, match="wrapper-owned") as registry_failure:
        Registry.load().check_report_claim(
            field,
            "fingerprint.token_cost_profile",
            claim,
        )
    assert marker not in str(registry_failure.value)

    render_attempts = []

    def forbidden_render(*_args, **_kwargs):
        render_attempts.append(True)
        raise AssertionError("reserved wrapper path reached HTML rendering")

    monkeypatch.setattr("mybench.report.page._claim_html", forbidden_render)
    with pytest.raises(PageError, match="wrapper-owned") as page_failure:
        render_page(report, signed_claims=claims)
    assert marker not in str(page_failure.value)
    assert render_attempts == []

    def forbidden_write(*_args, **_kwargs):
        raise AssertionError("reserved wrapper path reached bundle storage")

    monkeypatch.setattr("mybench.report.cli._write_private", forbidden_write)
    manifest = evidence_manifest(report, [], [])
    assert not paths.reports_dir().exists()
    with pytest.raises(BundleError, match="wrapper-owned") as bundle_failure:
        assemble_bundle(
            report,
            manifest,
            private_key=SYNTHETIC_KEY,
            signed_claims=claims,
        )
    assert marker not in str(bundle_failure.value)
    assert not paths.reports_dir().exists()


def test_cost_field_requires_pricing_binding():
    report, _claims = _token_cost_report_claims()
    report.pop("pricing_snapshot")
    with pytest.raises(BundleError, match="require a pricing snapshot"):
        canonical_report_bytes(report)
    with pytest.raises(BundleError, match="require a pricing snapshot"):
        evidence_manifest(report, [], [])


@pytest.mark.parametrize(
    ("field", "wrong"),
    (("version", "1.0.1"), ("digest", "0" * 64)),
)
def test_well_formed_report_pricing_mismatch_with_signed_cost_claims_fails(field, wrong):
    report, claims = _token_cost_report_claims()
    report["pricing_snapshot"][field] = wrong
    manifest = evidence_manifest(report, [], [])
    with pytest.raises(BundleError, match="pricing snapshot does not match signed cost claims"):
        assemble_bundle(
            report,
            manifest,
            private_key=SYNTHETIC_KEY,
            signed_claims=claims,
        )


@pytest.mark.parametrize(
    ("field", "wrong"),
    (("version", "1.0.1"), ("digest", "0" * 64)),
)
def test_well_formed_manifest_pricing_mismatch_with_report_fails(field, wrong):
    report, claims = _token_cost_report_claims()
    manifest = evidence_manifest(report, [], [])
    manifest["versions"]["pricing"][field] = wrong
    with pytest.raises(BundleError, match="manifest pricing snapshot does not match report"):
        assemble_bundle(
            report,
            manifest,
            private_key=SYNTHETIC_KEY,
            signed_claims=claims,
        )


def test_manifest_pricing_currency_is_closed_and_bound():
    report, _claims = _token_cost_report_claims()
    manifest = evidence_manifest(report, [], [])
    manifest["versions"]["pricing"]["currency"] = "EUR"
    with pytest.raises(BundleError, match="schema validation"):
        validate_evidence_manifest(manifest)


def test_private_bundle_rejects_missing_or_invalid_v2_claim_before_writing():
    report = v2_report()
    manifest = evidence_manifest(report, [], [])
    with pytest.raises(BundleError, match="require signed claim envelopes"):
        assemble_bundle(report, manifest, private_key=SYNTHETIC_KEY)

    claim = v2_claims()[0]
    claim["signature"] = ("0" if claim["signature"][0] != "0" else "1") + claim["signature"][1:]
    with pytest.raises(BundleError, match="signed claim verification failed"):
        assemble_bundle(
            report,
            manifest,
            private_key=SYNTHETIC_KEY,
            signed_claims=[claim],
        )


def test_v2_bundle_claim_input_metadata_is_absent_from_artifacts_and_logs(tmp_path, caplog):
    canary_text = [
        "MYBENCH-CANARY-report-content-10-19",
        "MYBENCH-CANARY-report-filename-10-19.py",
        "MYBENCH-CANARY-report-session-10-19",
        "MYBENCH-CANARY-report-event-10-19",
        "MYBENCH-CANARY-report-key-10-19",
        "MYBENCH-CANARY-report-nonce-10-19",
    ]
    canaries = [value.encode() for value in canary_text]
    claim = signed_v2_claim(anchor_refs=canary_text)
    report = report_for_claim(claim)
    caplog.set_level(logging.INFO)
    directory = assemble_bundle(
        report,
        evidence_manifest(report, [], []),
        private_key=SYNTHETIC_KEY,
        signed_claims=[claim],
    )
    log = tmp_path / "claim-bundle.log"
    log.write_text(caplog.text)
    assert assert_no_canaries([directory, log], canaries) == len(BUNDLE_FILES) + 1

    planted = directory / "assets" / "claim-canary.txt"
    planted.write_bytes(canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([directory], canaries)


def test_bundle_layout_modes_idempotence_and_outside_path_refusal(tmp_path):
    report = _report()
    manifest = _manifest(report)
    directory = assemble_bundle(report, manifest, private_key=SYNTHETIC_KEY)
    assert directory.name == content_address((directory / "report.json").read_bytes())
    assert {entry.name for entry in directory.iterdir()} == {*BUNDLE_FILES, "assets"}
    assert _mode(directory) == _mode(directory / "assets") == 0o700
    assert all(_mode(directory / name) == 0o600 for name in BUNDLE_FILES)
    first = {name: (directory / name).read_bytes() for name in BUNDLE_FILES}
    assert assemble_bundle(report, manifest, private_key=SYNTHETIC_KEY) == directory
    assert {name: (directory / name).read_bytes() for name in BUNDLE_FILES} == first

    with pytest.raises(BundleError, match="outside the private data directory"):
        assemble_bundle(
            report,
            manifest,
            private_key=SYNTHETIC_KEY,
            bundle_dir=tmp_path / "outside" / directory.name,
        )
    assert not (tmp_path / "outside").exists()


def test_signature_covers_exact_canonical_report_bytes_and_tampering_fails():
    directory = assemble_bundle(_report(), _manifest(_report()), private_key=SYNTHETIC_KEY)
    report_bytes = (directory / "report.json").read_bytes()
    encoded_signature = (directory / "report.sig").read_bytes()
    verify_signature(report_bytes, encoded_signature, SYNTHETIC_KEY.public_key())
    with pytest.raises(BundleError, match="does not verify"):
        verify_signature(report_bytes + b" ", encoded_signature, SYNTHETIC_KEY.public_key())


@pytest.mark.parametrize(
    ("location", "field"),
    (
        ((), "nonce"),
        (("ledger",), "preimage"),
        (("ledger", "row_ranges", 0), "filename"),
        (("versions", "schemas"), "path"),
        (("versions", "formulas", 0), "prompt"),
    ),
)
def test_evidence_manifest_closed_schema_rejects_secret_or_filename_fields(location, field):
    manifest = _manifest(_report())
    if location == ("ledger", "row_ranges", 0):
        manifest["ledger"]["row_ranges"] = [{"start": 0, "end": 1}]
    if location == ("versions", "formulas", 0):
        manifest["versions"]["formulas"] = [
            {"registry_id": "synthetic.metric", "registry_version": "1.0.0"}
        ]
    cursor = manifest
    for part in location:
        cursor = cursor[part]
    cursor[field] = "MYBENCH-CANARY-forbidden"
    with pytest.raises(BundleError, match="schema validation"):
        validate_evidence_manifest(manifest)


def test_manifest_references_are_content_free_sorted_and_strict():
    rows = [
        {"i": 0, "h": "b" * 64, "session_root": "d" * 64},
        {"i": 1, "h": "a" * 64, "session_root": "c" * 64},
    ]
    manifest = evidence_manifest(_report(), rows, ["2026-02-02", "2026-01-01"])
    assert manifest["ledger"] == {
        "row_ranges": [{"start": 0, "end": 2}],
        "chain_tip": "a" * 64,
    }
    assert manifest["anchors"]["event_dates"] == ["2026-01-01", "2026-02-02"]
    assert manifest["corpora"]["commitments"] == ["c" * 64, "d" * 64]
    assert manifest["versions"]["schemas"]["evidence_manifest"] == "1"


def test_open_uses_a_file_url_and_is_headless_safe(monkeypatch):
    directory = assemble_bundle(_report(), _manifest(_report()), private_key=SYNTHETIC_KEY)
    opened = []

    def record_url(url, **_kwargs):
        opened.append(url)
        return True

    monkeypatch.setattr("webbrowser.open", record_url)
    assert open_report(directory / "index.html") is True
    assert opened[0].startswith("file://")

    def no_browser(*_args, **_kwargs):
        raise RuntimeError("synthetic headless environment")

    monkeypatch.setattr("webbrowser.open", no_browser)
    assert open_report(directory / "index.html") is False


def test_open_rejects_report_id_symlink_to_outside(tmp_path, monkeypatch):
    outside = tmp_path / "outside" / ("e" * 64)
    outside.mkdir(parents=True)
    (outside / "index.html").write_text("synthetic outside page")
    symlinked_bundle = paths.ensure_reports_dir() / ("e" * 64)
    symlinked_bundle.symlink_to(outside, target_is_directory=True)
    opened = []
    monkeypatch.setattr("webbrowser.open", lambda url, **_kwargs: opened.append(url) or True)

    assert open_report(symlinked_bundle / "index.html") is False
    assert opened == []


def test_scored_report_and_manifest_share_one_immutable_input_snapshot(tmp_path, monkeypatch):
    from mybench.ledger import GENESIS_PREV, row_hash

    fx = generate_fixtures(tmp_path / "snapshot-fixtures")
    ledger, _canaries = build_canary_ledger(fx)
    source_rows = ledger.rows()
    for index, row in enumerate(source_rows):
        row.pop("h")
        row["prev"] = GENESIS_PREV if index == 0 else source_rows[index - 1]["h"]
        if row.get("source") == "synthetic":
            row["source"] = "codex"
        row["h"] = row_hash(row)
    expected_tip = source_rows[-1]["h"]
    row_reads = 0

    def rows_once(_ledger):
        nonlocal row_reads
        row_reads += 1
        if row_reads > 1:
            raise AssertionError("report assembly reread mutable ledger state")
        return source_rows

    monkeypatch.setattr("mybench.ledger.Ledger.rows", rows_once)
    monkeypatch.setattr("mybench.scorer.__main__._anchor_events", lambda: [])
    snapshot = capture_report_inputs()
    assert isinstance(snapshot, ReportInputSnapshot)
    source_rows[-1]["h"] = "0" * 64

    report, manifest = derive_report_artifacts(
        snapshot,
        generated_at="2026-07-09T00:00:00Z",
    )
    assert row_reads == 1
    assert report["schema_version"] == "1"
    assert manifest["ledger"]["chain_tip"] == expected_tip


def test_entire_canary_bundle_and_logs_are_leak_free_and_firing_test_detects(tmp_path, caplog):
    fx = generate_fixtures(tmp_path / "synthetic-fixtures")
    ledger, canaries = build_canary_ledger(fx)
    rows = ledger.rows()
    report = json.loads(score(rows, [], generated_at="2026-07-09T00:00:00Z", allow_synthetic=True))
    caplog.set_level(logging.INFO)
    directory = assemble_bundle(
        report,
        evidence_manifest(report, rows, []),
        private_key=SYNTHETIC_KEY,
    )
    log = tmp_path / "bundle.log"
    log.write_text(caplog.text)
    assert assert_no_canaries([directory, log], canaries) == len(BUNDLE_FILES) + 1

    planted = directory / "assets" / "planted.txt"
    planted.write_bytes(canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([directory], canaries)
