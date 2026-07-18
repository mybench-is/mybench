"""Wave-1 transcript scorer behavior, support, privacy, and firing tests."""

from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from mybench.claims import canonical_bytes, dev_signing_key, verify_claim
from mybench.normalizer.contract import corpus_commitment, validate_corpus_artifact
from mybench.registry import Registry
from mybench.scorer.wave1 import (
    Wave1ScorerError,
    build_harness_currency_snapshot,
    build_mcp_recurrence_snapshot,
    score_autonomy_band,
    score_mcp_breadth,
    score_orchestrators,
    score_tool_mix,
    score_verification_ratio,
    score_wave1_claims,
    score_wellformed,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries
from tests.fixtures.wave1 import WAVE1_CANARIES, wave1_synthetic_input

WINDOW = {
    "window_start": "2026-01-01T00:00:00Z",
    "window_end": "2026-01-01T01:00:00Z",
    "signed_at": "2026-07-18T00:00:00Z",
}
KEY = dev_signing_key(b"w" * 32)


def _claims(synthetic):
    return score_wave1_claims(
        synthetic.corpus,
        synthetic.currency_snapshot,
        synthetic.mcp_snapshot,
        private_key=KEY,
        signer_kind="dev",
        **WINDOW,
    )


def _rebind(corpus: dict) -> dict:
    corpus["manifest"]["event_count"] = len(corpus["events"])
    corpus["corpus_commitment"] = corpus_commitment(corpus["manifest"], corpus["events"])
    validate_corpus_artifact(canonical_bytes(corpus) + b"\n")
    return corpus


def test_all_six_scorers_emit_expected_registry_bands():
    synthetic = wave1_synthetic_input()
    assert score_wellformed(synthetic.corpus) == {
        "sessions_checked_band": "10-99",
        "wellformed_share_band": "75-100%",
        "timestamp_monotonic_share_band": "75-100%",
        "tool_pairing_intact_share_band": "75-100%",
        "splice_artifacts_found": False,
    }
    assert score_tool_mix(synthetic.corpus) == {
        "read_share_band": "10-39%",
        "write_share_band": "10-39%",
        "execute_share_band": "10-39%",
        "browse_share_band": "10-39%",
    }
    assert score_autonomy_band(synthetic.corpus) == {
        "median_run_band": "1-4",
        "interventions_per_1k_band": "50-199",
    }
    assert score_verification_ratio(synthetic.corpus) == {
        "sessions_with_test_events_band": "75-100%"
    }
    assert score_orchestrators(synthetic.corpus, synthetic.currency_snapshot) == {
        "harnesses": ["claude-code"],
        "version_currency_band": "within-one-minor",
    }
    assert score_mcp_breadth(synthetic.corpus, synthetic.mcp_snapshot) == {
        "category_breadth_band": "3-5"
    }


def test_claim_set_is_signed_registry_valid_and_bound_to_control_snapshots():
    synthetic = wave1_synthetic_input()
    claim_set = _claims(synthetic)
    claims = claim_set["claims"]
    assert [claim["registry_id"] for claim in claims] == [
        "transcript.autonomy_band",
        "transcript.mcp_breadth",
        "transcript.orchestrators",
        "transcript.tool_mix",
        "transcript.verification_ratio",
        "transcript.wellformed",
    ]
    registry = Registry.load()
    assert registry.entry("transcript.orchestrators")["inputs"] == [
        "normalized-session-events",
        "harness-version-currency-snapshot",
    ]
    assert registry.entry("transcript.mcp_breadth")["inputs"] == [
        "normalized-session-events",
        "mcp-category-recurrence-snapshot",
    ]
    for claim in claims:
        assert verify_claim(claim)["kind"] == "dev"
        registry.check_claim(claim)
        assert f"registry:sha256:{registry.digest()}" in claim["inputs"]["anchor_refs"]

    by_id = {claim["registry_id"]: claim for claim in claims}
    mcp = by_id["transcript.mcp_breadth"]
    assert mcp["inputs"]["corpus_commitment"] == sorted(
        [synthetic.corpus["corpus_commitment"], synthetic.mcp_snapshot["digest"]]
    )
    assert (
        f"mcp-recurrence:sha256:{synthetic.mcp_snapshot['digest']}" in mcp["inputs"]["anchor_refs"]
    )
    orchestrators = by_id["transcript.orchestrators"]
    assert (
        f"harness-currency:sha256:{synthetic.currency_snapshot['digest']}"
        in orchestrators["inputs"]["anchor_refs"]
    )


def test_below_support_means_no_claim_not_a_zero_claim():
    synthetic = wave1_synthetic_input(session_count=4)
    assert score_wellformed(synthetic.corpus) is None
    assert score_tool_mix(synthetic.corpus) is None
    assert score_autonomy_band(synthetic.corpus) is None
    assert score_verification_ratio(synthetic.corpus) is None
    assert score_orchestrators(synthetic.corpus, synthetic.currency_snapshot) is None
    assert score_mcp_breadth(synthetic.corpus, synthetic.mcp_snapshot) is None
    assert _claims(synthetic)["claims"] == []


def test_each_registry_support_floor_is_applied_independently():
    synthetic = wave1_synthetic_input(session_count=10)
    assert [claim["registry_id"] for claim in _claims(synthetic)["claims"]] == [
        "transcript.orchestrators",
        "transcript.wellformed",
    ]


def test_mcp_breadth_ignores_one_off_category_spam():
    synthetic = wave1_synthetic_input()
    counts = {
        row["category"]: row["sessions"]
        for row in synthetic.mcp_snapshot["category_session_counts"]
    }
    assert counts["other"] == 1
    assert score_mcp_breadth(synthetic.corpus, synthetic.mcp_snapshot) == {
        "category_breadth_band": "3-5"
    }


def test_mcp_snapshot_is_content_free_bound_and_fail_closed():
    synthetic = wave1_synthetic_input()
    encoded = canonical_bytes(synthetic.mcp_snapshot)
    assert b"session_id" not in encoded
    assert b"record_index" not in encoded
    assert b"tool" not in encoded
    assert all(canary not in encoded for canary in WAVE1_CANARIES)

    wrong_root = build_mcp_recurrence_snapshot("ab" * 32, {"vcs": 20})
    with pytest.raises(Wave1ScorerError, match="different normalized corpus"):
        score_mcp_breadth(synthetic.corpus, wrong_root)

    tampered = copy.deepcopy(synthetic.mcp_snapshot)
    tampered["category_session_counts"][0]["sessions"] -= 1
    with pytest.raises(Wave1ScorerError, match="digest"):
        score_mcp_breadth(synthetic.corpus, tampered)


@pytest.mark.parametrize(
    ("latest", "expected"),
    [
        ("5.1.0", "within-one-minor"),
        ("5.2.0", "within-one-major"),
        ("6.0.0", "within-one-major"),
        ("7.0.0", "older"),
    ],
)
def test_harness_currency_uses_only_the_explicit_snapshot(latest, expected):
    synthetic = wave1_synthetic_input()
    snapshot = build_harness_currency_snapshot({"claude-code": latest}, snapshot_version="2026.7.0")
    assert score_orchestrators(synthetic.corpus, snapshot)["version_currency_band"] == expected


def test_harness_snapshot_tamper_staleness_and_missing_coverage_fail_closed():
    synthetic = wave1_synthetic_input()
    tampered = copy.deepcopy(synthetic.currency_snapshot)
    tampered["versions"][0]["latest"] = "5.2.0"
    with pytest.raises(Wave1ScorerError, match="digest"):
        score_orchestrators(synthetic.corpus, tampered)

    stale = build_harness_currency_snapshot({"claude-code": "4.9.0"}, snapshot_version="2026.7.0")
    with pytest.raises(Wave1ScorerError, match="predates"):
        score_orchestrators(synthetic.corpus, stale)

    missing = build_harness_currency_snapshot({"codex": "5.1.0"}, snapshot_version="2026.7.0")
    with pytest.raises(Wave1ScorerError, match="every observed harness"):
        score_orchestrators(synthetic.corpus, missing)


def test_wellformed_pairing_timestamp_and_splice_checks_fire():
    synthetic = wave1_synthetic_input()
    corpus = copy.deepcopy(synthetic.corpus)
    affected = {f"synthetic-wave1-session-{index:02d}" for index in range(6)}

    # The last result in record 2 has the last subevent index, so removing it
    # preserves the normalized contract while making one call unpaired.
    remove_locations = set()
    for session_id in affected:
        results = [
            event
            for event in corpus["events"]
            if event["session_id"] == session_id
            and event["record_index"] == 2
            and event["event_kind"] == "tool-result"
        ]
        last = max(results, key=lambda event: event["subevent_index"])
        remove_locations.add((last["source"], last["session_id"], 2, last["subevent_index"]))
    corpus["events"] = [
        event
        for event in corpus["events"]
        if (
            event["source"],
            event["session_id"],
            event["record_index"],
            event["subevent_index"],
        )
        not in remove_locations
    ]
    for event in corpus["events"]:
        if event["session_id"] not in affected:
            continue
        if event["record_index"] == 1:
            event["observed_at"] = "2026-01-01T00:59:59.000000Z"
            event["parent_link"] = {"status": "missing"}
    _rebind(corpus)

    assert score_wellformed(corpus) == {
        "sessions_checked_band": "10-99",
        "wellformed_share_band": "50-74%",
        "timestamp_monotonic_share_band": "50-74%",
        "tool_pairing_intact_share_band": "50-74%",
        "splice_artifacts_found": True,
    }


def test_wellformed_harness_parse_anomaly_fires_conservatively():
    synthetic = wave1_synthetic_input()
    corpus = copy.deepcopy(synthetic.corpus)
    corpus["manifest"]["sessions"][0]["admitted_record_count"] += 1
    coverage = corpus["manifest"]["coverage"]
    coverage["records_seen"] += 1
    coverage["records_malformed"] += 1
    _rebind(corpus)
    output = score_wellformed(corpus)
    assert output["wellformed_share_band"] == "0-24%"
    assert output["timestamp_monotonic_share_band"] == "75-100%"
    assert output["tool_pairing_intact_share_band"] == "75-100%"


def test_claim_output_has_no_content_ids_or_ordered_event_surface(tmp_path):
    synthetic = wave1_synthetic_input()
    claim_set = _claims(synthetic)
    encoded = canonical_bytes(claim_set) + b"\n"
    safe = tmp_path / "wave1-claims.json"
    safe.write_bytes(encoded)
    assert assert_no_canaries([safe], list(WAVE1_CANARIES)) == 1
    for session in synthetic.corpus["manifest"]["sessions"]:
        assert session["session_id"].encode() not in encoded
    assert b"record_index" not in encoded
    assert b"subevent_index" not in encoded
    assert '"events":' not in encoded.decode()

    planted = tmp_path / "planted-wave1-claims.json"
    planted.write_bytes(encoded + WAVE1_CANARIES[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], list(WAVE1_CANARIES))


def test_registry_neutrality_copy_and_production_source_exclude_banned_framings():
    registry = Registry.load()
    surfaces = " ".join(
        f"{registry.entry(registry_id)['title']} {registry.entry(registry_id)['neutrality_note']}"
        for registry_id in (
            "transcript.wellformed",
            "transcript.tool_mix",
            "transcript.autonomy_band",
            "transcript.verification_ratio",
            "transcript.orchestrators",
            "transcript.mcp_breadth",
        )
    ).lower()
    scorer_source = (Path(__file__).parents[2] / "src/mybench/scorer/wave1.py").read_text().lower()
    for banned in (
        "iq",
        "intelligence",
        "reasoning ability",
        "correction rate",
        "developer score",
        "10x",
    ):
        pattern = rf"\b{re.escape(banned)}\b"
        assert re.search(pattern, surfaces) is None
        assert re.search(pattern, scorer_source) is None
    assert "delegating" in registry.entry("transcript.autonomy_band")["neutrality_note"]
    assert "not code quality" in registry.entry("transcript.verification_ratio")["neutrality_note"]
