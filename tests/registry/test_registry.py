"""MYB-10.2: descriptor registry — schema, cross-rules, disclosure derivation, claims bridge."""

import copy
import json

import pytest

from mybench.claims import build_claim, dev_signing_key, sign_claim
from mybench.registry import EMPLOYER_SAFE, Registry, RegistryError, _packaged_registry_bytes
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures


@pytest.fixture(scope="module")
def registry():
    return Registry.load()


def packaged_doc():
    return json.loads(_packaged_registry_bytes())


def mutated(mutate):
    doc = packaged_doc()
    mutate(doc)
    return doc


def entry_by_id(doc, eid):
    return next(e for e in doc["entries"] if e["id"] == eid)


# --- Loading, identity, determinism (AC #3 substrate) ----------------------------


def test_packaged_registry_loads_and_validates(registry):
    assert registry.version == "0.1.0"
    assert len(registry.ids()) == 41
    # OQ #31 is owner-gated: the file must say its format is provisional.
    assert packaged_doc()["format_status"] == "provisional-json-pending-OQ-31"


def test_digest_is_deterministic_and_formatting_independent(registry, tmp_path):
    reformatted = tmp_path / "registry-reformatted.json"
    reformatted.write_text(json.dumps(packaged_doc(), indent=None, sort_keys=True))
    assert Registry.load(reformatted).digest() == registry.digest()
    assert len(registry.digest()) == 64


def test_registry_schema_rejects_unknown_fields():
    with pytest.raises(RegistryError, match="schema violation"):
        Registry(mutated(lambda d: d.__setitem__("extra", 1)))
    with pytest.raises(RegistryError, match="schema violation"):
        Registry(mutated(lambda d: d["entries"][0].__setitem__("score", 10)))


# --- Cross-entry rules the schema cannot express -----------------------------------


def test_employer_safe_preset_is_r0_only():
    def promote_r1_into_employer_safe(doc):
        e = entry_by_id(doc, "repo.activity_heatmap")  # R1
        e["presets"] = [EMPLOYER_SAFE, "full"]

    with pytest.raises(RegistryError, match="employer-safe preset is R0-only"):
        Registry(mutated(promote_r1_into_employer_safe))


def test_non_r0_entries_require_risk_note():
    def drop_note(doc):
        entry_by_id(doc, "repo.stack_fingerprint").pop("risk_note")

    with pytest.raises(RegistryError, match="require a plain-language risk_note"):
        Registry(mutated(drop_note))


def test_internal_feature_only_may_not_join_presets():
    def sneak_into_preset(doc):
        entry_by_id(doc, "transcript.domain_vocabulary")["presets"] = ["full"]

    with pytest.raises(RegistryError, match="may not appear in any preset"):
        Registry(mutated(sneak_into_preset))


def test_duplicate_ids_rejected():
    def dupe(doc):
        doc["entries"].append(copy.deepcopy(doc["entries"][0]))

    with pytest.raises(RegistryError, match="duplicate registry id"):
        Registry(mutated(dupe))


def test_banned_framings_rejected_in_titles_and_ids():
    def trait_title(doc):
        doc["entries"][0]["title"] = "Developer IQ band"

    with pytest.raises(RegistryError, match="banned framing"):
        Registry(mutated(trait_title))


def test_active_entries_need_bands_support_and_concrete_schema():
    for strip in (
        lambda e: e.__setitem__("band_definitions", []),
        lambda e: e.__setitem__("min_support", {}),
        lambda e: e.__setitem__("output_schema", {"$comment": "reserved"}),
    ):
        doc = packaged_doc()
        strip(entry_by_id(doc, "transcript.tool_mix"))
        with pytest.raises(RegistryError, match="active entries need"):
            Registry(doc)


def test_output_schema_must_be_a_valid_schema():
    def corrupt(doc):
        entry_by_id(doc, "transcript.tool_mix")["output_schema"] = {"type": "wat"}

    with pytest.raises(RegistryError, match="not a valid schema"):
        Registry(mutated(corrupt))


# --- Scorer contract (AC #1): bands and min-support live here, not in code ---------


def test_scorers_read_bands_and_min_support_from_the_registry(registry):
    bands = registry.band_definitions("transcript.autonomy_band")
    assert any(b["field"] == "median_run_band" for b in bands)
    assert registry.min_support("transcript.autonomy_band") == {"sessions": 20}
    with pytest.raises(RegistryError, match="unknown registry id"):
        registry.entry("transcript.nonexistent")


# --- Disclosure surfaces (handoff §7.1; AC #2 negative) -----------------------------


def test_internal_feature_only_is_structurally_non_renderable(registry):
    assert "transcript.domain_vocabulary" not in registry.renderable_ids()
    for preset in (EMPLOYER_SAFE, "full"):
        manifest = registry.disclosure_manifest(preset)
        assert "transcript.domain_vocabulary" not in manifest["included"]
        reason = next(
            x["reason"] for x in manifest["excluded"] if x["id"] == "transcript.domain_vocabulary"
        )
        assert "internal-feature-only" in reason


def test_renderability_gate_fires_when_flag_flips():
    # Companion firing test: the SAME gate admits the entry once the flag
    # changes — proving the exclusion above is the flag, not a coincidence.
    def flip(doc):
        e = entry_by_id(doc, "transcript.domain_vocabulary")
        e["disclosure"] = "public"
        e["status"] = "active"
        e["band_definitions"] = [{"field": "overlap_band", "bands": ["low", "high"]}]
        e["min_support"] = {"sessions": 20}
        e["output_schema"] = {
            "type": "object",
            "additionalProperties": False,
            "required": ["overlap_band"],
            "properties": {"overlap_band": {"enum": ["low", "high"]}},
        }

    flipped = Registry(mutated(flip))
    assert "transcript.domain_vocabulary" in flipped.renderable_ids()


def test_employer_safe_manifest_is_r0_actives_only(registry):
    manifest = registry.disclosure_manifest(EMPLOYER_SAFE)
    assert manifest["included"], "employer-safe preset must not be empty"
    for eid in manifest["included"]:
        entry = registry.entry(eid)
        assert entry["inference_risk"] == "R0"
        assert entry["status"] == "active"
    # R1/R2 actives are excluded WITH their risk explanation (plain-language note).
    heatmap_reason = next(
        x["reason"] for x in manifest["excluded"] if x["id"] == "repo.activity_heatmap"
    )
    assert "R1" in heatmap_reason and "timezone" in heatmap_reason


def test_manifest_is_deterministic_and_carries_rejected_section(registry):
    a = registry.disclosure_manifest("full")
    b = registry.disclosure_manifest("full")
    assert a == b
    assert a["registry_digest"] == registry.digest()
    topics = " ".join(r["topic"] for r in a["rejected"])
    assert "lexical statistics" in topics  # AC #2: §7.2 initial entries present
    assert "cognitive-trait" in topics


def test_reserved_entries_are_excluded_with_reason(registry):
    manifest = registry.disclosure_manifest("full")
    reason = next(x["reason"] for x in manifest["excluded"] if x["id"] == "judge.spec_quality")
    assert "reserved" in reason


# --- Claims bridge ------------------------------------------------------------------


def tool_mix_claim(**overrides):
    kwargs = dict(
        claim_type="metric",
        registry_id="transcript.tool_mix",
        registry_version="0.1.0",
        scorer_name="mybench.tool_mix",
        scorer_version="0.1.0",
        corpus_commitment="ab" * 32,
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-31T00:00:00Z",
        output={
            "read_share_band": "40-69%",
            "write_share_band": "10-39%",
            "execute_share_band": "10-39%",
            "browse_share_band": "0-9%",
        },
        derivation_class="measured",
        signed_at="2026-02-01T00:00:00Z",
    )
    kwargs.update(overrides)
    return sign_claim(build_claim(**kwargs), dev_signing_key(bytes(range(32))), kind="dev")


def test_conforming_claim_passes_the_bridge(registry):
    registry.check_claim(tool_mix_claim())  # no raise


def test_bridge_rejects_version_class_reserved_and_shape_mismatches(registry):
    with pytest.raises(RegistryError, match="registry entry is 0.1.0"):
        registry.check_claim(tool_mix_claim(registry_version="0.9.9"))
    with pytest.raises(RegistryError, match="does not match registry class"):
        registry.check_claim(tool_mix_claim(derivation_class="characterization"))
    with pytest.raises(RegistryError, match="reserved"):
        registry.check_claim(
            tool_mix_claim(registry_id="judge.spec_quality", derivation_class="characterization")
        )
    with pytest.raises(RegistryError, match="does not conform"):
        registry.check_claim(tool_mix_claim(output={"read_share_band": "most of the time"}))


# --- Leak surface -------------------------------------------------------------------


def test_registry_and_manifest_pass_leak_scan_and_scanner_fires(registry, tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    registry_file = tmp_path / "registry.json"
    registry_file.write_bytes(_packaged_registry_bytes())
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(registry.disclosure_manifest("full")))
    assert assert_no_canaries([registry_file, manifest_file], fx.all_canaries()) == 2

    planted = tmp_path / "planted.json"
    planted.write_bytes(_packaged_registry_bytes() + fx.content_canaries[0].encode())
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], fx.all_canaries())
