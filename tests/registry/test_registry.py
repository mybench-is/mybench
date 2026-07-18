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


def add_tool_mix_conditioning(doc):
    """Give one existing synthetic-test entry the MYB-19.4 contract."""
    entry = entry_by_id(doc, "transcript.tool_mix")
    entry["conditioning_axis"] = {
        "taxonomy_id": "arrival-pattern",
        "taxonomy_version": "0.1.0",
    }
    entry["min_support"]["per_conditioning_cell"] = {
        "cold-start": {"sessions": 5},
        "prepared-spec": {"sessions": 5},
    }
    entry["output_schema"]["required"].append("condition")
    entry["output_schema"]["properties"]["condition"] = {
        "type": "string",
        "enum": ["cold-start", "prepared-spec"],
    }


# --- Loading, identity, determinism (AC #3 substrate) ----------------------------


def test_packaged_registry_loads_and_validates(registry):
    assert registry.version == "0.1.1"
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


def test_conditioning_declarations_and_per_cell_support_are_registry_inputs():
    doc = packaged_doc()
    add_tool_mix_conditioning(doc)
    entry = entry_by_id(doc, "transcript.tool_mix")
    entry["conditional_denominator"] = {
        "condition_class": "catchable-error",
        "denominator_source": "judge.enumerated-errors",
    }
    entry["severity_weight_vocabulary"] = {
        "taxonomy_id": "error-severity",
        "taxonomy_version": "0.1.0",
        "classes": ["low", "medium", "high"],
    }

    conditioned = Registry(doc)
    assert conditioned.conditioning_axis("transcript.tool_mix") == {
        "taxonomy_id": "arrival-pattern",
        "taxonomy_version": "0.1.0",
    }
    assert conditioned.conditioning_min_support("transcript.tool_mix", "cold-start") == {
        "sessions": 5
    }
    assert conditioned.conditional_denominator("transcript.tool_mix") == {
        "condition_class": "catchable-error",
        "denominator_source": "judge.enumerated-errors",
    }
    assert conditioned.severity_weight_vocabulary("transcript.tool_mix")["classes"] == [
        "low",
        "medium",
        "high",
    ]


def test_conditioning_support_is_defensive_and_unknown_cells_fail_closed():
    conditioned = Registry(mutated(add_tool_mix_conditioning))
    support = conditioned.min_support("transcript.tool_mix")
    support["per_conditioning_cell"]["cold-start"]["sessions"] = 0
    assert conditioned.conditioning_min_support("transcript.tool_mix", "cold-start") == {
        "sessions": 5
    }
    with pytest.raises(RegistryError, match="unknown or unsupported condition"):
        conditioned.conditioning_min_support("transcript.tool_mix", "iterative-emergence")
    with pytest.raises(RegistryError, match="has no conditioning axis"):
        Registry.load().conditioning_min_support("transcript.tool_mix", "cold-start")


def test_active_conditioned_entry_requires_condition_shape_and_cell_support():
    def omit_condition_output(doc):
        entry = entry_by_id(doc, "transcript.tool_mix")
        entry["conditioning_axis"] = {
            "taxonomy_id": "arrival-pattern",
            "taxonomy_version": "0.1.0",
        }
        entry["min_support"]["per_conditioning_cell"] = {
            "cold-start": {"sessions": 5}
        }

    with pytest.raises(RegistryError, match="require an enumerated string output.condition"):
        Registry(mutated(omit_condition_output))

    def omit_cell_support(doc):
        add_tool_mix_conditioning(doc)
        entry_by_id(doc, "transcript.tool_mix")["min_support"].pop(
            "per_conditioning_cell"
        )

    with pytest.raises(RegistryError, match="require min_support.per_conditioning_cell"):
        Registry(mutated(omit_cell_support))

    def support_without_axis(doc):
        entry_by_id(doc, "transcript.tool_mix")["min_support"][
            "per_conditioning_cell"
        ] = {"cold-start": {"sessions": 5}}

    with pytest.raises(RegistryError, match="support requires conditioning_axis"):
        Registry(mutated(support_without_axis))

    def mismatched_cell_keys(doc):
        add_tool_mix_conditioning(doc)
        entry_by_id(doc, "transcript.tool_mix")["min_support"][
            "per_conditioning_cell"
        ].pop("prepared-spec")

    with pytest.raises(RegistryError, match="condition enum and per-cell support keys must match"):
        Registry(mutated(mismatched_cell_keys))


def test_conditioning_support_thresholds_are_positive():
    def zero_support(doc):
        add_tool_mix_conditioning(doc)
        entry_by_id(doc, "transcript.tool_mix")["min_support"][
            "per_conditioning_cell"
        ]["cold-start"]["sessions"] = 0

    with pytest.raises(RegistryError, match="schema violation"):
        Registry(mutated(zero_support))


def test_registry_severity_vocabulary_cannot_embed_judge_weights():
    def add_weights(doc):
        entry_by_id(doc, "transcript.tool_mix")["severity_weight_vocabulary"] = {
            "taxonomy_id": "error-severity",
            "taxonomy_version": "0.1.0",
            "classes": ["low", "high"],
            "weights": {"low": 1, "high": 3},
        }

    with pytest.raises(RegistryError, match="schema violation"):
        Registry(mutated(add_weights))


def test_conditioning_declaration_identifiers_and_versions_are_exact():
    def newline_taxonomy_version(doc):
        add_tool_mix_conditioning(doc)
        entry_by_id(doc, "transcript.tool_mix")["conditioning_axis"][
            "taxonomy_version"
        ] = "0.1.0\n"

    with pytest.raises(RegistryError, match="taxonomy_version is not exact semver"):
        Registry(mutated(newline_taxonomy_version))

    def newline_denominator_source(doc):
        entry_by_id(doc, "transcript.tool_mix")["conditional_denominator"] = {
            "condition_class": "catchable-error",
            "denominator_source": "judge.enumerated-errors\n",
        }

    with pytest.raises(RegistryError, match="denominator_source is not exact"):
        Registry(mutated(newline_denominator_source))


# --- Disclosure surfaces (handoff §7.1; AC #2 negative) -----------------------------


def test_internal_feature_only_is_structurally_non_renderable(registry):
    # Handoff §7.1: never on ANY disclosure surface — not even named in the
    # excluded list; only an aggregate count admits such entries exist.
    assert "transcript.domain_vocabulary" not in registry.renderable_ids()
    for preset in (EMPLOYER_SAFE, "full"):
        manifest = registry.disclosure_manifest(preset)
        named = set(manifest["included"]) | {x["id"] for x in manifest["excluded"]}
        assert "transcript.domain_vocabulary" not in named
        assert manifest["internal_feature_only_count"] == 1


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
    # Two INDEPENDENT parse->validate->derive runs, not two calls on one object.
    a = Registry(packaged_doc()).disclosure_manifest("full")
    b = Registry(packaged_doc()).disclosure_manifest("full")
    assert a == b
    assert a["registry_digest"] == registry.digest()
    topics = " ".join(r["topic"] for r in a["rejected"])
    assert "lexical statistics" in topics  # AC #2: §7.2 initial entries present
    assert "cognitive-trait" in topics
    assert "utility, quality, or effectiveness" in topics


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


def test_conditioned_claim_requires_known_condition():
    conditioned = Registry(mutated(add_tool_mix_conditioning))
    with pytest.raises(RegistryError, match="conditioned claim omits output.condition"):
        conditioned.check_claim(tool_mix_claim())
    with pytest.raises(RegistryError, match="unknown or unsupported condition"):
        conditioned.check_claim(
            tool_mix_claim(
                output={
                    "read_share_band": "40-69%",
                    "write_share_band": "10-39%",
                    "execute_share_band": "10-39%",
                    "browse_share_band": "0-9%",
                    "condition": "iterative-emergence",
                }
            )
        )
    conditioned.check_claim(
        tool_mix_claim(
            output={
                "read_share_band": "40-69%",
                "write_share_band": "10-39%",
                "execute_share_band": "10-39%",
                "browse_share_band": "0-9%",
                "condition": "cold-start",
            }
        )
    )


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


# --- Review regressions (2026-07-13 pre-PR review) -----------------------------------


def test_ref_bearing_output_schema_rejected_at_load():
    # $ref resolution is a score-time dependency (and a network call on old
    # jsonschema) — banned outright so check_claim can never encounter one.
    def add_ref(doc):
        entry_by_id(doc, "transcript.tool_mix")["output_schema"] = {
            "$ref": "https://mybench-evil.invalid/schema.json",
            "properties": {},
        }

    with pytest.raises(RegistryError, match="may not use"):
        Registry(mutated(add_ref))


def test_banned_framings_match_word_boundaries_not_substrings():
    # 'unique' must NOT trip the 'IQ' ban...
    def unique_title(doc):
        entry_by_id(doc, "transcript.tool_mix")["title"] = "Unique tool technique mix"

    Registry(mutated(unique_title))  # loads fine
    # ...while dotted initialisms and hyphenated variants MUST trip it.
    for bad in ("Cognitive I.Q. proxy band", "Reasoning-ability band"):
        def trait_title(doc, bad=bad):
            entry_by_id(doc, "transcript.tool_mix")["title"] = bad

        with pytest.raises(RegistryError, match="banned framing"):
            Registry(mutated(trait_title))


def test_banned_framings_checked_in_notes_and_risk_notes():
    def sneak_into_note(doc):
        entry_by_id(doc, "repo.stack_fingerprint")["risk_note"] = "basically a developer score"

    with pytest.raises(RegistryError, match="banned framing"):
        Registry(mutated(sneak_into_note))


def test_trailing_newline_ids_and_versions_rejected():
    # jsonschema patterns run under re.search; the loader fullmatch closes it.
    def newline_id(doc):
        e = copy.deepcopy(entry_by_id(doc, "transcript.tool_mix"))
        e["id"] = "transcript.tool_mix\n"  # near-duplicate of an existing id
        doc["entries"].append(e)

    with pytest.raises(RegistryError, match="not exactly"):
        Registry(mutated(newline_id))
    with pytest.raises(RegistryError, match="not exactly"):
        Registry(mutated(lambda d: d.__setitem__("registry_version", "0.1.0\n")))


def test_registry_is_immune_to_caller_and_result_mutation(registry):
    digest = registry.digest()
    stolen = registry.entry("transcript.tool_mix")
    stolen["presets"].append(EMPLOYER_SAFE)  # mutate the returned copy
    stolen["band_definitions"][0]["bands"].append("always")
    assert registry.entry("transcript.tool_mix")["band_definitions"][0]["bands"][-1] != "always"
    assert registry.digest() == digest
    doc = packaged_doc()
    r = Registry(doc)
    doc["entries"][0]["title"] = "Developer IQ band"  # mutate the source doc post-load
    assert r.entry(doc["entries"][0]["id"])["title"] != "Developer IQ band"


def test_unknown_preset_is_an_error_not_an_empty_manifest(registry):
    with pytest.raises(RegistryError, match="unknown preset"):
        registry.disclosure_manifest("employer_safe")  # typo'd
    with pytest.raises(RegistryError, match="unknown preset"):
        registry.preset_ids("everything")


def test_active_output_schema_must_be_a_closed_whitelist():
    def open_schema(doc):
        entry_by_id(doc, "transcript.tool_mix")["output_schema"].pop("additionalProperties")

    with pytest.raises(RegistryError, match="closed whitelist"):
        Registry(mutated(open_schema))


def test_band_definitions_and_output_enums_cannot_drift():
    def drift_enum(doc):
        e = entry_by_id(doc, "transcript.tool_mix")
        e["output_schema"]["properties"]["read_share_band"]["enum"] = ["low", "high"]

    with pytest.raises(RegistryError, match="disagrees with the output_schema enum"):
        Registry(mutated(drift_enum))

    def orphan_band(doc):
        e = entry_by_id(doc, "transcript.tool_mix")
        e["band_definitions"].append({"field": "phantom_band", "bands": ["a", "b"]})

    with pytest.raises(RegistryError, match="matches no enum output property"):
        Registry(mutated(orphan_band))

    def unbanded_enum(doc):
        e = entry_by_id(doc, "transcript.tool_mix")
        e["band_definitions"] = e["band_definitions"][1:]  # drop read_share_band

    with pytest.raises(RegistryError, match="has no band_definitions entry"):
        Registry(mutated(unbanded_enum))


def test_duplicate_json_keys_in_registry_file_rejected(tmp_path):
    f = tmp_path / "dup.json"
    f.write_bytes(
        _packaged_registry_bytes().replace(
            b'"registry_version": "0.1.1"',
            b'"registry_version": "0.1.1", "registry_version": "0.1.1"',
            1,
        )
    )
    with pytest.raises(RegistryError, match="duplicate JSON key"):
        Registry.load(f)


def test_wave_zero_is_exactly_the_fingerprint_namespace():
    def wave_zero_elsewhere(doc):
        entry_by_id(doc, "transcript.skill_authoring")["wave"] = 0

    with pytest.raises(RegistryError, match="fingerprint"):
        Registry(mutated(wave_zero_elsewhere))
    def fingerprint_wave_two(doc):
        entry_by_id(doc, "fingerprint.workflow_map")["wave"] = 2

    with pytest.raises(RegistryError, match="fingerprint"):
        Registry(mutated(fingerprint_wave_two))


def test_packaged_load_is_cached_and_path_load_is_fresh(tmp_path, registry):
    assert Registry.load() is registry  # lru-cached packaged instance
    f = tmp_path / "copy.json"
    f.write_bytes(_packaged_registry_bytes())
    assert Registry.load(f) is not registry


def test_domain_mix_is_r1_per_the_handoff(registry):
    # §8.3 names "domain mix + location" as its R1 example.
    e = registry.entry("repo.domain_mix")
    assert e["inference_risk"] == "R1"
    assert "risk_note" in e
    assert EMPLOYER_SAFE not in e["presets"]


def test_bridge_rejects_free_text_in_slug_arrays(registry):
    # harnesses entries are slug-patterned: prose/content strings can't ride.
    with pytest.raises(RegistryError, match="does not conform"):
        registry.check_claim(
            tool_mix_claim(
                registry_id="transcript.orchestrators",
                output={
                    "harnesses": ["totally normal prose with spaces in it"],
                    "version_currency_band": "older",
                },
            )
        )
    registry.check_claim(
        tool_mix_claim(
            registry_id="transcript.orchestrators",
            output={"harnesses": ["claude-code", "codex"], "version_currency_band": "older"},
        )
    )


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
