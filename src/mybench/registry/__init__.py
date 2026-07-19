"""Descriptor registry — loader, cross-entry rules, disclosure derivation (MYB-10.2).

The registry (``descriptor_registry.json``, packaged and published in this
repo — its git history is the audit trail per handoff §7) is the single
source of truth for what mybench can claim: band edges and min-support live
HERE, not in scorer code, so a recalibration is a registry version bump plus
retroactive re-disclosure over already-anchored history — never a code
change. It equally records what mybench deliberately does NOT claim
(``rejected:`` section, banned framings) — a transparency artifact. The JSON
file is the hand-maintained source of truth (the initial seeding script was
one-time scaffolding); schema + loader validation is what makes hand edits
safe.

Format note (ADR-0016, accepted at the MYB-10.17 sitting): JSON is ratified.
The loader still works on parsed dictionaries and :meth:`Registry.digest`
hashes the *canonical parsed content* (via :mod:`mybench.claims.canonical`),
so registry identity remains independent of whitespace formatting.

Enforcement this module adds beyond the schema whitelist
(``descriptor_registry.schema.json``):

- duplicate JSON keys rejected at parse; canonical-safety (no floats) checked
  up front; ids/versions re-checked with ``re.fullmatch`` (jsonschema
  patterns run under ``re.search``, where ``$`` accepts a trailing newline);
- unique entry ids; every ``output_schema`` is a valid, ``$ref``-free,
  CLOSED 2020-12 fragment (``additionalProperties: false`` + ``required``)
  for active entries — the entry schema is the only whitelist standing
  between scorer output and a signed claim, and ``$ref`` resolution is
  banned outright (a remote ref would be a network call at score time);
- band edges are declared ONCE per output property: every enum-carrying
  output property must have a matching ``band_definitions`` entry with an
  identical band list, and vice versa — the two views cannot drift;
- ``employer-safe`` preset ⇒ R0 only (handoff §8.3 — the default bundle);
  R1/R2 entries carry a plain-language ``risk_note``;
- ``internal-feature-only`` entries have no presets and are STRUCTURALLY
  invisible on every disclosure surface: absent from renderable ids, preset
  lists, and the disclosure manifest entirely — only an aggregate count
  appears (handoff §7.1 "never appear in any report, preset, or API
  disclosure surface");
- banned framings never appear in entry ids, titles, notes, neutrality
  notes, risk notes, or band labels — matched on word-boundary token
  sequences with punctuation folding ("I.Q." caught; "unique" not);
- ``reserved`` entries are not claimable; ``wave: 0`` is exactly the
  ``fingerprint.*`` placeholder namespace;
- :meth:`Registry.check_claim` — the registry-conformance seam the claim
  envelope deliberately left open: a claim must cite an active entry, match
  its version and derivation class, and its output must validate against
  the entry's (precompiled) output schema. Conditioned entries additionally
  pin their taxonomy id/version, require ``output.condition``, and key a
  positive support floor by every admitted cell. Evidence-volume thresholds
  (``min_support``, handoff §8.4) are deliberately NOT checked here: claims
  carry no volume fields — the scorer's emit gate (MYB-10.6) enforces
  below-threshold ⇒ no claim, never a zero-valued claim (including each
  conditioning cell independently).
- conditional denominators name both their condition class and their source;
  severity vocabularies declare only closed class ids. Numeric severity
  weights remain judge-rubric behavior (MYB-7.1), not registry data.
- :meth:`Registry.check_report_field` is the report-v2 seam: active registry
  membership, closed report location, derivation class, disclosure, risk,
  controlled caveats, and reserved-block activation all fail closed.

Publication of the CLAIMS the registry governs stays gated on the
THREAT_MODEL §3 revision (invariant #4, MYB-16.2); the registry file itself
contains descriptor definitions only — no user data.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from functools import lru_cache
from importlib import resources
from pathlib import Path

import jsonschema

from mybench.claims.canonical import CanonicalError, canonical_bytes, check_canonical_value
from mybench.schemas import load_validator

EMPLOYER_SAFE = "employer-safe"

_ID_RE = re.compile(r"[a-z0-9_]+(\.[a-z0-9_]+)+")
_VOCABULARY_ID_RE = re.compile(r"[a-z0-9_]+([.-][a-z0-9_]+)*")
_CAVEAT_RE = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
_SEMVER_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


class RegistryError(RuntimeError):
    pass


def _packaged_registry_bytes() -> bytes:
    return resources.files("mybench.registry").joinpath("descriptor_registry.json").read_bytes()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise RegistryError(f"duplicate JSON key {key!r} in registry file")
        obj[key] = value
    return obj


def _tokens(text: str) -> list[str]:
    """Punctuation-folded word tokens, with single-letter runs merged so
    dotted initialisms match their framing ("I.Q." -> ["iq"])."""
    raw = re.findall(r"[a-z0-9]+", text.lower())
    merged: list[str] = []
    run: list[str] = []
    for tok in raw:
        if len(tok) == 1:
            run.append(tok)
            continue
        if run:
            merged.append("".join(run))
            run = []
        merged.append(tok)
    if run:
        merged.append("".join(run))
    return merged


def _contains_framing(text: str, framing_tokens: list[str]) -> bool:
    toks = _tokens(text)
    n = len(framing_tokens)
    return any(toks[i : i + n] == framing_tokens for i in range(len(toks) - n + 1))


def _iter_enum_properties(output_schema: dict, excluded_fields: set[str] | None = None):
    """Yield (property_name, enum) for every enum-carrying string property,
    top-level or one array-items level down — the band surfaces."""
    excluded_fields = excluded_fields or set()
    for name, prop in output_schema.get("properties", {}).items():
        if isinstance(prop, dict):
            if "enum" in prop and name not in excluded_fields:
                yield name, prop["enum"]
            items = prop.get("items")
            if isinstance(items, dict):
                for sub, subprop in items.get("properties", {}).items():
                    if (
                        isinstance(subprop, dict)
                        and "enum" in subprop
                        and sub not in excluded_fields
                    ):
                        yield sub, subprop["enum"]


def _contains_ref(fragment: object) -> bool:
    if isinstance(fragment, dict):
        return any(k in ("$ref", "$dynamicRef") for k in fragment) or any(
            _contains_ref(v) for v in fragment.values()
        )
    if isinstance(fragment, list):
        return any(_contains_ref(v) for v in fragment)
    return False


class Registry:
    """A loaded, fully validated, immutable descriptor registry."""

    def __init__(self, doc: dict):
        self._doc = copy.deepcopy(doc)  # own the snapshot: caller mutation can't void invariants
        self._entries: dict[str, dict] = {}
        self._output_validators: dict[str, jsonschema.Draft202012Validator] = {}
        self._validate()
        self._digest = hashlib.sha256(canonical_bytes(self._doc)).hexdigest()
        self._renderable = sorted(
            eid
            for eid, e in self._entries.items()
            if e["disclosure"] == "public" and e["status"] == "active"
        )

    # -- loading -----------------------------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> "Registry":
        """Load from ``path``, or the packaged registry when omitted (cached)."""
        if path is None:
            return _load_packaged()
        try:
            doc = json.loads(Path(path).read_bytes(), object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise RegistryError("registry file is not valid JSON") from exc
        return cls(doc)

    def _validate(self) -> None:
        try:
            check_canonical_value(self._doc)
        except CanonicalError as exc:
            raise RegistryError(f"registry is not canonical-JSON-safe: {exc}") from exc
        errors = sorted(
            load_validator("descriptor_registry.schema.json").iter_errors(self._doc), key=str
        )
        if errors:
            raise RegistryError(f"registry schema violation: {errors[0].message}")
        if not _SEMVER_RE.fullmatch(self._doc["registry_version"]):
            raise RegistryError("registry_version is not exactly a semver string")
        framings = [_tokens(b) for b in self._doc["banned_framings"]]
        for entry in self._doc["entries"]:
            self._validate_entry(entry, framings)

    def _validate_entry(self, entry: dict, framings: list[list[str]]) -> None:
        eid = entry["id"]
        # jsonschema patterns use re.search ('$' accepts a trailing newline);
        # fullmatch here makes near-duplicate ids/versions impossible.
        if not _ID_RE.fullmatch(eid):
            raise RegistryError(f"entry id is not exactly namespace.name: {eid!r}")
        if not _SEMVER_RE.fullmatch(entry["version"]):
            raise RegistryError(f"{eid}: version is not exactly a semver string")
        if eid in self._entries:
            raise RegistryError(f"duplicate registry id: {eid}")
        self._entries[eid] = entry

        for field in ("conditioning_axis", "severity_weight_vocabulary"):
            declaration = entry.get(field)
            if declaration is None:
                continue
            if not _VOCABULARY_ID_RE.fullmatch(declaration["taxonomy_id"]):
                raise RegistryError(f"{eid}: {field} taxonomy_id is not exact")
            if not _SEMVER_RE.fullmatch(declaration["taxonomy_version"]):
                raise RegistryError(f"{eid}: {field} taxonomy_version is not exact semver")
        denominator = entry.get("conditional_denominator")
        if denominator is not None:
            for field in ("condition_class", "denominator_source"):
                if not _VOCABULARY_ID_RE.fullmatch(denominator[field]):
                    raise RegistryError(f"{eid}: conditional_denominator {field} is not exact")
        cell_ids = entry["min_support"].get("per_conditioning_cell", {}).keys()
        severity_classes = entry.get("severity_weight_vocabulary", {}).get("classes", [])
        for value in (*cell_ids, *severity_classes):
            if not _VOCABULARY_ID_RE.fullmatch(value):
                raise RegistryError(f"{eid}: vocabulary cell id is not exact: {value!r}")

        band_labels = [band for bd in entry["band_definitions"] for band in bd["bands"]]
        registry_vocabulary = []
        if "conditioning_axis" in entry:
            registry_vocabulary.append(entry["conditioning_axis"]["taxonomy_id"])
            registry_vocabulary.extend(cell_ids)
        if denominator is not None:
            registry_vocabulary.extend(denominator.values())
        if "severity_weight_vocabulary" in entry:
            severity = entry["severity_weight_vocabulary"]
            registry_vocabulary.append(severity["taxonomy_id"])
            registry_vocabulary.extend(severity["classes"])
        copy_surfaces = [
            ("id", eid),
            ("title", entry["title"]),
            ("neutrality_note", entry["neutrality_note"]),
            ("notes", entry.get("notes", "")),
            ("risk_note", entry.get("risk_note", "")),
            ("caveat copy", " ".join(entry.get("caveat_copy", {}).values())),
            ("band labels", " ".join(band_labels)),
            ("registry vocabulary", " ".join(registry_vocabulary)),
        ]
        for framing_tokens, framing in zip(framings, self._doc["banned_framings"]):
            for where, text in copy_surfaces:
                if text and _contains_framing(text, framing_tokens):
                    raise RegistryError(f"banned framing {framing!r} in {where} of {eid}")

        if entry["inference_risk"] != "R0" and EMPLOYER_SAFE in entry["presets"]:
            raise RegistryError(
                f"{eid}: employer-safe preset is R0-only (handoff §8.3), "
                f"entry is {entry['inference_risk']}"
            )
        if entry["inference_risk"] != "R0" and "risk_note" not in entry:
            raise RegistryError(
                f"{eid}: {entry['inference_risk']} entries require a plain-language risk_note"
            )
        if entry["disclosure"] == "internal-feature-only" and entry["presets"]:
            raise RegistryError(
                f"{eid}: internal-feature-only entries may not appear in any preset"
            )
        if (entry["wave"] == 0) != eid.startswith("fingerprint."):
            raise RegistryError(f"{eid}: wave 0 is exactly the fingerprint.* placeholder namespace")

        if entry["disclosure"] == "local-report-only" and entry["presets"]:
            raise RegistryError(
                f"{eid}: local-report-only entries may not appear in publication presets"
            )
        report_location = entry.get("report_location")
        report_controls = entry.get("report_controls")
        caveat_copy = entry.get("caveat_copy")
        schema = entry["output_schema"]
        if report_location is not None and entry["disclosure"] == "internal-feature-only":
            raise RegistryError(
                f"{eid}: internal-feature-only entries may not have a report location"
            )
        if report_location is not None:
            if report_controls is None or caveat_copy is None:
                raise RegistryError(
                    f"{eid}: report-located entries require report_controls and caveat_copy"
                )
            output_properties = schema.get("properties", {})
            required_output = set(schema.get("required", []))
            tier_schema = output_properties.get("trust_tier", {})
            caveat_schema = output_properties.get("caveats", {})
            if not isinstance(tier_schema, dict) or tier_schema.get("const") not in {
                "PROVEN",
                "ANCHORED",
                "TEE-VERIFIED",
                "JUDGED",
            }:
                raise RegistryError(f"{eid}: report output requires a controlled trust-tier const")
            required_caveats = (
                caveat_schema.get("const") if isinstance(caveat_schema, dict) else None
            )
            if (
                not isinstance(required_caveats, list)
                or not all(
                    isinstance(code, str) and _CAVEAT_RE.fullmatch(code)
                    for code in required_caveats
                )
                or required_caveats != sorted(set(required_caveats))
                or not {"trust_tier", "caveats"}.issubset(required_output)
            ):
                raise RegistryError(
                    f"{eid}: report output must require a sorted controlled caveat const"
                )
            if set(caveat_copy) != set(required_caveats):
                raise RegistryError(
                    f"{eid}: caveat_copy keys must exactly match output_schema caveats"
                )
            if report_controls["conditioning"] != ("conditioning_axis" in entry):
                raise RegistryError(
                    f"{eid}: report conditioning activation must match conditioning_axis"
                )
        elif report_controls is not None or caveat_copy is not None:
            raise RegistryError(f"{eid}: report metadata requires an explicit report location")
        if (entry["wave"] == 0) != eid.startswith("fingerprint."):
            raise RegistryError(f"{eid}: wave 0 is exactly the fingerprint.* placeholder namespace")

        if _contains_ref(schema):
            raise RegistryError(
                f"{eid}: output_schema may not use $ref/$dynamicRef — resolution is a "
                "score-time dependency (and, on older jsonschema, a network call)"
            )
        try:
            jsonschema.Draft202012Validator.check_schema(schema)
        except jsonschema.SchemaError as exc:
            raise RegistryError(f"{eid}: output_schema is not a valid schema") from exc

        if entry["status"] == "active":
            if not entry["min_support"]:
                raise RegistryError(f"{eid}: active entries need min_support")
            if "properties" not in schema:
                raise RegistryError(f"{eid}: active entries need a concrete output_schema")
            if schema.get("additionalProperties") is not False or not schema.get("required"):
                raise RegistryError(
                    f"{eid}: active output_schema must be a closed whitelist "
                    "(additionalProperties: false + required) — it is the only shape gate "
                    "between scorer output and a signed claim"
                )
            conditioning = entry.get("conditioning_axis")
            cell_support = entry["min_support"].get("per_conditioning_cell")
            if conditioning is not None:
                condition_schema = schema.get("properties", {}).get("condition")
                if (
                    "condition" not in schema["required"]
                    or not isinstance(condition_schema, dict)
                    or condition_schema.get("type") != "string"
                    or not condition_schema.get("enum")
                ):
                    raise RegistryError(
                        f"{eid}: active conditioned entries require an enumerated string "
                        "output.condition"
                    )
                if not cell_support:
                    raise RegistryError(
                        f"{eid}: active conditioned entries require "
                        "min_support.per_conditioning_cell"
                    )
                if set(condition_schema["enum"]) != set(cell_support):
                    raise RegistryError(
                        f"{eid}: output.condition enum and per-cell support keys must match"
                    )
            elif cell_support is not None:
                raise RegistryError(
                    f"{eid}: per-conditioning-cell support requires conditioning_axis"
                )
            # Band edges are declared once per property; the schema enum and the
            # band_definitions view must be the same list or the recalibration
            # story (registry bump, no code change) silently breaks.
            non_band_fields = {"condition"} if conditioning is not None else set()
            enum_props = dict(_iter_enum_properties(schema, non_band_fields))
            declared = {bd["field"]: bd["bands"] for bd in entry["band_definitions"]}
            if enum_props and not declared:
                raise RegistryError(f"{eid}: enum output fields need band_definitions")
            for prop, enum in enum_props.items():
                if prop not in declared:
                    raise RegistryError(
                        f"{eid}: enum property {prop!r} has no band_definitions entry"
                    )
                if declared[prop] != enum:
                    raise RegistryError(
                        f"{eid}: band_definitions[{prop!r}] disagrees with the output_schema enum"
                    )
            for field in declared:
                if field not in enum_props:
                    raise RegistryError(
                        f"{eid}: band_definitions field {field!r} matches no enum output property"
                    )
            self._output_validators[eid] = jsonschema.Draft202012Validator(schema)

    # -- identity ----------------------------------------------------------------

    @property
    def version(self) -> str:
        return self._doc["registry_version"]

    def digest(self) -> str:
        """SHA-256 over the canonical parsed content — stable across
        serialization formatting (and across the OQ #31 format decision)."""
        return self._digest

    # -- lookup (the scorer-facing contract: bands live here, not in code) --------

    def ids(self) -> list[str]:
        return sorted(self._entries)

    def entry(self, registry_id: str) -> dict:
        """A defensive copy — the registry is immutable after validation."""
        return copy.deepcopy(self._entry(registry_id))

    def _entry(self, registry_id: str) -> dict:
        try:
            return self._entries[registry_id]
        except KeyError:
            raise RegistryError(f"unknown registry id: {registry_id}") from None

    def band_definitions(self, registry_id: str) -> list[dict]:
        return copy.deepcopy(self._entry(registry_id)["band_definitions"])

    def min_support(self, registry_id: str) -> dict:
        return copy.deepcopy(self._entry(registry_id)["min_support"])

    def conditioning_axis(self, registry_id: str) -> dict | None:
        """Return the pinned conditioning-axis declaration, when present."""
        axis = self._entry(registry_id).get("conditioning_axis")
        return copy.deepcopy(axis)

    def conditioning_min_support(self, registry_id: str, condition: str) -> dict:
        """Return one cell's positive support floors.

        Unknown cells fail closed. Scorers compare their evidence volume with
        this result and omit a thin cell entirely; zero is never a substitute.
        """
        entry = self._entry(registry_id)
        if "conditioning_axis" not in entry:
            raise RegistryError(f"{registry_id}: entry has no conditioning axis")
        cell_support = entry["min_support"].get("per_conditioning_cell", {})
        try:
            return dict(cell_support[condition])
        except (KeyError, TypeError):
            raise RegistryError(
                f"{registry_id}: unknown or unsupported condition {condition!r}"
            ) from None

    def conditional_denominator(self, registry_id: str) -> dict | None:
        """Return the declared condition class and denominator source."""
        declaration = self._entry(registry_id).get("conditional_denominator")
        return copy.deepcopy(declaration)

    def severity_weight_vocabulary(self, registry_id: str) -> dict | None:
        """Return severity class ids only; weights belong to the judge rubric."""
        vocabulary = self._entry(registry_id).get("severity_weight_vocabulary")
        return copy.deepcopy(vocabulary)

    # -- disclosure surfaces (handoff §7.1; consumed by MYB-14.1) ------------------

    def presets(self) -> tuple[str, ...]:
        return (EMPLOYER_SAFE, "full")

    def renderable_ids(self) -> list[str]:
        """Every id any render path may show: public + active, nothing else.
        internal-feature-only is structurally absent (handoff §7.1)."""
        return list(self._renderable)

    def preset_ids(self, preset: str) -> list[str]:
        if preset not in self.presets():
            raise RegistryError(f"unknown preset {preset!r}; known: {self.presets()}")
        return [eid for eid in self._renderable if preset in self._entries[eid]["presets"]]

    def disclosure_manifest(self, preset: str) -> dict:
        """The deterministic will/won't-be-included listing (roadmap Stage 1
        §8) derived from disclosure flags, risk classes, and presets — the
        one source of truth the publication preview (MYB-14.1) consumes.

        internal-feature-only entries do not appear AT ALL (handoff §7.1:
        never on any disclosure surface) — only an aggregate count, so the
        manifest stays honest about their existence without naming them.
        """
        included = set(self.preset_ids(preset))
        excluded = []
        hidden = 0
        for eid in self.ids():
            if eid in included:
                continue
            e = self._entries[eid]
            if e["disclosure"] == "internal-feature-only":
                hidden += 1
                continue
            if e["status"] == "reserved":
                reason = "reserved: no claims exist yet"
            else:
                reason = (
                    f"not in preset {preset!r}"
                    f" (inference risk {e['inference_risk']}"
                    f"{'; ' + e['risk_note'] if 'risk_note' in e else ''})"
                )
            excluded.append({"id": eid, "reason": reason})
        return {
            "registry_version": self.version,
            "registry_digest": self.digest(),
            "preset": preset,
            "included": sorted(included),
            "excluded": excluded,
            "internal_feature_only_count": hidden,
            "rejected": copy.deepcopy(self._doc["rejected"]),
        }

    # -- report-v2 rendering bridge ------------------------------------------------

    def report_location(self, registry_id: str) -> str | None:
        """Return the explicitly admitted v2 location, if one exists."""
        return self._entry(registry_id).get("report_location")

    def _check_report_field(self, field: dict, location: str) -> tuple[dict, dict]:
        """Return the registry entry and exact output represented by a v2 field."""
        entry = self._entry(field["registry_id"])
        eid = entry["id"]
        if entry["status"] != "active":
            raise RegistryError(f"{eid} is reserved — it cannot render")
        expected_location = entry.get("report_location")
        if expected_location is None:
            raise RegistryError(f"{eid}: no report-v2 location is active")
        if location != expected_location:
            raise RegistryError(
                f"{eid}: report location {location!r} does not match {expected_location!r}"
            )
        if field["registry_version"] != entry["version"]:
            raise RegistryError(
                f"{eid}: report cites version {field['registry_version']}, "
                f"registry entry is {entry['version']}"
            )
        if field["derivation_class"] != entry["class"]:
            raise RegistryError(f"{eid}: report derivation class does not match registry")
        if field["inference_risk"] != entry["inference_risk"]:
            raise RegistryError(f"{eid}: report inference risk does not match registry")
        disclosure = {
            "public": "PUBLISHABLE",
            "local-report-only": "LOCAL_ONLY",
        }.get(entry["disclosure"])
        if disclosure is None or field["disclosure"] != disclosure:
            raise RegistryError(f"{eid}: report disclosure does not match registry")
        controls = entry["report_controls"]

        expected_caveats = (
            entry["output_schema"].get("properties", {}).get("caveats", {}).get("const", [])
        )
        if field.get("caveats", []) != expected_caveats:
            raise RegistryError(f"{eid}: report caveats do not match registry")

        output = {}
        value = field["value"]
        if isinstance(value, list):
            dimension_order = [tuple(cell["dimensions"]) for cell in value]
            if dimension_order != sorted(dimension_order):
                raise RegistryError(f"{eid}: report value cells must be sorted by dimensions")
            for cell in value:
                dimensions = cell["dimensions"]
                if len(dimensions) != 1 or dimensions[0] in output:
                    raise RegistryError(
                        f"{eid}: report value cells must name unique output properties"
                    )
                output[dimensions[0]] = cell["value"]
        else:
            required = [
                name
                for name in entry["output_schema"]["required"]
                if name not in {"trust_tier", "caveats"}
            ]
            if len(required) != 1:
                raise RegistryError(f"{eid}: scalar report value is ambiguous")
            output[required[0]] = value
        output_properties = entry["output_schema"]["properties"]
        if "trust_tier" in output_properties:
            output["trust_tier"] = field["trust_tier"]
        if "caveats" in output_properties:
            output["caveats"] = field.get("caveats", [])
        errors = sorted(self._output_validators[eid].iter_errors(output), key=str)
        if errors:
            raise RegistryError(
                f"{eid}: report value does not conform to the registry entry: {errors[0].message}"
            )

        expected_tier = (
            entry["output_schema"].get("properties", {}).get("trust_tier", {}).get("const")
        )
        if expected_tier is not None and field["trust_tier"] != expected_tier:
            raise RegistryError(f"{eid}: report trust tier does not match registry")
        if field["execution_env"] == "local-unattested" and (
            field["trust_tier"] == "TEE-VERIFIED"
            or (
                field["trust_tier"] == "JUDGED"
                and not (controls["tier_qualifier"] and field.get("tier_qualifier") == "unattested")
            )
        ):
            raise RegistryError(f"{eid}: local-unattested presentation exceeds its tier cap")
        if field["execution_env"] == "tee-attested" and not (
            field["trust_tier"] == "TEE-VERIFIED"
            or (
                field["trust_tier"] == "JUDGED"
                and controls["tier_qualifier"]
                and field.get("tier_qualifier") == "attested"
            )
        ):
            raise RegistryError(f"{eid}: attested presentation requires an attested tier label")
        if field["derivation_class"] == "characterization" and field["trust_tier"] != "ANCHORED":
            raise RegistryError(f"{eid}: rule-based characterizations render ANCHORED")

        for key, label in (
            ("reference_frame", "reference frames"),
            ("tier_qualifier", "judged tier qualifiers"),
        ):
            if key in field and not controls[key]:
                raise RegistryError(f"{eid}: {label} are not active")
        conditioning = field.get("conditioning")
        axis = entry.get("conditioning_axis")
        if conditioning is not None:
            if not controls["conditioning"] or axis is None:
                raise RegistryError(f"{eid}: report conditioning is not active")
            if conditioning["axis"] != axis["taxonomy_id"]:
                raise RegistryError(f"{eid}: report conditioning axis is not active")
            if conditioning["cell"] not in entry["min_support"]["per_conditioning_cell"]:
                raise RegistryError(f"{eid}: report conditioning cell is not active")
        elif axis is not None:
            raise RegistryError(f"{eid}: conditioned report field omits its condition")
        return copy.deepcopy(entry), output

    def check_report_field(self, field: dict, location: str) -> dict:
        """Validate registry-owned presentation metadata for one v2 field.

        The report envelope schema validates the closed field/value shape.
        This supplies ADR-0019's separate semantic gate and returns a
        defensive entry copy for rendering controlled registry text.
        """
        entry, _output = self._check_report_field(field, location)
        return entry

    def check_report_claim(self, field: dict, location: str, claim: dict) -> dict:
        """Require one registry-valid signed-claim payload to back a v2 field.

        Envelope and signature verification belong to the caller.  This
        registry-owned bridge validates both semantic surfaces, derives the
        report wrapper's exact registry output without renderer-side
        reconstruction, and compares structures directly (never stringifies
        or coerces values).
        """
        eid = field["registry_id"]
        entry, report_output = self._check_report_field(field, location)
        try:
            self.check_claim(claim)
        except RegistryError as exc:
            # A claim output may be registry-invalid local input.  Do not let
            # jsonschema echo its offending value through a report error/log.
            raise RegistryError(f"{eid}: signed claim is not registry-conforming") from exc
        for key in ("registry_id", "registry_version", "derivation_class", "execution_env"):
            if field[key] != claim[key]:
                raise RegistryError(f"{eid}: report {key} does not match signed claim")
        if report_output != claim["output"]:
            raise RegistryError(f"{eid}: report output does not match signed claim")
        return entry

    # -- the claims bridge ----------------------------------------------------------

    def check_claim(self, claim: dict) -> None:
        """Registry conformance for one (already envelope-validated) claim:
        the seam MYB-10.1 left open. Raises RegistryError (only).

        min_support is NOT checked here — claims carry no evidence-volume
        fields; the scorer's emit gate owns below-threshold ⇒ no claim
        (handoff §8.4, MYB-10.6). Scorers SHOULD also record the registry
        identity as an anchor_ref ("registry:sha256:<digest>") so "what did
        this descriptor mean at time T" survives entry-version mistakes.
        """
        entry = self._entry(claim["registry_id"])
        if entry["status"] != "active":
            raise RegistryError(f"{claim['registry_id']} is reserved — no claims may cite it yet")
        if claim["registry_version"] != entry["version"]:
            raise RegistryError(
                f"{claim['registry_id']}: claim cites version {claim['registry_version']}, "
                f"registry entry is {entry['version']}"
            )
        if claim["derivation_class"] != entry["class"]:
            raise RegistryError(
                f"{claim['registry_id']}: derivation_class {claim['derivation_class']!r} "
                f"does not match registry class {entry['class']!r}"
            )
        if "conditioning_axis" in entry:
            output = claim.get("output")
            if not isinstance(output, dict) or "condition" not in output:
                raise RegistryError(
                    f"{claim['registry_id']}: conditioned claim omits output.condition"
                )
            condition = output["condition"]
            cell_support = entry["min_support"]["per_conditioning_cell"]
            if not isinstance(condition, str) or condition not in cell_support:
                raise RegistryError(
                    f"{claim['registry_id']}: unknown or unsupported condition {condition!r}"
                )
        validator = self._output_validators[claim["registry_id"]]
        try:
            errors = sorted(validator.iter_errors(claim["output"]), key=str)
        except Exception as exc:  # noqa: BLE001 — exception contract: RegistryError only
            raise RegistryError(
                f"{claim['registry_id']}: output validation failed: {type(exc).__name__}"
            ) from exc
        if errors:
            raise RegistryError(
                f"{claim['registry_id']}: output does not conform to the registry entry: "
                f"{errors[0].message}"
            )


@lru_cache(maxsize=1)
def _load_packaged() -> Registry:
    try:
        doc = json.loads(_packaged_registry_bytes(), object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise RegistryError("packaged registry is not valid JSON") from exc
    return Registry(doc)
