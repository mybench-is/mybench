"""Descriptor registry — loader, cross-entry rules, disclosure derivation (MYB-10.2).

The registry (``descriptor_registry.json``, packaged and published in this
repo — its git history is the audit trail per handoff §7) is the single
source of truth for what mybench can claim: band edges and min-support live
HERE, not in scorer code, so a recalibration is a registry version bump plus
retroactive re-disclosure over already-anchored history — never a code
change. It equally records what mybench deliberately does NOT claim
(``rejected:`` section, banned framings) — a transparency artifact.

Format note (OQ #31, owner-gated at the MYB-10.17 sitting): the JSON
serialization is provisional (``format_status`` says so in-band); this
loader works on parsed dicts, so ratifying YAML instead is a data-file swap,
not a loader change. :func:`Registry.digest` hashes the *canonical parsed
content* (via :mod:`mybench.claims.canonical`), so the registry identity is
independent of serialization formatting either way.

Enforcement this module adds beyond the schema whitelist
(``descriptor_registry.schema.json``):

- unique entry ids; every ``output_schema`` is itself a valid 2020-12 schema;
- ``employer-safe`` preset ⇒ R0 only (handoff §8.3 — the default bundle);
- R1/R2 entries carry a plain-language ``risk_note``;
- ``internal-feature-only`` entries have no presets and are STRUCTURALLY
  non-renderable: excluded from :meth:`Registry.renderable_ids` and every
  disclosure manifest (handoff §7.1);
- ``active`` entries have band definitions, min-support, and a concrete
  output schema; ``reserved`` entries are not claimable;
- banned framings never appear in entry ids or titles (handoff §7.2/§8.6);
- :meth:`Registry.check_claim` — the registry-conformance seam the claim
  envelope deliberately left open: a claim must cite an active entry, match
  its version and derivation class, and its output must validate against the
  entry's output schema.

Publication of the CLAIMS the registry governs stays gated on the
THREAT_MODEL §3 revision (invariant #4, MYB-16.2); the registry file itself
contains descriptor definitions only — no user data.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from pathlib import Path

import jsonschema

from mybench.claims.canonical import CanonicalError, canonical_bytes
from mybench.schemas import load_validator

EMPLOYER_SAFE = "employer-safe"


class RegistryError(RuntimeError):
    pass


def _packaged_registry_bytes() -> bytes:
    return (
        resources.files("mybench.registry").joinpath("descriptor_registry.json").read_bytes()
    )


class Registry:
    """A loaded, fully validated descriptor registry."""

    def __init__(self, doc: dict):
        self._doc = doc
        self._entries: dict[str, dict] = {}
        self._validate()

    # -- loading -----------------------------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> "Registry":
        """Load from ``path``, or the packaged registry when omitted."""
        raw = Path(path).read_bytes() if path is not None else _packaged_registry_bytes()
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RegistryError("registry file is not valid JSON") from exc
        return cls(doc)

    def _validate(self) -> None:
        errors = sorted(
            load_validator("descriptor_registry.schema.json").iter_errors(self._doc), key=str
        )
        if errors:
            raise RegistryError(f"registry schema violation: {errors[0].message}")
        banned = [b.lower() for b in self._doc["banned_framings"]]
        for entry in self._doc["entries"]:
            eid = entry["id"]
            if eid in self._entries:
                raise RegistryError(f"duplicate registry id: {eid}")
            self._entries[eid] = entry
            for text, where in ((eid, "id"), (entry["title"], "title")):
                lowered = text.lower()
                for framing in banned:
                    if framing in lowered:
                        raise RegistryError(
                            f"banned framing {framing!r} in {where} of {eid}"
                        )
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
            try:
                jsonschema.Draft202012Validator.check_schema(entry["output_schema"])
            except jsonschema.SchemaError as exc:
                raise RegistryError(f"{eid}: output_schema is not a valid schema") from exc
            if entry["status"] == "active":
                if not entry["band_definitions"]:
                    raise RegistryError(f"{eid}: active entries need band_definitions")
                if not entry["min_support"]:
                    raise RegistryError(f"{eid}: active entries need min_support")
                if "properties" not in entry["output_schema"]:
                    raise RegistryError(f"{eid}: active entries need a concrete output_schema")

    # -- identity ----------------------------------------------------------------

    @property
    def version(self) -> str:
        return self._doc["registry_version"]

    def digest(self) -> str:
        """SHA-256 over the canonical parsed content — stable across
        serialization formatting (and across the OQ #31 format decision)."""
        try:
            return hashlib.sha256(canonical_bytes(self._doc)).hexdigest()
        except CanonicalError as exc:  # registry must obey the byte discipline too
            raise RegistryError(f"registry is not canonical-JSON-safe: {exc}") from exc

    # -- lookup (the scorer-facing contract: bands live here, not in code) --------

    def ids(self) -> list[str]:
        return sorted(self._entries)

    def entry(self, registry_id: str) -> dict:
        try:
            return self._entries[registry_id]
        except KeyError:
            raise RegistryError(f"unknown registry id: {registry_id}") from None

    def band_definitions(self, registry_id: str) -> list[dict]:
        return self.entry(registry_id)["band_definitions"]

    def min_support(self, registry_id: str) -> dict:
        return self.entry(registry_id)["min_support"]

    # -- disclosure surfaces (handoff §7.1; consumed by MYB-14.1) ------------------

    def renderable_ids(self) -> list[str]:
        """Every id any render path may show: public + active, nothing else.
        internal-feature-only is structurally absent (handoff §7.1)."""
        return sorted(
            eid
            for eid, e in self._entries.items()
            if e["disclosure"] == "public" and e["status"] == "active"
        )

    def preset_ids(self, preset: str) -> list[str]:
        return sorted(
            eid for eid in self.renderable_ids() if preset in self._entries[eid]["presets"]
        )

    def disclosure_manifest(self, preset: str) -> dict:
        """The deterministic will/won't-be-included listing (roadmap Stage 1
        §8) derived from disclosure flags, risk classes, and presets — the
        one source of truth the publication preview (MYB-14.1) consumes."""
        included = self.preset_ids(preset)
        excluded = []
        for eid in self.ids():
            if eid in included:
                continue
            e = self._entries[eid]
            if e["disclosure"] == "internal-feature-only":
                reason = "internal-feature-only: never rendered on any surface"
            elif e["status"] == "reserved":
                reason = "reserved: no claims exist yet"
            elif preset not in e["presets"]:
                reason = (
                    f"not in preset {preset!r}"
                    f" (inference risk {e['inference_risk']}"
                    f"{'; ' + e['risk_note'] if 'risk_note' in e else ''})"
                )
            else:  # pragma: no cover — defensive; renderable_ids covers the rest
                reason = "not renderable"
            excluded.append({"id": eid, "reason": reason})
        return {
            "registry_version": self.version,
            "registry_digest": self.digest(),
            "preset": preset,
            "included": included,
            "excluded": excluded,
            "rejected": [dict(r) for r in self._doc["rejected"]],
        }

    # -- the claims bridge ----------------------------------------------------------

    def check_claim(self, claim: dict) -> None:
        """Registry conformance for one (already envelope-validated) claim:
        the seam MYB-10.1 left open. Raises RegistryError."""
        entry = self.entry(claim["registry_id"])
        if entry["status"] != "active":
            raise RegistryError(
                f"{claim['registry_id']} is reserved — no claims may cite it yet"
            )
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
        errors = sorted(
            jsonschema.Draft202012Validator(entry["output_schema"]).iter_errors(
                claim["output"]
            ),
            key=str,
        )
        if errors:
            raise RegistryError(
                f"{claim['registry_id']}: output does not conform to the registry entry: "
                f"{errors[0].message}"
            )
