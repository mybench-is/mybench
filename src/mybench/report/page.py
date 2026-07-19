"""Static validate-then-render report page (MYB-5.x, MYB-10.9).

A deterministic function of the report JSON: same input ⇒ byte-identical
page. Whitelist rendering, the strict way: the input is validated against
the matching report schema BEFORE rendering, so an unknown field fails the build, and
a metric without a plain-language description fails the build. Every
interpolated value is HTML-escaped; the page contains zero JavaScript; its
only external references are mybench.is URLs (ADR-0005: the domain is the
URL trust root — GitHub locations are movable implementation details).

Backfill honesty (handoff #6): when anchored_span_days is below
BACKFILL_FLOOR_DAYS, capture-time metric cells are annotated in-cell and
the weekly distribution is flagged as reflecting the import event. The
floor value is OQ #18 (owner-proposed 14; adjust there, not ad hoc).

The hallmark stamp here is the bare die+pins geometry only — deliberately
WITHOUT the `mb` letters, because BRAND §1 forbids shipping raw font
renders; MYB-5.7's outlined-path mark replaces it. Never filled, never
foil (§1.2: those registers require cryptographically-true TEE claims).

Schema-v2 fields pass a second registry-conformance gate before rendering.
The page is the same zero-JavaScript local report surface, not a publication
route. Public projection remains owned by MYB-14.1 and is refused here.
"""

from __future__ import annotations

import copy
import hashlib
import html
import re
from collections.abc import Collection, Sequence
from datetime import date

from mybench.claims import ClaimError, canonical_bytes, verify_claim
from mybench.registry import Registry, RegistryError
from mybench.report.descriptions import GLOSSARY, INTRO, METRIC_DESCRIPTIONS
from mybench.schemas import load_validator

ROOT_URL = "https://mybench.is"
BACKFILL_FLOOR_DAYS = 14  # OQ #18 — owner-proposed; change there, not here
CAPTURE_TIME_METRICS = {"ledger_span_days", "active_days", "sessions_total"}

# ADR-0014/0015: tier is label + geometry, never provider/substrate or rank color.
TIER_LEGEND = (
    (
        "IMPORTED",
        "history captured by backfill — anchored as of capture time, the weakest "
        "provenance; shown as an annotation, not a metric label, in v0",
    ),
    (
        "ANCHORED",
        "timing/volume cryptographically anchored; content-derived facts asserted "
        "by the owner, spot-checkable via selective disclosure",
    ),
    ("PROVEN", "verifiable from public artifacts and open code alone — no trust required"),
    (
        "TEE-VERIFIED",
        "deterministic measured claim with verified execution-environment "
        "attestation — unreachable until its evidence schema activates",
    ),
    (
        "JUDGED",
        "reproducible canonical-judge opinion; unattested/attested qualifiers are "
        "reserved until the judge taxonomy activates",
    ),
)

SECTION_TITLES = {
    "workflow_summary": "Workflow summary",
    "workflow_map": "Workflow map",
    "model_role_profile": "Model role profile",
    "context_management_profile": "Context management profile",
    "orchestration_topology": "Orchestration topology",
    "token_cost_profile": "Token and cost profile",
    "evidence_coverage": "Evidence coverage",
}

STAMP_SVG = (  # outlined-path 3-pin mark — assets/brand/generate_marks.py
    '<svg class="stamp" aria-hidden="true" viewBox="0 0 60 68" xmlns="http://www.w3.org/2000/svg" fill="none"><rect x="8" y="12" width="44" height="44" rx="5" stroke="currentColor" stroke-width="2.5"/><line x1="18" y1="5" x2="18" y2="12" stroke="currentColor" stroke-width="2"/><line x1="18" y1="56" x2="18" y2="63" stroke="currentColor" stroke-width="2"/><line x1="30" y1="5" x2="30" y2="12" stroke="currentColor" stroke-width="2"/><line x1="30" y1="56" x2="30" y2="63" stroke="currentColor" stroke-width="2"/><line x1="42" y1="5" x2="42" y2="12" stroke="currentColor" stroke-width="2"/><line x1="42" y1="56" x2="42" y2="63" stroke="currentColor" stroke-width="2"/><g fill="currentColor" stroke="currentColor" stroke-width="0.4" transform="translate(17.40,39.46) scale(0.02100,-0.02100)"><path d="M30 0V516H149V440H156Q168 476 190.5 502.0Q213 528 254 528Q329 528 346 440H352Q358 458 367.0 474.0Q376 490 389.0 502.0Q402 514 420.0 521.0Q438 528 462 528Q570 528 570 369V0H451V354Q451 390 438.5 404.5Q426 419 406 419Q387 419 373.5 406.5Q360 394 360 368V0H240V354Q240 390 228.5 404.5Q217 419 197 419Q177 419 163.0 406.5Q149 394 149 368V0Z"/><path transform="translate(600,0)" d="M59 740H207V422H214Q233 468 269.0 498.0Q305 528 367 528Q410 528 445.5 512.0Q481 496 506.5 463.0Q532 430 546.5 379.0Q561 328 561 258Q561 188 546.5 137.0Q532 86 506.5 53.0Q481 20 445.5 4.0Q410 -12 367 -12Q305 -12 269.0 17.5Q233 47 214 94H207V0H59ZM303 103Q353 103 380.0 133.5Q407 164 407 218V298Q407 352 380.0 382.5Q353 413 303 413Q264 413 235.5 394.0Q207 375 207 334V182Q207 141 235.5 122.0Q264 103 303 103Z"/></g></svg>'
)

_CSS = """
:root{
  --ink:#171A19; --paper:#F2EFE7;
  --accent-display:#4FA095; --accent-text:#2E6B62; --accent-tint:#DCEFEA;
  --rule:#D8D4C8; --muted:#5c615e;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
}
html[data-theme="dark"]{--ink:#F2EFE7;--paper:#171A19;--accent-display:#78BDB3;
--accent-text:#9BD2CA;--accent-tint:#243E3A;--rule:#4B514E;--muted:#B7BDB9}
@media(prefers-color-scheme:dark){html[data-theme="auto"]{--ink:#F2EFE7;--paper:#171A19;
--accent-display:#78BDB3;--accent-text:#9BD2CA;--accent-tint:#243E3A;
--rule:#4B514E;--muted:#B7BDB9}}
body{font-family:Inter,system-ui,sans-serif;background:var(--paper);color:var(--ink);
max-width:56rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
h1{margin-bottom:.2rem} a{color:var(--accent-text)}
.sub{color:var(--muted);font-size:.9rem;font-family:var(--mono)}
.stamp{width:2.2rem;height:2.5rem;vertical-align:middle;margin-right:.5rem;
color:var(--accent-display)}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--rule);
vertical-align:top}
strong,.dist,.badge,.claim-pill,.confidence{font-family:var(--mono)}
.badge{display:inline-block;padding:.12rem .48rem;color:var(--ink);background:transparent;
font-size:.72rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.tier--imported,.tier--judged{border:1px solid currentColor}
.tier--anchored{border:3px double currentColor}
.tier--proven{border:3px double currentColor;box-shadow:inset 0 0 0 2px var(--paper)}
.tier--tee-verified{border:4px double currentColor;background:var(--ink);color:var(--paper)}
.tier--characterization{border:1px solid currentColor;box-shadow:none;background:transparent;
color:var(--ink)}
.dist{font-size:.85rem;color:var(--muted)} .caveat{font-size:.85rem;color:var(--accent-text)}
.desc{font-size:.85rem;color:var(--muted);max-width:28rem}
.note{font-size:.8rem;color:var(--accent-text);font-style:italic}
.environment{border-left:3px double currentColor;padding:.45rem .7rem;font-family:var(--mono)}
.fingerprint-grid{display:grid;gap:.8rem}.fingerprint-section{border-top:1px solid var(--rule)}
.section-status{font-family:var(--mono);font-size:.78rem;color:var(--muted)}
.claim{padding:.7rem;margin:.55rem 0}
.claim-head{display:flex;gap:.45rem;align-items:center;flex-wrap:wrap}
.claim-title{margin-right:auto}.claim-pill{font-size:.7rem;padding:.08rem .4rem;
border:1px solid currentColor;background:var(--accent-tint)}
.confidence{font-size:.72rem}.claim-meta{font-size:.76rem;color:var(--muted);
font-family:var(--mono)}
code,pre{background:var(--accent-tint);border-radius:.3rem;font-family:var(--mono)}
pre{padding:.8rem;overflow-x:auto} code{padding:.1rem .3rem}
footer{color:var(--muted);font-size:.8rem;margin-top:2rem}
details{margin:.5rem 0} summary{cursor:pointer;color:var(--muted);font-size:.9rem}
"""


class PageError(ValueError):
    pass


class ClaimBindingError(ValueError):
    """A report-v2 field is not exactly backed by trusted signed evidence."""


def _verify_report_claims(
    fields: Sequence[tuple[str, dict]],
    signed_claims: Sequence[dict] | None,
    *,
    registry: Registry,
    trusted_device_pubs: Collection[str] | None,
) -> dict[str, dict]:
    """Verify and exactly bind all and only the signed claims a report renders."""
    if signed_claims is None:
        raise ClaimBindingError("report-v2 fields require signed claim envelopes")
    if not isinstance(signed_claims, Sequence) or isinstance(
        signed_claims, str | bytes | bytearray
    ):
        raise ClaimBindingError("signed claim envelopes must be a sequence")

    claims_by_digest: dict[str, dict] = {}
    try:
        for claim in signed_claims:
            claim_snapshot = copy.deepcopy(claim)
            signer = verify_claim(claim_snapshot, trusted_device_pubs=trusted_device_pubs)
            if signer["kind"] == "device" and trusted_device_pubs is None:
                raise ClaimBindingError(
                    "device-signed report claims require an explicit trusted-device binding"
                )
            if signer["kind"] == "dev" and claim_snapshot["execution_env"] != "local-unattested":
                raise ClaimBindingError("development claims are limited to the local lane")
            digest = hashlib.sha256(canonical_bytes(claim_snapshot)).hexdigest()
            if digest in claims_by_digest:
                raise ClaimBindingError("duplicate signed claim envelope")
            claims_by_digest[digest] = claim_snapshot
    except (ClaimError, KeyError, TypeError) as exc:
        # Claim inputs can carry local-only references. Never reflect a
        # validator message (which may quote an offending value) into logs.
        raise ClaimBindingError("signed claim verification failed") from exc

    expected_digests = [field["claim_digest"] for _location, field in fields]
    if len(set(expected_digests)) != len(expected_digests):
        raise ClaimBindingError("report-v2 fields must reference unique signed claims")
    if set(expected_digests) != set(claims_by_digest):
        raise ClaimBindingError("report-v2 claim envelopes do not exactly match field digests")

    entries: dict[str, dict] = {}
    try:
        for location, field in fields:
            claim = claims_by_digest[field["claim_digest"]]
            entries[field["registry_id"]] = registry.check_report_claim(field, location, claim)
    except (KeyError, RegistryError) as exc:
        raise ClaimBindingError(f"signed claim does not match report field: {exc}") from exc
    return entries


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _pretty_bucket(label: str) -> str:
    """Strip the sortable zero-padding for humans: 0011-0100 -> 11-100."""
    if re.match(r"^\d{2}_", label):
        label = label[3:]
    return re.sub(r"\b0+(\d)", r"\1", label).replace("_", " ")


def _badge(tier: str, *, characterization: bool = False, qualifier: str | None = None) -> str:
    geometry = "characterization" if characterization else tier.lower()
    label = f"{tier}({qualifier})" if qualifier else tier
    return f'<span class="badge tier--{_esc(geometry)}">{_esc(label)}</span>'


def _value_html(value) -> str:
    if isinstance(value, bool):
        return f"<strong>{'yes' if value else 'no'}</strong>"
    if isinstance(value, int | float):
        return f"<strong>{_esc(value)}</strong>"
    if isinstance(value, str):
        return f"<strong>{_esc(value)}</strong>"
    if isinstance(value, list):
        rows = "".join(
            "<div>"
            f"{_esc(' / '.join(cell['dimensions']))}: "
            f"<strong>{_esc(_pretty_bucket(str(cell['value'])))}</strong>"
            "</div>"
            for cell in value
        )
        return f'<div class="dist">{rows}</div>'
    rows = "".join(
        f"<div>{_esc(_pretty_bucket(label))}: <strong>{_esc(count)}</strong></div>"
        for label, count in value.items()
    )
    return f'<div class="dist">{rows}</div>'


def _field_locations(report: dict):
    for field in report["catalog_metrics"]:
        yield "catalog_metrics", field
    for section_name, section in report["fingerprint"].items():
        for field in section["fields"]:
            yield f"fingerprint.{section_name}", field


def _validate_v2_registry(
    report: dict,
    registry: Registry,
    signed_claims: Sequence[dict] | None,
    trusted_device_pubs: Collection[str] | None,
) -> dict[str, dict]:
    identity = report["registry"]
    if identity != {"version": registry.version, "digest": registry.digest()}:
        raise PageError("refusing to render report with an unpinned registry identity")
    if report["evidence_period"]["start"] > report["evidence_period"]["end"]:
        raise PageError("refusing to render a reversed evidence period")

    fields = list(_field_locations(report))
    groups = [report["catalog_metrics"], *(s["fields"] for s in report["fingerprint"].values())]
    for group in groups:
        order = [
            (field["registry_id"], field["registry_version"], field["claim_digest"])
            for field in group
        ]
        if order != sorted(order):
            raise PageError("report-v2 fields must be sorted within each section")
    if len({field["registry_id"] for _, field in fields}) != len(fields):
        raise PageError("report-v2 fields must be sorted and unique by registry id")

    try:
        return _verify_report_claims(
            fields,
            signed_claims,
            registry=registry,
            trusted_device_pubs=trusted_device_pubs,
        )
    except (ClaimBindingError, KeyError, RegistryError) as exc:
        raise PageError(f"refusing a registry-nonconforming report: {exc}") from exc


def _validate_report(
    report: dict,
    registry: Registry | None,
    signed_claims: Sequence[dict] | None,
    trusted_device_pubs: Collection[str] | None,
) -> tuple[str, dict[str, dict]]:
    schema_version = report.get("schema_version") if isinstance(report, dict) else None
    schema_name = {"1": "report.schema.json", "2": "report-v2.schema.json"}.get(schema_version)
    if schema_name is None:
        raise PageError("refusing to render an unsupported report schema")
    errors = sorted(load_validator(schema_name).iter_errors(report), key=str)
    if errors:
        raise PageError(f"refusing to render a non-conforming report: {errors[0].message}")
    if schema_version == "2":
        return schema_version, _validate_v2_registry(
            report,
            registry or Registry.load(),
            signed_claims,
            trusted_device_pubs,
        )
    return schema_version, {}


def _iso_week(generated_at: str) -> str:
    y, w, _ = date.fromisoformat(generated_at[:10]).isocalendar()
    return f"{y}-W{w:02d}"


def _metric_row(metric: dict, backfill_dominated: bool) -> str:
    if metric["name"] not in METRIC_DESCRIPTIONS:
        raise PageError(f"metric {metric['name']!r} has no plain-language description")
    name = _esc(metric["name"].replace("_", " "))
    desc = f'<div class="desc">{_esc(METRIC_DESCRIPTIONS[metric["name"]])}</div>'
    caveat = f'<div class="caveat">{_esc(metric["caveat"])}</div>' if "caveat" in metric else ""
    value = _value_html(metric["value"])
    if backfill_dominated and metric["name"] in CAPTURE_TIME_METRICS:
        value += ' <span class="note">· backfilled</span>'
    if backfill_dominated and metric["name"] == "sessions_per_week_distribution":
        value += '<div class="note">reflects the history-import event, not working cadence</div>'
    return (
        f"<tr><td>{name}{desc}{caveat}</td><td>{value}</td>"
        f"<td>{_badge(metric['trust_tier'])}</td></tr>"
    )


def _claim_html(field: dict, entry: dict) -> str:
    characterization = field["derivation_class"] == "characterization"
    description = f'<div class="desc">{_esc(entry["neutrality_note"])}</div>'
    confidence = (
        f'<span class="confidence">confidence {_esc(field["confidence"])}</span>'
        if characterization
        else ""
    )
    caveats = "".join(
        f'<div class="caveat">{_esc(entry["caveat_copy"][code])}</div>'
        for code in field.get("caveats", ())
    )
    coverage = field["coverage_basis_points"]
    if coverage == "UNKNOWN":
        coverage_text = "unknown"
    else:
        whole, fractional = divmod(coverage, 100)
        coverage_text = f"{whole}.{fractional:02d}".rstrip("0").rstrip(".") + "%"
    return (
        f'<article class="claim tier--{"characterization" if characterization else field["trust_tier"].lower()}">'
        '<div class="claim-head">'
        f'<strong class="claim-title">{_esc(entry["title"])}</strong>'
        f'<span class="claim-pill">{_esc(field["derivation_class"].upper())}</span>'
        f"{confidence}{_badge(field['trust_tier'], characterization=characterization, qualifier=field.get('tier_qualifier'))}"
        "</div>"
        f"{description}{_value_html(field['value'])}"
        '<div class="claim-meta">'
        f"coverage {_esc(coverage_text)} · anchor {_esc(field['anchor_state'])} · "
        f"risk {_esc(field['inference_risk'])} · {_esc(field['disclosure'])}"
        "</div>"
        f"{caveats}</article>"
    )


def _environment_notice(report: dict) -> str:
    environments = sorted({field["execution_env"] for _, field in _field_locations(report)})
    if not environments:
        text = "no claim execution environment available"
    elif environments == ["local-unattested"]:
        text = "computed locally — unattested"
    elif environments == ["tee-attested"]:
        text = "computed in an attested execution environment"
    else:
        text = "mixed execution environments — inspect each tier label"
    return f'<p class="environment" data-environments="{_esc(" ".join(environments))}">{text}</p>'


def _fingerprint_html(report: dict, entries: dict[str, dict]) -> str:
    sections = []
    for name, title in SECTION_TITLES.items():
        section = report["fingerprint"][name]
        fields = "".join(
            _claim_html(field, entries[field["registry_id"]]) for field in section["fields"]
        )
        sections.append(
            f'<section class="fingerprint-section" data-section="{_esc(name)}">'
            f"<h3>{_esc(title)}</h3>"
            f'<p class="section-status">{_esc(section["status"])}</p>{fields}</section>'
        )
    catalog = "".join(
        _claim_html(field, entries[field["registry_id"]]) for field in report["catalog_metrics"]
    )
    catalog_html = (
        '<section class="fingerprint-section" data-section="catalog_metrics">'
        "<h3>Additional catalog metrics</h3>"
        f"{catalog}</section>"
        if catalog
        else ""
    )
    return (
        f"{_environment_notice(report)}<h2>Workflow fingerprint</h2>"
        f'<div class="fingerprint-grid">{"".join(sections)}{catalog_html}</div>'
    )


def render_page(
    report: dict,
    *,
    anchors_url: str = f"{ROOT_URL}/anchors",
    handle: str | None = None,
    report_json_href: str = "report.json",
    registry: Registry | None = None,
    signed_claims: Sequence[dict] | None = None,
    trusted_device_pubs: Collection[str] | None = None,
    public: bool = False,
    theme: str = "auto",
) -> bytes:
    """Validate strictly, then render the one local/static report surface."""
    schema_version, entries = _validate_report(report, registry, signed_claims, trusted_device_pubs)
    if public and schema_version == "2":
        raise PageError(
            "public fingerprint rendering is unavailable; use the separately gated preview"
        )
    if theme not in {"auto", "light", "dark"}:
        raise PageError("unknown report theme")

    anchored_span = next(
        (m["value"] for m in report["metrics"] if m["name"] == "anchored_span_days"), None
    )
    backfill_dominated = anchored_span is not None and anchored_span < BACKFILL_FLOOR_DAYS

    metric_rows = "".join(_metric_row(m, backfill_dominated) for m in report["metrics"])
    fingerprint = _fingerprint_html(report, entries) if schema_version == "2" else ""
    legend = "".join(
        f"<tr><td>{_badge(tier)}</td><td>{_esc(text)}</td></tr>" for tier, text in TIER_LEGEND
    )
    glossary_rows = "".join(
        f"<tr><td><strong>{_esc(term)}</strong></td><td>{_esc(text)}</td></tr>"
        for term, text in GLOSSARY
    )
    tips = report.get("binding_tips", {})
    tips_html = ""
    if tips:
        tip_rows = "".join(
            f"<tr><td><code>{_esc(repo)}</code></td><td><code>{_esc(tip)}</code></td></tr>"
            for repo, tip in sorted(tips.items())
        )
        tips_html = (
            "<h2>Enrolled repos (binding coverage pinned at)</h2>"
            f"<table><tr><th>repo</th><th>tip commit</th></tr>{tip_rows}</table>"
        )

    who = f"@{_esc(handle)} · " if handle else ""
    input_versions = report.get("input_schema_versions", {})
    ledger_versions = "/".join(input_versions.get("ledger", ())) or "none"
    anchor_versions = "/".join(input_versions.get("anchor", ())) or "none"
    input_version_html = ""
    if input_versions:
        input_version_html = (
            f" · input schemas ledger {_esc(ledger_versions)}, anchor {_esc(anchor_versions)}"
        )
    anchored_through = report.get("anchored_through")
    freshness_html = (
        f'<p class="sub">anchored through {_esc(anchored_through)}</p>'
        if anchored_through
        else '<p class="sub">not yet anchored</p>'
    )
    canonical = ""
    og_url = ROOT_URL
    if handle:
        og_url = f"{ROOT_URL}/@{handle}/{_iso_week(report['generated_at'])}"
        canonical = f'\n<link rel="canonical" href="{_esc(og_url)}">'
    title = f"mybench report — @{handle}" if handle else "mybench report"

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="{_esc(theme)}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>{canonical}
<meta property="og:title" content="{_esc(title)}">
<meta property="og:description" content="Verifiable proof of agentic skill — anchored sessions, open scorer, honest trust tiers.">
<meta property="og:image" content="{ROOT_URL}/og.png">
<meta property="og:url" content="{_esc(og_url)}">
<meta name="twitter:card" content="summary_large_image">
<style>{_CSS}</style></head><body>
<h1>{STAMP_SVG}mybench activity report</h1>
<p class="sub">{who}report {_esc(report["report_version"])} · schema {_esc(report["schema_version"])}
· scorer {_esc(report["scorer_version"])} · generated {_esc(report["generated_at"])}
{input_version_html} · <a href="{_esc(report_json_href)}">machine-readable report</a></p>
{freshness_html}
<p>{_esc(INTRO)}</p>
<p class="caveat">{_esc(report.get("backfill_note", ""))}</p>
{fingerprint}
<h2>Metrics</h2>
<table><tr><th>metric</th><th>value</th><th>trust tier</th></tr>{metric_rows}</table>
{tips_html}
<h2>Trust tiers</h2>
<table>{legend}</table>
<h2>Glossary</h2>
<table>{glossary_rows}</table>
<h2>Verify this yourself</h2>
<p>Anchors: <a href="{_esc(anchors_url)}">{_esc(anchors_url)}</a></p>
<pre>uvx mybench-verify {_esc(anchors_url)}</pre>
<details><summary>without uv</summary>
<pre>python -m venv .venv &amp;&amp; . .venv/bin/activate
pip install mybench
python -m mybench.verify {_esc(anchors_url)}</pre></details>
<p>The verifier checks anchor schema and signatures, the identity chain
(genesis self-certification, handle and device bindings), chain continuity
(no gaps or rewrites), and OpenTimestamps proofs against Bitcoin block
headers cross-checked via two independent explorers. It needs no trust in
the report&#x27;s author and reads none of their private data.</p>
<footer>Generated by the open-source mybench scorer as a deterministic
function of the local ledger. No transcript content, prompt text, code, or
filenames appear on this page or anywhere in the anchors log — only salted
commitments, Merkle roots, timestamps, and the aggregates above.
· <a href="{ROOT_URL}/how-it-works">how anchoring works</a>
· <a href="{ROOT_URL}">{_esc(ROOT_URL.removeprefix("https://"))}</a></footer>
</body></html>
""".encode()
