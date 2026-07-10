"""Static report page renderer v1 (MYB-5.2/5.5/5.8).

A deterministic function of the report JSON: same input ⇒ byte-identical
page. Whitelist rendering, the strict way: the input is validated against
report schema v1 BEFORE rendering, so an unknown field fails the build, and
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
"""

from __future__ import annotations

import html
import re
from datetime import date

from mybench.report.descriptions import GLOSSARY, INTRO, METRIC_DESCRIPTIONS
from mybench.schemas import load_validator

ROOT_URL = "https://mybench.is"
BACKFILL_FLOOR_DAYS = 14  # OQ #18 — owner-proposed; change there, not here
CAPTURE_TIME_METRICS = {"ledger_span_days", "active_days", "sessions_total"}

TIER_COLORS = {"PROVEN": "#1a7f37", "ANCHORED": "#9a6700", "JUDGED": "#57606a",
               "IMPORTED": "#57606a", "TEE-VERIFIED": "#57606a"}

# Handoff #5: the full five-rung ladder, unused rungs marked. Colored pills
# pending OQ #19 (geometry vs color) — do not restyle silently.
TIER_LEGEND = (
    ("IMPORTED", "history captured by backfill — anchored as of capture time, the weakest "
                 "provenance; shown as an annotation, not a metric label, in v0"),
    ("ANCHORED", "timing/volume cryptographically anchored; content-derived facts asserted "
                 "by the owner, spot-checkable via selective disclosure"),
    ("PROVEN", "verifiable from public artifacts and open code alone — no trust required"),
    ("TEE-VERIFIED", "judged inside attested hardware — not in scope in v0"),
    ("JUDGED", "reproducible model opinion — not in scope in v0; no metric carries it"),
)

STAMP_SVG = (  # outlined-path 3-pin mark — assets/brand/generate_marks.py
    '<svg class="stamp" aria-hidden="true" viewBox="0 0 60 68" xmlns="http://www.w3.org/2000/svg" fill="none"><rect x="8" y="12" width="44" height="44" rx="5" stroke="currentColor" stroke-width="2.5"/><line x1="18" y1="5" x2="18" y2="12" stroke="currentColor" stroke-width="2"/><line x1="18" y1="56" x2="18" y2="63" stroke="currentColor" stroke-width="2"/><line x1="30" y1="5" x2="30" y2="12" stroke="currentColor" stroke-width="2"/><line x1="30" y1="56" x2="30" y2="63" stroke="currentColor" stroke-width="2"/><line x1="42" y1="5" x2="42" y2="12" stroke="currentColor" stroke-width="2"/><line x1="42" y1="56" x2="42" y2="63" stroke="currentColor" stroke-width="2"/><g fill="currentColor" stroke="currentColor" stroke-width="0.4" transform="translate(17.40,39.46) scale(0.02100,-0.02100)"><path d="M30 0V516H149V440H156Q168 476 190.5 502.0Q213 528 254 528Q329 528 346 440H352Q358 458 367.0 474.0Q376 490 389.0 502.0Q402 514 420.0 521.0Q438 528 462 528Q570 528 570 369V0H451V354Q451 390 438.5 404.5Q426 419 406 419Q387 419 373.5 406.5Q360 394 360 368V0H240V354Q240 390 228.5 404.5Q217 419 197 419Q177 419 163.0 406.5Q149 394 149 368V0Z"/><path transform="translate(600,0)" d="M59 740H207V422H214Q233 468 269.0 498.0Q305 528 367 528Q410 528 445.5 512.0Q481 496 506.5 463.0Q532 430 546.5 379.0Q561 328 561 258Q561 188 546.5 137.0Q532 86 506.5 53.0Q481 20 445.5 4.0Q410 -12 367 -12Q305 -12 269.0 17.5Q233 47 214 94H207V0H59ZM303 103Q353 103 380.0 133.5Q407 164 407 218V298Q407 352 380.0 382.5Q353 413 303 413Q264 413 235.5 394.0Q207 375 207 334V182Q207 141 235.5 122.0Q264 103 303 103Z"/></g></svg>'
)

_CSS = """
:root{
  /* BRAND §3 tokens — no surface references a hex directly below this block */
  --ink:#171A19; --paper:#F2EFE7;
  --accent-display:#4FA095; --accent-text:#2E6B62; --accent-tint:#DCEFEA;
  --rule:#D8D4C8; --muted:#5c615e;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
}
/* A certificate is a document (BRAND §3.3): paper regardless of app theme. */
body{font-family:Inter,system-ui,sans-serif;background:var(--paper);color:var(--ink);
max-width:56rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
h1{margin-bottom:.2rem} a{color:var(--accent-text)}
.sub{color:var(--muted);font-size:.9rem;font-family:var(--mono)}
.stamp{width:2.2rem;height:2.5rem;vertical-align:middle;margin-right:.5rem;
color:var(--accent-display)}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--rule);
vertical-align:top}
strong,.dist,.badge{font-family:var(--mono)}  /* evidence is monospace (§4) */
.badge{display:inline-block;padding:.1rem .5rem;border-radius:.8rem;color:var(--paper);
font-size:.75rem;font-weight:600;letter-spacing:.03em}
.dist{font-size:.85rem;color:var(--muted)} .caveat{font-size:.85rem;color:#9a6700}
.desc{font-size:.85rem;color:var(--muted);max-width:28rem}
.note{font-size:.8rem;color:#9a6700;font-style:italic}
code,pre{background:var(--accent-tint);border-radius:.3rem;font-family:var(--mono)}
pre{padding:.8rem;overflow-x:auto} code{padding:.1rem .3rem}
footer{color:var(--muted);font-size:.8rem;margin-top:2rem}
details{margin:.5rem 0} summary{cursor:pointer;color:var(--muted);font-size:.9rem}
"""

class PageError(ValueError):
    pass


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _pretty_bucket(label: str) -> str:
    """Strip the sortable zero-padding for humans: 0011-0100 -> 11-100."""
    return re.sub(r"\b0+(\d)", r"\1", label)


def _badge(tier: str) -> str:
    return f'<span class="badge" style="background:{TIER_COLORS[tier]}">{_esc(tier)}</span>'


def _value_html(value) -> str:
    if isinstance(value, int | float):
        return f"<strong>{_esc(value)}</strong>"
    rows = "".join(
        f"<div>{_esc(_pretty_bucket(label))}: <strong>{_esc(count)}</strong></div>"
        for label, count in value.items()
    )
    return f'<div class="dist">{rows}</div>'


def _iso_week(generated_at: str) -> str:
    y, w, _ = date.fromisoformat(generated_at[:10]).isocalendar()
    return f"{y}-W{w:02d}"


def _metric_row(metric: dict, backfill_dominated: bool) -> str:
    if metric["name"] not in METRIC_DESCRIPTIONS:
        raise PageError(f"metric {metric['name']!r} has no plain-language description")
    name = _esc(metric["name"].replace("_", " "))
    desc = f'<div class="desc">{_esc(METRIC_DESCRIPTIONS[metric["name"]])}</div>'
    caveat = (
        f'<div class="caveat">{_esc(metric["caveat"])}</div>' if "caveat" in metric else ""
    )
    value = _value_html(metric["value"])
    if backfill_dominated and metric["name"] in CAPTURE_TIME_METRICS:
        value += ' <span class="note">· backfilled</span>'
    if backfill_dominated and metric["name"] == "sessions_per_week_distribution":
        value += ('<div class="note">reflects the history-import event, '
                  "not working cadence</div>")
    return (
        f"<tr><td>{name}{desc}{caveat}</td><td>{value}</td>"
        f"<td>{_badge(metric['trust_tier'])}</td></tr>"
    )


def render_page(report: dict, *, anchors_url: str = f"{ROOT_URL}/anchors",
                handle: str | None = None, report_json_href: str = "report.json") -> bytes:
    """Validate strictly, then render. Raises PageError on any schema violation."""
    errors = sorted(load_validator("report.schema.json").iter_errors(report), key=str)
    if errors:
        raise PageError(f"refusing to render a non-conforming report: {errors[0].message}")

    anchored_span = next(
        (m["value"] for m in report["metrics"] if m["name"] == "anchored_span_days"), None
    )
    backfill_dominated = anchored_span is not None and anchored_span < BACKFILL_FLOOR_DAYS

    metric_rows = "".join(_metric_row(m, backfill_dominated) for m in report["metrics"])
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
    canonical = ""
    og_url = ROOT_URL
    if handle:
        og_url = f"{ROOT_URL}/@{handle}/{_iso_week(report['generated_at'])}"
        canonical = f'\n<link rel="canonical" href="{_esc(og_url)}">'
    title = f"mybench report — @{handle}" if handle else "mybench report"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>{canonical}
<meta property="og:title" content="{_esc(title)}">
<meta property="og:description" content="Verifiable proof of agentic skill — anchored sessions, open scorer, honest trust tiers.">
<meta property="og:image" content="{ROOT_URL}/og.png">
<meta property="og:url" content="{_esc(og_url)}">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="favicon.svg">
<style>{_CSS}</style></head><body>
<h1>{STAMP_SVG}mybench activity report</h1>
<p class="sub">{who}report {_esc(report["report_version"])} · schema {_esc(report["schema_version"])}
· scorer {_esc(report["scorer_version"])} · generated {_esc(report["generated_at"])}
· <a href="{_esc(report_json_href)}">machine-readable report</a></p>
<p>{_esc(INTRO)}</p>
<p class="caveat">{_esc(report.get("backfill_note", ""))}</p>
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
