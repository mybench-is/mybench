"""Static report page renderer (MYB-5.2).

A deterministic function of the report JSON: same input ⇒ byte-identical
page. Whitelist rendering, the strict way: the input is validated against
report schema v1 BEFORE rendering, so an unknown field fails the build —
nothing can silently pass through to a public page. Every interpolated
value is HTML-escaped; the page contains zero JavaScript and fetches
nothing at runtime (the only external reference is the anchors-repo link) —
a skeptic can read the source.
"""

from __future__ import annotations

import html

from mybench.report.descriptions import GLOSSARY, INTRO, METRIC_DESCRIPTIONS
from mybench.schemas import load_validator

TIER_COLORS = {"PROVEN": "#1a7f37", "ANCHORED": "#9a6700", "JUDGED": "#57606a"}

TIER_LEGEND = (
    ("PROVEN", "verifiable from public artifacts and open code alone — no trust required"),
    ("ANCHORED", "timing/volume cryptographically anchored; content-derived facts asserted "
                 "by the owner, spot-checkable via selective disclosure"),
    ("JUDGED", "reproducible model opinion — out of scope in v0; no metric carries it"),
)

_CSS = """
body{font-family:system-ui,sans-serif;max-width:56rem;margin:2rem auto;padding:0 1rem;
color:#1f2328;line-height:1.5}
h1{margin-bottom:.2rem} .sub{color:#57606a;font-size:.9rem}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid #d0d7de;vertical-align:top}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:.8rem;color:#fff;
font-size:.75rem;font-weight:600}
.dist{font-size:.85rem;color:#57606a} .caveat{font-size:.85rem;color:#9a6700}
.desc{font-size:.85rem;color:#57606a;max-width:28rem}
code,pre{background:#f6f8fa;border-radius:.3rem} pre{padding:.8rem;overflow-x:auto}
code{padding:.1rem .3rem} footer{color:#57606a;font-size:.8rem;margin-top:2rem}
"""


class PageError(ValueError):
    pass


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _badge(tier: str) -> str:
    return f'<span class="badge" style="background:{TIER_COLORS[tier]}">{_esc(tier)}</span>'


def _value_html(value) -> str:
    if isinstance(value, int | float):
        return f"<strong>{_esc(value)}</strong>"
    rows = "".join(
        f"<div>{_esc(label)}: <strong>{_esc(count)}</strong></div>"
        for label, count in value.items()
    )
    return f'<div class="dist">{rows}</div>'


def _metric_row(metric: dict) -> str:
    if metric["name"] not in METRIC_DESCRIPTIONS:
        # Whitelist discipline, inverted: nothing ships unexplained (MYB-5.5).
        raise PageError(f"metric {metric['name']!r} has no plain-language description")
    name = _esc(metric["name"].replace("_", " "))
    desc = f'<div class="desc">{_esc(METRIC_DESCRIPTIONS[metric["name"]])}</div>'
    caveat = (
        f'<div class="caveat">{_esc(metric["caveat"])}</div>' if "caveat" in metric else ""
    )
    return (
        f"<tr><td>{name}{desc}{caveat}</td>"
        f"<td>{_value_html(metric['value'])}</td>"
        f"<td>{_badge(metric['trust_tier'])}</td></tr>"
    )


def render_page(report: dict, *, anchors_url: str) -> bytes:
    """Validate strictly, then render. Raises PageError on any schema violation."""
    errors = sorted(load_validator("report.schema.json").iter_errors(report), key=str)
    if errors:
        raise PageError(f"refusing to render a non-conforming report: {errors[0].message}")

    metric_rows = "".join(_metric_row(m) for m in report["metrics"])
    legend = "".join(
        f"<tr><td>{_badge(tier)}</td><td>{_esc(text)}</td></tr>" for tier, text in TIER_LEGEND
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

    glossary_rows = "".join(
        f"<tr><td><strong>{_esc(term)}</strong></td><td>{_esc(text)}</td></tr>"
        for term, text in GLOSSARY
    )
    quickstart = (
        "python -m venv .venv && . .venv/bin/activate\n"
        "pip install -e .   # from the mybench source repo\n"
        f"python -m mybench.verify {anchors_url}"
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mybench report</title><style>{_CSS}</style></head><body>
<h1>mybench activity report</h1>
<p class="sub">report {_esc(report["report_version"])} · schema {_esc(report["schema_version"])}
· scorer {_esc(report["scorer_version"])} · generated {_esc(report["generated_at"])}</p>
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
<pre>{_esc(quickstart)}</pre>
<p>The verifier checks anchor schema and device signatures, chain continuity
(no gaps or rewrites), and OpenTimestamps proofs against Bitcoin block
headers cross-checked via two independent explorers. It needs no trust in
the report&#x27;s author and reads none of their private data.</p>
<footer>Generated by the open-source mybench scorer as a deterministic
function of the local ledger. No transcript content, prompt text, code, or
filenames appear on this page or anywhere in the anchors repo — only salted
commitments, Merkle roots, timestamps, and the aggregates above.</footer>
</body></html>
""".encode()
