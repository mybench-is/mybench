"""Generate the brand/social asset set (BRAND.md §10 + SOCIAL.md) — MYB-5.7.

Usage:
    python assets/brand/generate_assets.py <PlexMonoBold.ttf> \
        <MartianMonoMedium.ttf> <PlexMonoRegular.ttf>

Fonts (all OFL): IBM Plex Mono (github.com/IBM/plex), Martian Mono
(github.com/evilmartians/mono). All text ships as OUTLINED PATHS (BRAND §1
production note). Produces: wordmark lockups (hero/standard, dark+light),
X avatar 400x400, banner 1500x500, og.png 1200x630, favicon PNGs
(16 pinless + 16 two-pin for the empirical test, 32, 48), favicon.svg,
tokens.css. Deliberately NOT produced: filled/foil die registers, rank
hues, guilloche (reserved; BRAND §1.2/§3.4/§9).
"""

import sys
from pathlib import Path

import cairosvg
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont

INK, PAPER = "#171A19", "#F2EFE7"
VG_DISPLAY, VG_ON_DARK, VG_ON_LIGHT = "#4FA095", "#7EC8BA", "#2E6B62"
TAGLINE = "verifiable proof of agentic skill"
OUT = Path(__file__).parent


class Face:
    def __init__(self, path):
        self.font = TTFont(path)
        self.gs = self.font.getGlyphSet()
        self.cmap = self.font.getBestCmap()
        self.upm = self.font["head"].unitsPerEm
        self.x_height = self.font["OS/2"].sxHeight

    def glyph(self, ch):
        name = self.cmap[ord(ch)]
        pen = SVGPathPen(self.gs)
        self.gs[name].draw(pen)
        return pen.getCommands(), self.gs[name].width

    def text_paths(self, text, size, x, baseline_y, fill):
        """Outlined text run starting at x; returns (svg fragment, end_x)."""
        s = size / self.upm
        parts, cx = [], x
        for ch in text:
            d, w = self.glyph(ch)
            if d:
                parts.append(
                    f'<path fill="{fill}" transform="translate({cx:.2f},'
                    f'{baseline_y:.2f}) scale({s:.5f},-{s:.5f})" d="{d}"/>'
                )
            cx += w * s
        return "".join(parts), cx


def die_dot(cx_cell_start, cell_w, baseline_y, size, color, pins):
    """The die at punctuation scale, bottom ON the baseline (never below)."""
    side = size
    x = cx_cell_start + (cell_w - side) / 2
    y = baseline_y - side
    r = side * 0.15 if not pins else side * 0.11
    stroke = max(1.4, side * 0.09)
    svg = (f'<rect x="{x:.2f}" y="{y:.2f}" width="{side:.2f}" height="{side:.2f}" '
           f'rx="{r:.2f}" stroke="{color}" stroke-width="{stroke:.2f}" fill="none"/>')
    if pins:  # top pins only ("plugged into the baseline")
        plen, pw = side * 0.22, stroke * 0.8
        for fx in (0.3, 0.7):
            px = x + side * fx
            svg += (f'<line x1="{px:.2f}" y1="{y - plen:.2f}" x2="{px:.2f}" '
                    f'y2="{y:.2f}" stroke="{color}" stroke-width="{pw:.2f}"/>')
    return svg


def wordmark(martian, size, x, baseline_y, main_color, is_color, register):
    """mybench.is lockup; register: 'hero' (pins, 50% x-height) or
    'standard' (square, 40%)."""
    frag1, x1 = martian.text_paths("mybench", size, x, baseline_y, main_color)
    cell_w = martian.glyph(".")[1] * (size / martian.upm)
    xh = martian.x_height * (size / martian.upm)
    dot = die_dot(x1, cell_w, baseline_y,
                  xh * (0.5 if register == "hero" else 0.4),
                  VG_DISPLAY, pins=(register == "hero"))
    frag2, x2 = martian.text_paths("is", size, x1 + cell_w, baseline_y, is_color)
    return frag1 + dot + frag2, x2


def svgdoc(w, h, inner, bg=None):
    rect = f'<rect width="{w}" height="{h}" fill="{bg}"/>' if bg else ""
    return (f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'xmlns="http://www.w3.org/2000/svg">{rect}{inner}</svg>')


def png(svg, path, w, h):
    cairosvg.svg2png(bytestring=svg.encode(), write_to=str(path),
                     output_width=w, output_height=h)
    print(path.name, f"{w}x{h}")


def recolored_mark(name, color):
    return (OUT / f"{name}.svg").read_text().replace("currentColor", color)


def mark_on_field(mark_name, canvas, body_side_frac, mark_body_px_of_60, color, bg):
    """Center a mark cut on a square field with die BODY = frac of canvas."""
    body_target = canvas * body_side_frac
    scale = body_target / mark_body_px_of_60
    w = 60 * scale
    h = 68 * scale
    x, y = (canvas - w) / 2, (canvas - h) / 2
    # fill="none" must survive the root-tag strip — a filled die is the
    # reserved TEE register (BRAND §1.2) and must never ship from here.
    inner = (f'<g fill="none" transform="translate({x:.1f},{y:.1f}) scale({scale:.4f})">'
             + recolored_mark(mark_name, color)
             .replace('<svg viewBox="0 0 60 68" xmlns="http://www.w3.org/2000/svg" '
                      'fill="none">', "").replace("</svg>", "") + "</g>")
    return svgdoc(canvas, canvas, inner, bg=bg)


def main(plex_bold, martian_path, plex_regular):
    martian = Face(martian_path)
    plex_reg = Face(plex_regular)

    # Wordmark lockups (SVG, outlined) — dark = for ink fields, light = paper
    for reg in ("hero", "standard"):
        for variant, main, isc, bg in (("dark", PAPER, VG_ON_DARK, INK),
                                       ("light", INK, VG_ON_LIGHT, None)):
            frag, end_x = wordmark(martian, 64, 20, 88, main, isc, reg)
            doc = svgdoc(int(end_x + 20), 120, frag, bg=bg)
            (OUT / f"wordmark-{reg}-{variant}.svg").write_text(doc + "\n")
            print(f"wordmark-{reg}-{variant}.svg")

    # X avatar 400x400: 2-pin mark, paper on ink, body ~= 55% of canvas
    png(mark_on_field("mark-2pin", 400, 0.55, 46, PAPER, INK),
        OUT / "avatar-400.png", 400, 400)

    # Banner 1500x500: hero lockup from x=420, vertically centered; tagline
    frag, end_x = wordmark(martian, 96, 420, 250, PAPER, VG_ON_DARK, "hero")
    tag, _ = plex_reg.text_paths(TAGLINE, 30, 424, 310, PAPER)
    banner = svgdoc(1500, 500, frag + f'<g opacity="0.7">{tag}</g>', bg=INK)
    png(banner, OUT / "banner-1500x500.png", 1500, 500)

    # og:image 1200x630: hero lockup + tagline, roughly centered
    frag, end_x = wordmark(martian, 110, 190, 320, PAPER, VG_ON_DARK, "hero")
    tag, _ = plex_reg.text_paths(TAGLINE, 34, 196, 390, PAPER)
    og = svgdoc(1200, 630, frag + f'<g opacity="0.7">{tag}</g>', bg=INK)
    png(og, OUT / "og.png", 1200, 630)

    # Favicons: ink-on-transparent PNGs + the SVG the report page links
    png(mark_on_field("mark-pinless", 16, 0.9, 48, INK, None),
        OUT / "favicon-16-pinless.png", 16, 16)
    png(mark_on_field("mark-2pin", 16, 0.78, 46, INK, None),
        OUT / "favicon-16-2pin.png", 16, 16)
    png(mark_on_field("mark-2pin", 32, 0.78, 46, INK, None),
        OUT / "favicon-32.png", 32, 32)
    png(mark_on_field("mark-3pin", 48, 0.73, 44, INK, None),
        OUT / "favicon-48.png", 48, 48)
    (OUT / "favicon.svg").write_text(recolored_mark("mark-2pin", INK) + "\n")

    # Design tokens (BRAND §3/§4)
    (OUT / "tokens.css").write_text(f""":root {{
  --ink: {INK}; --paper: {PAPER};
  --vg-100: #DCEFEA; --vg-300: {VG_ON_DARK}; --vg-400: {VG_DISPLAY};
  --vg-600: {VG_ON_LIGHT}; --vg-800: #1A423C;
  --accent-display: var(--vg-400);
  --accent-text: var(--vg-600);
  --accent-tint: var(--vg-100);
  --font-evidence: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  --font-ui: Inter, system-ui, sans-serif;
}}
@media (prefers-color-scheme: dark) {{
  :root {{ --accent-text: var(--vg-300); --accent-tint: var(--vg-800); }}
}}
/* Reserved (BRAND §3.4): rank metals and foil hues are NOT tokens here on
   purpose — they may only ever appear on rank/evidence badge surfaces. */
""")
    print("tokens.css")


if __name__ == "__main__":
    main(*sys.argv[1:4])
