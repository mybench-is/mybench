"""Regenerate the outlined-path master marks (BRAND.md §1) — MYB-5.6/5.7.

Usage: python assets/brand/generate_marks.py <path-to-IBMPlexMono-Bold.ttf>
Font source (OFL): https://github.com/IBM/plex — packages/plex-mono/fonts/
complete/ttf/IBMPlexMono-Bold.ttf. Requires fonttools. The 'mb' letters are
extracted as glyph OUTLINES and lightly stroked (~4-6%) so they hold at
small sizes; no shipped mark is a raw font render (BRAND §1 production
note). Three cuts per the pin-shedding ladder: 3-pin (>=33px), 2-pin
(17-32px), pinless (<=16px). The report page embeds the 3-pin cut
(src/mybench/report/page.py STAMP_SVG) — re-embed after regenerating.
"""

import sys
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont


def main(ttf: str) -> None:
    font = TTFont(ttf)
    glyph_set = font.getGlyphSet()
    upm = font["head"].unitsPerEm
    cmap = font.getBestCmap()

    def glyph_path(char):
        pen = SVGPathPen(glyph_set)
        glyph_set[cmap[ord(char)]].draw(pen)
        return pen.getCommands(), glyph_set[cmap[ord(char)]].width

    def mb_group(font_size, cx, cy, thicken):
        s = font_size / upm
        d_m, w_m = glyph_path("m")
        d_b, _ = glyph_path("b")
        x_height = 520  # Plex Mono lowercase height (font units)
        x0 = cx - (2 * w_m * s) / 2
        baseline_y = cy + (x_height * s) / 2
        stroke = f' stroke="currentColor" stroke-width="{thicken}"' if thicken else ""
        return (f'<g fill="currentColor"{stroke} transform="translate({x0:.2f},'
                f'{baseline_y:.2f}) scale({s:.5f},-{s:.5f})"><path d="{d_m}"/>'
                f'<path transform="translate({w_m},0)" d="{d_b}"/></g>')

    def pins(xs, top, bottom, length, width):
        out = []
        for x in xs:
            out.append(f'<line x1="{x}" y1="{top - length}" x2="{x}" y2="{top}" '
                       f'stroke="currentColor" stroke-width="{width}"/>')
            out.append(f'<line x1="{x}" y1="{bottom}" x2="{x}" y2="{bottom + length}" '
                       f'stroke="currentColor" stroke-width="{width}"/>')
        return "".join(out)

    def mark(pin_xs, body, body_stroke, pin_len, pin_w, font_size, thicken):
        x, y, side, r = body
        return ('<svg viewBox="0 0 60 68" xmlns="http://www.w3.org/2000/svg" fill="none">'
                f'<rect x="{x}" y="{y}" width="{side}" height="{side}" rx="{r}" '
                f'stroke="currentColor" stroke-width="{body_stroke}"/>'
                + (pins(pin_xs, y, y + side, pin_len, pin_w) if pin_xs else "")
                + mb_group(font_size, x + side / 2, y + side / 2, thicken) + "</svg>")

    out = Path(__file__).parent
    (out / "mark-3pin.svg").write_text(
        mark([18, 30, 42], (8, 12, 44, 5), 2.5, 7, 2, 21, 0.4) + "\n")
    (out / "mark-2pin.svg").write_text(
        mark([21, 39], (7, 12, 46, 5), 3, 7, 2.5, 26, 0.6) + "\n")
    (out / "mark-pinless.svg").write_text(
        mark([], (6, 11, 48, 5.5), 3, 0, 0, 32, 0.8) + "\n")
    print("marks regenerated")


if __name__ == "__main__":
    main(sys.argv[1])
