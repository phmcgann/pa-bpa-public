#!/usr/bin/env python3
"""
Generates the Harborlight Consulting logo system as vector paths.

    python3 scripts/brand/harborlight_logo.py            # writes src/brand/harborlight/logoData.ts
                                                          # and docs/brand/*.svg

The symbol is drawn from simple geometry; the wordmark is Manrope ExtraBold / SemiBold outlines
(SIL Open Font License) converted to paths, so the logo renders the same without the font. The
"I" in HARBORLIGHT is a custom letterform: a tapered lighthouse tower whose top is the lit, gold lamp room, in one piece and
kept inside the cap height so the word still reads as capitals (a dot above it read as a lowercase i).

Needs: pip install fonttools brotli; npm install (for node_modules/@fontsource/manrope).
"""

from __future__ import annotations

import json
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

FRONTEND = Path(__file__).resolve().parents[2]
REPO = FRONTEND.parents[1]
FONTS = FRONTEND / "node_modules" / "@fontsource" / "manrope" / "files"

NAVY = "#0B2545"
GOLD = "#C9A227"
GREEN = "#1E7B4F"


def rect(x0, y0, x1, y1):
    return f"M{x0:g} {y0:g}H{x1:g}V{y1:g}H{x0:g}Z"


def poly(*pts):
    return "M" + "L".join(f"{x:g} {y:g}" for x, y in pts) + "Z"


# ── The beacon mark (100 × 100 grid) ─────────────────────────────────────
# Roof, lamp, gallery, a tapered tower split by one band of negative space (the lighthouse's
# day-mark stripe), a single beam reaching forward, and the green waterline it stands on.
SYMBOL = {
    "viewBox": "0 0 100 100",
    "paths": [
        {"d": poly((37, 21), (50, 10), (63, 21)), "tone": "ink"},                     # roof
        {"d": rect(40, 23, 60, 33), "tone": "gold"},                                    # lamp
        {"d": poly((60, 25.5), (96, 15), (96, 41), (60, 30.5)), "tone": "gold"},        # beam
        {"d": rect(34, 34.5, 66, 38.5), "tone": "ink"},                                 # gallery
        {"d": poly((39.5, 40.5), (60.5, 40.5), (62.6, 57), (37.4, 57)), "tone": "ink"}, # tower, upper
        {"d": poly((36.6, 63), (63.4, 63), (66.5, 86), (33.5, 86)), "tone": "ink"},     # tower, lower
        {"d": "M18 89.5H82a2.5 2.5 0 0 1 0 5H18a2.5 2.5 0 0 1 0-5Z", "tone": "green"},  # waterline
    ],
}


def glyph_paths(font: TTFont, text: str, x: float, baseline: float, scale: float,
                tracking: float, replace_i=None) -> tuple[list[str], float]:
    """Paths for `text` set left to right from x (font units scaled by `scale`, y flipped).
    `replace_i(x, advance)` draws the letter I instead of the font's glyph."""
    gs = font.getGlyphSet()
    cmap = font.getBestCmap()
    hmtx = font["hmtx"]
    out = []
    for ch in text:
        name = cmap[ord(ch)]
        adv = hmtx[name][0] * scale
        if ch == "I" and replace_i:
            out.extend(replace_i(x, adv))
        else:
            pen = SVGPathPen(gs)
            gs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x, baseline)))
            out.append(pen.getCommands())
        x += adv + tracking
    return out, x - tracking


def build():
    bold = TTFont(FONTS / "manrope-latin-800-normal.woff")
    semi = TTFont(FONTS / "manrope-latin-600-normal.woff")
    upm = bold["head"].unitsPerEm
    cap = bold["OS/2"].sCapHeight or 720

    # Wordmark: cap height 40 units, baseline at y=60.
    s = 40 / cap
    baseline = 60.0
    tracking = 5.2

    # The I keeps the font's stem weight (about 7.6 units at this size) but tapers like the tower.
    # Its top quarter is the gold lamp room, butted straight onto the navy tower: any gap between
    # them reads as the dot of a lowercase i.
    def half_width(y):  # y measured up from the baseline, 0..40
        return 4.5 - 1.25 * (y / 40)

    def seg(cx, y0, y1):
        return poly((cx - half_width(y1), baseline - y1), (cx + half_width(y1), baseline - y1),
                    (cx + half_width(y0), baseline - y0), (cx - half_width(y0), baseline - y0))

    lamp = []

    def tower_i(x, adv):
        cx = x + adv / 2
        lamp.append(seg(cx, 30, 40))
        return [seg(cx, 0, 30)]

    word, end = glyph_paths(bold, "HARBORLIGHT", 0, baseline, s, tracking, replace_i=tower_i)
    wordmark_w = end

    # Descriptor, tracked wide and centred under the wordmark.
    ds = 12.5 / cap
    dtrack = 9.0
    dwidth = sum(semi["hmtx"][semi.getBestCmap()[ord(c)]][0] * ds for c in "CONSULTING") + dtrack * 9
    desc, _ = glyph_paths(semi, "CONSULTING", (wordmark_w - dwidth) / 2, baseline + 26, ds, dtrack)

    wordmark = {
        "viewBox": f"-1 16 {wordmark_w + 2:.2f} 46",
        "paths": [{"d": p, "tone": "ink"} for p in word] + [{"d": lamp[0], "tone": "gold"}],
    }
    wordmark_full = {
        "viewBox": f"-1 16 {wordmark_w + 2:.2f} 74",
        "paths": wordmark["paths"] + [{"d": p, "tone": "muted"} for p in desc],
    }

    # Horizontal lockup: symbol (scaled to 84 tall) left of the full wordmark.
    def place(data, dx, dy, k):
        from fontTools.pens.svgPathPen import SVGPathPen as _P  # noqa: F401  (paths are strings)
        return [{"d": transform_path(p["d"], dx, dy, k), "tone": p["tone"]} for p in data["paths"]]

    # The text block (cap top to descriptor baseline) centres on the symbol's roof-to-waterline.
    lockup_paths = place(SYMBOL, 0, 2, 0.86) + place(wordmark_full, 102, -6, 1.0)
    lockup = {"viewBox": f"-1 1 {102 + wordmark_w + 3:.2f} 88", "paths": lockup_paths}

    # App icon / favicon: the mark reversed out of a navy tile. Simplified for 16 px: one solid
    # tower (the stripe would vanish), a thicker waterline, the beam cropped by the tile edge.
    icon = {"viewBox": "0 0 100 100", "paths": [
        {"d": "M22 0H78A22 22 0 0 1 100 22V78A22 22 0 0 1 78 100H22A22 22 0 0 1 0 78V22A22 22 0 0 1 22 0Z",
         "tone": "ink"},
        {"d": poly((33, 26), (45, 16), (57, 26)), "tone": "paper"},
        {"d": rect(36, 28, 54, 38), "tone": "gold"},
        {"d": poly((54, 30.5), (88, 20), (88, 46), (54, 35.5)), "tone": "gold"},
        {"d": poly((34.5, 41), (55.5, 41), (60, 80), (30, 80)), "tone": "paper"},
        {"d": "M22 84H68a3.5 3.5 0 0 1 0 7H22a3.5 3.5 0 0 1 0-7Z", "tone": "signal"},
    ]}

    return {"symbol": SYMBOL, "wordmark": wordmark, "wordmarkFull": wordmark_full, "lockup": lockup,
            "icon": icon}


def transform_path(d: str, dx: float, dy: float, k: float) -> str:
    """Scale by k then translate, for absolute and relative SVG path commands we emit."""
    import re
    tokens = re.findall(r"[MLHVCQZAmlhvcqza]|-?\d*\.?\d+(?:e-?\d+)?", d)
    out, cmd, args = [], None, []

    def flush():
        if cmd is None:
            return
        a = [float(v) for v in args]
        if cmd in "ML" or cmd in "CQ":
            a = [a[i] * k + (dx if i % 2 == 0 else dy) for i in range(len(a))]
        elif cmd == "H":
            a = [v * k + dx for v in a]
        elif cmd == "V":
            a = [v * k + dy for v in a]
        elif cmd == "A":
            a = [v * k if i % 7 in (0, 1) else (v * k + dx if i % 7 == 5 else v * k + dy if i % 7 == 6 else v)
                 for i, v in enumerate(a)]
        elif cmd in "mlhvcq":
            a = [v * k for v in a]
        elif cmd == "a":
            a = [v * k if i % 7 in (0, 1, 5, 6) else v for i, v in enumerate(a)]
        out.append(cmd + " ".join(f"{v:.2f}".rstrip("0").rstrip(".") for v in a))

    for t in tokens:
        if t.isalpha():
            flush()
            cmd, args = t, []
            if t in "Zz":
                out.append(t)
                cmd = None
        else:
            args.append(t)
    flush()
    return "".join(out)


def svg(data: dict, colors: dict[str, str], title: str) -> str:
    paths = "".join(f'<path d="{p["d"]}" fill="{colors[p["tone"]]}"/>' for p in data["paths"])
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{data["viewBox"]}" role="img" '
            f'aria-label="{title}"><title>{title}</title>{paths}</svg>\n')


def main():
    logos = build()
    out_ts = FRONTEND / "src" / "brand" / "harborlight" / "logoData.ts"
    out_ts.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"export const {k}: LogoData = {json.dumps(v)};" for k, v in logos.items())
    out_ts.write_text(
        "// Harborlight Consulting logo system — generated by scripts/brand/harborlight_logo.py; don't edit.\n"
        "// Tones: ink (navy), gold (beacon gold), green (channel green), muted (descriptor text), paper (white on the icon tile), signal (brighter green on the navy tile).\n\n"
        'export interface LogoData { viewBox: string; paths: { d: string; tone: "ink" | "gold" | "green" | "muted" | "paper" | "signal" }[] }\n\n'
        + body + "\n")

    docs = REPO / "docs" / "brand"
    docs.mkdir(parents=True, exist_ok=True)
    light = {"ink": NAVY, "gold": GOLD, "green": GREEN, "muted": "#51607A", "paper": "#FFFFFF", "signal": "#3FB37B"}
    dark = {"ink": "#F4F6FA", "gold": "#D9B94A", "green": "#3FB37B", "muted": "#A9B6CC", "paper": "#FFFFFF", "signal": "#3FB37B"}
    for name, data in logos.items():
        (docs / f"harborlight-{name}.svg").write_text(svg(data, light, "Harborlight Consulting"))
        if name != "icon":   # the icon carries its own navy tile
            (docs / f"harborlight-{name}-on-dark.svg").write_text(svg(data, dark, "Harborlight Consulting"))
    # The browser-tab icon for the Harborlight build.
    (FRONTEND / "src" / "brand" / "harborlight" / "favicon.svg").write_text(svg(logos["icon"], light, "Harborlight"))
    print(f"wrote {out_ts.relative_to(REPO)}, the favicon, and the SVGs in docs/brand/")


if __name__ == "__main__":
    main()
