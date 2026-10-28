"""Draws bench/<platform>-light.svg and -dark.svg from bench/results.json.

    python3 bench/chart.py

One horizontal bar per parser: nanoseconds per event over the whole corpus,
fastest first. nostr-parse is blue, Kite orange, the other parsers gray, and
every bar is labelled with its name and value, so color is never the only cue.
The palette passed the dataviz validator against GitHub's light and dark pages.
"""

import json
import os
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))

# (parser id, label, group)
ROWS = [
    ("nostr-parse-compact-typed", "nostr-parse · CompactEvent", "ours"),
    ("nostr-parse-typed", "nostr-parse · Event", "ours"),
    ("quartz-kite", "Kite · Quartz {full} (JVM)", "kite"),
    ("sonic_rs-typed", "sonic-rs {v}", "rust"),
    ("simd_json-typed", "simd-json {v}", "rust"),
    ("simdjson_rust-typed", "simdjson (C++) via simdjson-rust", "rust"),
    ("serde_json-typed", "serde_json {v}", "rust"),
    ("nostr-typed", "rust-nostr {v}", "rust"),
]

THEMES = {
    "light": {
        "ink": "#1f2328",
        "muted": "#59636e",
        "rule": "#d1d9e0",
        "ours": "#2a78d6",
        "kite": "#eb6834",
        "rust": "#8e8c85",
    },
    "dark": {
        "ink": "#f0f6fc",
        "muted": "#9198a1",
        "rule": "#3d444d",
        "ours": "#3987e5",
        "kite": "#d95926",
        "rust": "#77756f",
    },
}

LEGEND = [("ours", "nostr-parse"), ("kite", "Kite, the JVM parser it set out to beat"), ("rust", "Rust JSON parsers")]
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif"
WIDTH = 820
LABEL_RIGHT = 262
BAR_LEFT = 274
BAR_MAX = 440
PITCH = 32
BAR = 20
TOP = 104


def short_version(v):
    return ".".join(v.split(".")[:2])


def bar_path(x, y, w, h, r=4):
    """A bar square at the baseline with a rounded data end."""
    r = min(r, w / 2, h / 2)
    return (
        f"M{x:.1f},{y:.1f} H{x + w - r:.1f} A{r},{r} 0 0 1 {x + w:.1f},{y + r:.1f} "
        f"V{y + h - r:.1f} A{r},{r} 0 0 1 {x + w - r:.1f},{y + h:.1f} H{x:.1f} Z"
    )


def draw(platform, libraries, events, theme):
    t = THEMES[theme]
    rows = []
    for parser, label, group in ROWS:
        cell = platform["parsers"].get(parser, {}).get("all")
        if cell is None:
            continue
        version = libraries.get(parser, {}).get("version", "")
        rows.append((cell["ns"], label.format(v=short_version(version), full=version), group))
    rows.sort()
    scale = BAR_MAX / max(ns for ns, _, _ in rows)
    height = TOP + len(rows) * PITCH + 16

    title = f"Parsing Nostr events · {platform['label']}"
    subtitle = f"Nanoseconds per event over {events:,} real events, owned and fully decoded. Lower is better."
    desc = "; ".join(f"{label}: {ns:.0f} ns" for ns, label, _ in rows)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}" role="img" aria-labelledby="t d">',
        f'<title id="t">{escape(title)}</title><desc id="d">{escape(desc)}</desc>',
        f'<g font-family="{FONT}" fill="{t["ink"]}">',
        f'<text x="0" y="22" font-size="18" font-weight="600">{escape(title)}</text>',
        f'<text x="0" y="46" font-size="13" fill="{t["muted"]}">{escape(subtitle)}</text>',
    ]
    x = 0
    for group, text in LEGEND:
        out.append(f'<rect x="{x}" y="64" width="12" height="12" rx="3" fill="{t[group]}"/>')
        out.append(f'<text x="{x + 18}" y="74.5" font-size="12.5" fill="{t["muted"]}">{escape(text)}</text>')
        x += 18 + len(text) * 6.3 + 20
    out.append(
        f'<line x1="{BAR_LEFT - 0.5}" y1="{TOP - 6}" x2="{BAR_LEFT - 0.5}" '
        f'y2="{TOP + len(rows) * PITCH - PITCH + BAR + 6}" stroke="{t["rule"]}" stroke-width="1"/>'
    )
    for i, (ns, label, group) in enumerate(rows):
        y = TOP + i * PITCH
        w = max(ns * scale, 2)
        weight = ' font-weight="600"' if group == "ours" else ""
        out.append(
            f'<text x="{LABEL_RIGHT}" y="{y + BAR / 2 + 4.5}" font-size="13.5" '
            f'text-anchor="end"{weight}>{escape(label)}</text>'
        )
        out.append(f'<path d="{bar_path(BAR_LEFT, y, w, BAR)}" fill="{t[group]}"/>')
        out.append(
            f'<text x="{BAR_LEFT + w + 8:.1f}" y="{y + BAR / 2 + 4.5}" font-size="13" '
            f'font-variant-numeric="tabular-nums"{weight}>{ns:,.0f} ns</text>'
        )
    out.append("</g></svg>")
    return "\n".join(out) + "\n"


def main():
    with open(os.path.join(HERE, "results.json")) as f:
        results = json.load(f)
    events = results["corpus"]["events"]
    for key, platform in results["platforms"].items():
        for theme in THEMES:
            path = os.path.join(HERE, f"{key}-{theme}.svg")
            with open(path, "w") as f:
                f.write(draw(platform, results["libraries"], events, theme))
            print(path)


if __name__ == "__main__":
    main()
