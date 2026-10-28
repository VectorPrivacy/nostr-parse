"""The README's benchmark tables, from bench/results.json.

    python3 bench/tables.py            # print every table and the headline ratios
    python3 bench/tables.py README.md  # rewrite the tables between its markers

A marker pair is `<!-- bench:<platform>:<speed|memory> -->` ... `<!-- /bench -->`.
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORKLOADS = ["all", "notes", "reactions", "dms", "giftwraps", "metadata", "zaps", "lists"]
NAMES = {
    "nostr-parse-compact-typed": "**nostr-parse `CompactEvent`**",
    "nostr-parse-typed": "**nostr-parse `Event`**",
    "nostr-parse-nostr-typed": "nostr-parse → rust-nostr `Event`",
    "quartz-kite": "Kite, Quartz {v} (JVM)",
    "sonic_rs-typed": "sonic-rs {v}",
    "simd_json-typed": "simd-json {v}",
    "simdjson_rust-typed": "simdjson-rust {v} (C++ simdjson)",
    "serde_json-typed": "serde_json {v}",
    "nostr-typed": "rust-nostr {v} `Event::from_json`",
}


def name(parser, libraries):
    return NAMES[parser].format(v=libraries.get(parser, {}).get("version", ""))


def speed(platform, libraries):
    parsers = platform["parsers"]
    order = sorted(NAMES, key=lambda p: parsers[p]["all"]["ns"] if p in parsers else 1e18)
    lines = ["| ns per event | " + " | ".join(WORKLOADS) + " |", "|---|" + "---:|" * len(WORKLOADS)]
    for p in order:
        if p not in parsers:
            continue
        cells = [f'{parsers[p][w]["ns"]:,.0f}' for w in WORKLOADS]
        if p.startswith("nostr-parse") and p != "nostr-parse-nostr-typed":
            cells = [f"**{c}**" for c in cells]
        lines.append(f"| {name(p, libraries)} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def memory(platform, libraries):
    parsers = platform["parsers"]
    order = sorted(NAMES, key=lambda p: parsers[p]["all"]["ns"] if p in parsers else 1e18)
    lines = [
        "| per event, all events | allocations | bytes allocated | objects kept | bytes kept |",
        "|---|---:|---:|---:|---:|",
    ]
    for p in order:
        if p not in parsers:
            continue
        c = parsers[p]["all"]
        lines.append(
            f'| {name(p, libraries)} | {c["allocs"]:.1f} | {c["alloc_bytes"]:,.0f} | '
            f'{c.get("kept_objects", 0):.1f} | {c.get("kept_bytes", 0):,.0f} |'
        )
    return "\n".join(lines)


def ratios(platform):
    p = platform["parsers"]
    ours = p["nostr-parse-compact-typed"]["all"]["ns"]
    out = []
    for other in ["quartz-kite", "sonic_rs-typed", "simd_json-typed", "simdjson_rust-typed", "serde_json-typed", "nostr-typed"]:
        if other in p:
            out.append(f'{other}: {p[other]["all"]["ns"] / ours:.2f}x')
    wins = {
        other: all(p["nostr-parse-compact-typed"][w]["ns"] < p[other][w]["ns"] for w in WORKLOADS)
        for other in p
        if other != "nostr-parse-compact-typed"
    }
    lost = [o for o, won in wins.items() if not won]
    return ", ".join(out) + f" | compact faster on every workload against all but: {lost or 'none'}"


def rewrite(readme, results):
    with open(readme) as f:
        text = f.read()
    tables = {"speed": speed, "memory": memory}

    def table(m):
        platform = results["platforms"][m.group(1)]
        return f"{m.group(0).split('-->')[0]}-->\n{tables[m.group(2)](platform, results['libraries'])}\n<!-- /bench -->"

    text, n = re.subn(r"<!-- bench:(\w+):(speed|memory) -->.*?<!-- /bench -->", table, text, flags=re.S)
    with open(readme, "w") as f:
        f.write(text)
    print(f"{readme}: {n} tables")


def main():
    with open(os.path.join(HERE, "results.json")) as f:
        results = json.load(f)
    if len(sys.argv) > 1:
        rewrite(sys.argv[1], results)
        return
    for key, platform in results["platforms"].items():
        print(f"## {key}: {platform['label']} ({platform['cpu']}), {platform['rounds']} rounds")
        print(platform["runtimes"])
        print()
        print(speed(platform, results["libraries"]))
        print()
        print(memory(platform, results["libraries"]))
        print()
        print("compact vs:", ratios(platform))
        print()


if __name__ == "__main__":
    main()
