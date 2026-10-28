"""Folds nostrJsonBench runs for one platform into bench/results.json.

    python3 bench/summarize.py <runs dir> <key> "<label>"

The runs dir holds kiteN.json (JVM harness) and rustN.json (Rust harness) from
alternating rounds. Every result must have matched the reference digest. Only
medians across rounds, the CPU and the toolchains are kept: no host names or
kernel versions.
"""

import glob
import json
import os
import statistics
import sys

METRICS = {
    "ns": "ns_per_event",
    "alloc_bytes": "alloc_bytes_per_event",
    "allocs": "allocs_per_event",
    "kept_bytes": "retained_bytes_per_event",
    "kept_objects": "retained_objects_per_event",
}


def main():
    runs, key, label = sys.argv[1:4]
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.json")
    try:
        with open(out_path) as f:
            results = json.load(f)
    except FileNotFoundError:
        results = {"platforms": {}, "libraries": {}}

    values = {}
    rounds = {}
    platform = {"label": label, "runtimes": {}}
    for path in sorted(glob.glob(os.path.join(runs, "*.json"))):
        with open(path) as f:
            run = json.load(f)
        platform["cpu"] = run["host"]["cpu"]
        platform["runtimes"][run["harness"]] = run["runtime"]
        results["corpus"] = {"fingerprint": run["corpus_fingerprint"]}
        for r in run["results"]:
            name = f'{r["parser"]} / {r["workload"]}'
            if not r["digest_ok"] or r["error"]:
                sys.exit(f"{path}: {name} failed its digest")
            results["libraries"][r["parser"]] = {"library": r["library"], "version": r["version"]}
            if r["workload"] == "all":
                results["corpus"]["events"] = r["events"]
            cell = values.setdefault(r["parser"], {}).setdefault(r["workload"], {})
            for short, field in METRICS.items():
                if r.get(field) is not None:
                    cell.setdefault(short, []).append(r[field])
            rounds[r["parser"]] = rounds.get(r["parser"], 0) + (r["workload"] == "all")

    if len(set(rounds.values())) != 1:
        sys.exit(f"uneven rounds per parser: {rounds}")
    platform["rounds"] = next(iter(rounds.values()))
    platform["parsers"] = {
        parser: {
            workload: {m: round(statistics.median(v), 2) for m, v in metrics.items()}
            for workload, metrics in workloads.items()
        }
        for parser, workloads in values.items()
    }
    results["platforms"][key] = platform
    with open(out_path, "w") as f:
        json.dump(results, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{key}: {len(values)} parsers, {platform['rounds']} rounds -> {out_path}")


if __name__ == "__main__":
    main()
