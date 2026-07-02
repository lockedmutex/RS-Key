# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rank functions by complexity from rust-code-analysis JSON (scripts/metrics.sh).

Reads the per-file metric JSON that `rust-code-analysis-cli -m -O json -o <dir>`
emits and prints the heaviest functions by cognitive, cyclomatic and SLOC.
Advisory only — cognitive complexity is the map worth reading; a high cyclomatic
with a low cognitive is usually a flat serializer, not a refactor target.
"""

import json
import os
import sys


def collect(space, fpath, out):
    if space.get("kind") == "function":
        m = space.get("metrics", {})
        out.append(
            {
                "name": space.get("name", "?"),
                "file": fpath,
                "line": space.get("start_line", 0),
                "cog": m.get("cognitive", {}).get("sum", 0),
                "cyc": m.get("cyclomatic", {}).get("sum", 0),
                "sloc": m.get("loc", {}).get("sloc", 0),
                "nexits": m.get("nexits", {}).get("sum", 0),
            }
        )
    for child in space.get("spaces", []):
        collect(child, fpath, out)


def main(root):
    cwd = os.getcwd() + "/"
    funcs = []
    for dirpath, _, names in os.walk(root):
        for n in names:
            if not n.endswith(".json"):
                continue
            with open(os.path.join(dirpath, n)) as f:
                data = json.load(f)
            fpath = data.get("name", "").removeprefix(cwd)
            collect(data, fpath, funcs)

    # Test/proof files are not refactor targets — drop them from the ranking.
    code = [
        f
        for f in funcs
        if not (
            f["file"].endswith("_tests.rs")
            or f["file"].endswith("tests.rs")
            or f["file"].endswith("_kani.rs")
            or f["file"].endswith("kani.rs")
        )
    ]

    def row(f):
        return (
            f"  cog={f['cog']:>4} cyc={f['cyc']:>3} sloc={f['sloc']:>4} "
            f"exits={f['nexits']:>3}  {f['name']:<34} {f['file']}:{f['line']}"
        )

    print(f"functions analysed (non-test): {len(code)}\n")
    print("== top 25 by COGNITIVE complexity (the map worth reading) ==")
    for f in sorted(code, key=lambda x: -x["cog"])[:25]:
        print(row(f))
    print("\n== top 15 by CYCLOMATIC complexity (cross-check: low cog = flat, skip) ==")
    for f in sorted(code, key=lambda x: -x["cyc"])[:15]:
        print(row(f))
    print("\n== top 12 by SLOC (longest bodies) ==")
    for f in sorted(code, key=lambda x: -x["sloc"])[:12]:
        print(row(f))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: metrics_complexity.py <rust-code-analysis-json-dir>")
    main(sys.argv[1])
