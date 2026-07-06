# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rank functions by complexity from rust-code-analysis JSON (scripts/metrics.sh).

Reads the per-file metric JSON that `rust-code-analysis-cli -m -O json -o <dir>`
emits and prints the heaviest functions by cognitive, cyclomatic and SLOC.
Advisory only — cognitive complexity is the map worth reading; a high cyclomatic
with a low cognitive is usually a flat serializer, not a refactor target.

With `--max-cognitive N` it also acts as a gate (scripts/complexity_gate.sh, run
in deep-checks): after printing the map it exits non-zero if any non-test
function's cognitive complexity exceeds N — a regression alarm for new hotspots.
"""

import argparse
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


def main(root, max_cognitive=None):
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
    # Matches the repo's cfg(test)/cfg(kani) sibling conventions: `*_tests.rs`,
    # `*_kani.rs`, `tests.rs`, `kani.rs`, and prefix helpers like
    # `tests_support.rs`. A `startswith` (not a bare `test in name`) keeps a
    # production file such as `attestation.rs` in the ranking.
    def is_test_or_proof(path):
        base = os.path.basename(path)
        return base.startswith(("test", "kani")) or "_tests." in base or "_kani." in base

    code = [f for f in funcs if not is_test_or_proof(f["file"])]

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

    if max_cognitive is None:
        return 0

    peak = max((f["cog"] for f in code), default=0)
    over = sorted((f for f in code if f["cog"] > max_cognitive), key=lambda x: -x["cog"])
    if not over:
        print(f"\nOK: peak cognitive {peak:g} <= ceiling {max_cognitive}")
        return 0
    print(f"\nFAIL: {len(over)} function(s) over the cognitive ceiling of {max_cognitive}:")
    for f in over:
        print(row(f))
    print(
        "  Refactor the offender(s), or — if the growth is justified — raise\n"
        "  COGNITIVE_CEILING in scripts/complexity_gate.sh in the same commit."
    )
    return 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Rank (and optionally gate) function complexity from rust-code-analysis JSON."
    )
    ap.add_argument("json_dir", help="directory of rust-code-analysis -m -O json output")
    ap.add_argument(
        "--max-cognitive",
        type=int,
        default=None,
        metavar="N",
        help="exit non-zero if any non-test function's cognitive complexity exceeds N",
    )
    args = ap.parse_args()
    sys.exit(main(args.json_dir, args.max_cognitive))
