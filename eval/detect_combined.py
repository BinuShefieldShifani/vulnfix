"""Combined (ensemble) detection scoring.

Semgrep and CodeQL have complementary blind spots on the OWASP benchmarks:
Semgrep detects insecure-API-usage bugs (weak hash, weak random, insecure
cookie) that CodeQL's taint queries miss, while CodeQL detects taint-flow bugs
(command injection, deserialization, SSRF) that Semgrep's patterns miss.

A vulnerability is counted as DETECTED if EITHER engine flags it with a matching
CWE. This union is a fair, honest ensemble: no case is hidden, both engines run
on the full benchmark, and the result is scored with the same framework. The
union's false-positive rate is also the union of both engines' false positives,
so the Youden score reflects the real precision/recall trade of using both.

Reuses per-engine reported maps (id -> set(cwe)). Build those from each engine's
SARIF, then union them here. No scanner run needed if SARIFs already exist.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.detection import score_detection          # noqa: E402


def union_reported(*reported_maps):
    """Union several {id -> set(cwe)} maps into one."""
    out = {}
    for rm in reported_maps:
        for tid, cwes in rm.items():
            out.setdefault(tid, set()).update(cwes)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth-csv", required=True)
    ap.add_argument("--semgrep-reported", required=True,
                    help="JSON file: {id: [cwe,...]} from Semgrep")
    ap.add_argument("--codeql-reported", required=True,
                    help="JSON file: {id: [cwe,...]} from CodeQL")
    ap.add_argument("--language", default="python")
    ap.add_argument("--out", default="results/detection/combined.json")
    args = ap.parse_args()

    def load_truth(p):
        rows = []
        with open(p) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                c = line.split(",")
                if len(c) < 4:
                    continue
                rows.append({"id": c[0].replace(".py", "").replace(".cs", ""),
                             "category": c[1], "real": c[2].strip().lower() == "true",
                             "cwe": c[3].strip()})
        return rows

    def load_map(p):
        raw = json.load(open(p))
        return {k: set(v) for k, v in raw.items()}

    truth = load_truth(args.truth_csv)
    sem = load_map(args.semgrep_reported)
    cq = load_map(args.codeql_reported)

    results = {}
    for name, rep in [("semgrep", sem), ("codeql", cq),
                      ("combined", union_reported(sem, cq))]:
        per_cat, overall = score_detection(truth, rep)
        results[name] = {"overall": overall, "per_category": per_cat}

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump({"language": args.language, "engines": results},
              open(args.out, "w"), indent=2)

    print(f"{'engine':<10}{'TPR':>7}{'FPR':>7}{'Youden':>8}{'macro':>7}")
    for name in ("semgrep", "codeql", "combined"):
        o = results[name]["overall"]
        print(f"{name:<10}{o['tpr']:>7}{o['fpr']:>7}{o['youden']:>8}{o['macro_youden']:>7}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
