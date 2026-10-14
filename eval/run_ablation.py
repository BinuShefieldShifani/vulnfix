"""Retrieval ablation: run the same cases with retrieval ON and OFF, compare.

Answers 'does the OSV advisory retrieval actually improve the fixes, or is it
dead weight?'. Runs each case N times in each arm, scores with the oracles, and
reports fix rate (truly-safe) and validated rate per arm.

Needs Ollama + ChromaDB (for the ON arm). GPU.

Usage:
    python eval/run_ablation.py --repeats 3
"""
from __future__ import annotations

import argparse
import json
import os
import time

import sys, os as _os
sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from models import Finding
from testcases import TEST_CASES
from eval.scorer import score_patch


def _run_arm(no_retrieval, repeats, cases):
    # toggle the switch, then import/reload the pipeline so it picks it up
    if no_retrieval:
        os.environ["VULNFIX_NO_RETRIEVAL"] = "1"
    else:
        os.environ.pop("VULNFIX_NO_RETRIEVAL", None)
    import importlib
    import agents, graph
    importlib.reload(agents)
    importlib.reload(graph)
    from graph import remediate_finding

    rows = []
    for c in cases:
        finding = Finding(rule_id=c["rule_id"], message=c["name"], file_path=c["file"],
                          start_line=1, cwe=[c["cwe"]] if c["cwe"].startswith("CWE") else [])
        for i in range(1, repeats + 1):
            t0 = time.perf_counter()
            try:
                r = remediate_finding(finding, c["code"])
                score = score_patch(c["id"], r.patched_code or c["code"])
                rows.append({"case_id": c["id"], "repeat": i,
                             "validated": bool(r.validation and r.validation.validated),
                             "exploit": score.exploit, "behavior": score.behavior,
                             "time_s": round(time.perf_counter() - t0, 1)})
            except Exception as e:
                rows.append({"case_id": c["id"], "repeat": i,
                             "error": f"{type(e).__name__}"})
            print(f"  [{'OFF' if no_retrieval else 'ON '}] {c['id']:12} "
                  f"run {i}/{repeats}", flush=True)
    return rows


def _summ(rows):
    done = [r for r in rows if "error" not in r]
    n = len(done)
    if not n:
        return {"n": 0}
    safe = sum(1 for r in done if r.get("exploit") == "safe")
    val = sum(1 for r in done if r.get("validated"))
    return {"n": n,
            "truly_safe_rate": round(safe / n, 3),
            "validated_rate": round(val / n, 3),
            "errors": len(rows) - n}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", default="results/ablation/retrieval.json")
    args = ap.parse_args()

    # use the cases that have a runnable exploit oracle (so fix rate is measurable)
    from eval.cases import CASE_ORACLES
    from eval.cases_heldout import HELDOUT_CASES, HELDOUT_ORACLES
    from eval.cases_ablation import ABLATION_CASES, ABLATION_ORACLES
    all_cases = TEST_CASES + HELDOUT_CASES + ABLATION_CASES
    all_oracles = {**CASE_ORACLES, **HELDOUT_ORACLES, **ABLATION_ORACLES}
    cases = [c for c in all_cases
             if all_oracles.get(c["id"], {}).get("exploit_driver")]
    print(f"ablation on {len(cases)} cases with exploit oracles, "
          f"{args.repeats} repeats each arm\n")

    print("=== ARM: retrieval ON ===")
    on = _run_arm(False, args.repeats, cases)
    print("\n=== ARM: retrieval OFF ===")
    off = _run_arm(True, args.repeats, cases)

    res = {"with_retrieval": _summ(on), "without_retrieval": _summ(off),
           "repeats": args.repeats, "cases": len(cases)}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump({**res, "runs_on": on, "runs_off": off}, open(args.out, "w"), indent=2)

    print("\n=== retrieval ablation ===")
    print(f"{'arm':<20}{'truly_safe':>12}{'validated':>11}")
    print(f"{'with retrieval':<20}{res['with_retrieval']['truly_safe_rate']:>12}"
          f"{res['with_retrieval']['validated_rate']:>11}")
    print(f"{'without retrieval':<20}{res['without_retrieval']['truly_safe_rate']:>12}"
          f"{res['without_retrieval']['validated_rate']:>11}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
