"""Run the VulnFix pipeline over every test case, N times each, and score every
patch against the oracles and the validator. Writes a per-run JSONL log and a
summary table of rates.

This is the only eval module that imports the model pipeline, so it runs where
Ollama is available (Kaggle), not on CI. The scorer and oracles it uses are
CI-tested separately.

Usage (inside a GPU notebook, from the repo root):

    from eval.harness import run_evaluation
    summary = run_evaluation(repeats=5, run_label="run5")

Outputs under results/eval/<run_label>/:
    runs.jsonl    - one line per (case, repeat): patch, scores, validator verdict
    summary.csv   - per-case rates over the repeats
"""
from __future__ import annotations

import json
import os
import time

from models import Finding
from graph import remediate_finding
from testcases import TEST_CASES
from eval.scorer import score_patch
from eval.cases import CASE_ORACLES
from eval.summary import summarize as _summarize_rows


def _finding_for(case):
    return Finding(
        rule_id=case["rule_id"], message=case["name"], file_path=case["file"],
        start_line=1,
        cwe=[case["cwe"]] if case["cwe"].startswith("CWE") else [],
    )


def run_evaluation(repeats: int = 5, run_label: str = "run",
                   case_ids=None, out_root: str = "results/eval",
                   trace: bool = False):
    if trace:
        from eval.tracing import enable_tracing
        enable_tracing(f"vulnfix-{run_label}")
    cases = [c for c in TEST_CASES if (case_ids is None or c["id"] in case_ids)]
    out_dir = os.path.join(out_root, run_label)
    os.makedirs(out_dir, exist_ok=True)
    runs_path = os.path.join(out_dir, "runs.jsonl")

    per_case = {c["id"]: [] for c in cases}

    with open(runs_path, "w") as log:
        for c in cases:
            finding = _finding_for(c)
            for i in range(1, repeats + 1):
                t0 = time.perf_counter()
                row = {"case_id": c["id"], "repeat": i, "language": c["language"]}
                try:
                    bt = CASE_ORACLES[c["id"]]["behavior_driver"]
                    r = remediate_finding(finding, c["code"], behavior_test=bt)
                    elapsed = time.perf_counter() - t0
                    v = r.validation
                    score = score_patch(c["id"], r.patched_code or c["code"])
                    row.update({
                        "status": r.status,
                        "attempts": r.attempts,
                        "validated": bool(v and v.validated),
                        "inconclusive": bool(v and v.inconclusive),
                        "compiles": score.compiles,
                        "exploit": score.exploit,
                        "behavior": score.behavior,
                        "time_s": round(elapsed, 1),
                        "patch_diff": r.patch_diff,
                    })
                except Exception as e:  # noqa: BLE001
                    row.update({"status": f"ERROR: {type(e).__name__}: {str(e)[:120]}",
                                "time_s": round(time.perf_counter() - t0, 1)})
                log.write(json.dumps(row) + "\n")
                log.flush()
                per_case[c["id"]].append(row)
                print(f"{c['id']:14} run {i}/{repeats}: "
                      f"{row.get('status','?'):12} "
                      f"val={row.get('validated')} "
                      f"exploit={row.get('exploit')} "
                      f"behavior={row.get('behavior')}", flush=True)

    has_exploit = {c['id']: CASE_ORACLES[c['id']]['exploit_driver'] is not None for c in cases}
    has_behavior = {c['id']: CASE_ORACLES[c['id']]['behavior_driver'] is not None for c in cases}
    summary = _summarize_rows(per_case, repeats, has_exploit, has_behavior)
    _write_summary_csv(summary, os.path.join(out_dir, "summary.csv"))
    return summary




def _write_summary_csv(summary, path):
    import csv
    if not summary:
        return
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)
