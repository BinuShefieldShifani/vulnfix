"""OWASP Benchmark (Java) detection scoring.

Clones the real OWASP BenchmarkJava, runs Semgrep (the VulnFix config) against
the real unmodified test cases, reads the official ground-truth CSV, and scores
TPR/FPR/Youden per category and overall. This measures the scanner layer on a
real public benchmark; it does not touch the fixer or the model.

Usage (anywhere Semgrep is installed; no GPU):
    python eval/detect_owasp_java.py --limit 0        # full 2740 cases
    python eval/detect_owasp_java.py --limit 300      # quick subset
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.detection import score_detection          # noqa: E402

BENCH_REPO = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"


def _clone(dest):
    if os.path.isdir(os.path.join(dest, "src")):
        return
    subprocess.run(["git", "clone", "--depth", "1", BENCH_REPO, dest],
                   check=True, capture_output=True, text=True)


def _load_truth(repo, limit):
    csv_path = os.path.join(repo, "expectedresults-1.2.csv")
    rows = []
    with open(csv_path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            name, category, real, cwe = parts[0], parts[1], parts[2], parts[3]
            rows.append({"id": name, "category": category,
                         "real": real.strip().lower() == "true", "cwe": cwe.strip()})
    if limit and limit > 0:
        rows = rows[:limit]
    return rows


def _semgrep_cwes_by_file(testcode_dir, config, only_ids):
    """Run Semgrep once over the testcode dir, return {BenchmarkTestNNNNN -> set(cwe)}."""
    args = []
    for c in config.split(","):
        c = c.strip()
        if c:
            args += ["--config", c]
    out = subprocess.run(
        ["semgrep", *args, "--sarif", "--quiet", "--timeout", "15", testcode_dir],
        capture_output=True, text=True, timeout=3600,
    )
    try:
        sarif = json.loads(out.stdout)
    except Exception:
        return {}
    found = {}
    for run in sarif.get("runs", []) or []:
        rule_cwes = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            tags = " ".join((rule.get("properties") or {}).get("tags") or [])
            rule_cwes[rule.get("id")] = set(re.findall(r"CWE-(\d+)", tags))
        for res in run.get("results", []) or []:
            loc = (res.get("locations") or [{}])[0]
            uri = (loc.get("physicalLocation", {}).get("artifactLocation", {})
                   .get("uri", ""))
            m = re.search(r"(BenchmarkTest\d+)\.java", uri)
            if not m:
                continue
            tid = m.group(1)
            if only_ids and tid not in only_ids:
                continue
            found.setdefault(tid, set()).update(rule_cwes.get(res.get("ruleId"), set()))
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="0 = all cases")
    ap.add_argument("--repo", default="/kaggle/working/BenchmarkJava")
    ap.add_argument("--out", default="results/detection/owasp_java.json")
    args = ap.parse_args()

    try:
        from config import settings
        config = settings.SEMGREP_CONFIG
    except Exception:
        config = "p/default,p/security-audit,p/java,p/owasp-top-ten,p/cwe-top-25"
    # drop the local vulnfix_rules.yml for this run (it's VulnFix-specific, not Java-general)
    config = ",".join(c for c in config.split(",") if not c.strip().endswith((".yml", ".yaml")))

    print(f"cloning benchmark to {args.repo} ...", flush=True)
    _clone(args.repo)
    truth = _load_truth(args.repo, args.limit)
    ids = {t["id"] for t in truth}
    print(f"ground truth: {len(truth)} cases "
          f"({sum(t['real'] for t in truth)} real, {sum(not t['real'] for t in truth)} fake)",
          flush=True)

    testcode = os.path.join(args.repo, "src", "main", "java", "org", "owasp",
                            "benchmark", "testcode")
    print(f"scanning with semgrep [{config}] ... (this takes a few minutes)", flush=True)
    reported = _semgrep_cwes_by_file(testcode, config, ids)
    print(f"semgrep flagged {len(reported)} files", flush=True)

    per_cat, overall = score_detection(truth, reported)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump({"language": "java", "source": "OWASP Benchmark v1.2",
                   "config": config, "overall": overall, "per_category": per_cat},
                  fh, indent=2)

    print("\n=== OWASP Benchmark (Java) detection ===")
    print(f"{'category':<14}{'real':>5}{'TPR':>7}{'FPR':>7}{'Youden':>8}")
    for c in per_cat:
        print(f"{c['category']:<14}{c['real']:>5}"
              f"{(c['tpr'] if c['tpr'] is not None else 0):>7}"
              f"{(c['fpr'] if c['fpr'] is not None else 0):>7}"
              f"{(c['youden'] if c['youden'] is not None else 0):>8}")
    print(f"\nOVERALL  TPR={overall['tpr']}  FPR={overall['fpr']}  "
          f"Youden={overall['youden']}  macro={overall['macro_youden']}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
