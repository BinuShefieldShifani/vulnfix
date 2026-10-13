"""OWASP Benchmark for Python detection scoring.

Same approach as the Java scorer, same ground-truth CSV format
(expectedresults-0.1.csv), same TPR/FPR/Youden framework. Runs Semgrep AND
Bandit against the real OWASP Benchmark Python test cases and scores detection.
No GPU, no model.

Usage (anywhere Semgrep + Bandit are installed):
    python eval/detect_owasp_python.py --limit 0       # all cases
    python eval/detect_owasp_python.py --limit 300     # quick subset
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.detection import score_detection          # noqa: E402

BENCH_REPO = "https://github.com/OWASP-Benchmark/BenchmarkPython.git"


def _clone(dest):
    if os.path.isdir(dest) and os.listdir(dest):
        return
    subprocess.run(["git", "clone", "--depth", "1", BENCH_REPO, dest],
                   check=True, capture_output=True, text=True)


def _find_csv(repo):
    for root, _dirs, files in os.walk(repo):
        for f in files:
            if re.match(r"expectedresults-.*\.csv", f):
                return os.path.join(root, f)
    raise FileNotFoundError("expectedresults CSV not found in benchmark repo")


def _find_testcode_dir(repo):
    # find the directory holding the BenchmarkTest*.py files
    best = None
    for root, _dirs, files in os.walk(repo):
        n = sum(1 for f in files if re.match(r"BenchmarkTest.*\.py", f))
        if n and (best is None or n > best[1]):
            best = (root, n)
    if best is None:
        raise FileNotFoundError("no BenchmarkTest*.py files found")
    return best[0]


def _load_truth(csv_path, limit):
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
            rows.append({"id": name.replace(".py", ""), "category": category,
                         "real": real.strip().lower() == "true", "cwe": cwe.strip()})
    if limit and limit > 0:
        rows = rows[:limit]
    return rows


def _semgrep_cwes(testdir, config, only_ids):
    args = []
    for c in config.split(","):
        c = c.strip()
        if c:
            args += ["--config", c]
    out = subprocess.run(
        ["semgrep", *args, "--sarif", "--quiet", "--timeout", "15", testdir],
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
            uri = ((res.get("locations") or [{}])[0].get("physicalLocation", {})
                   .get("artifactLocation", {}).get("uri", ""))
            m = re.search(r"(BenchmarkTest\d+)\.py", uri)
            if not m:
                continue
            tid = m.group(1)
            if only_ids and tid not in only_ids:
                continue
            found.setdefault(tid, set()).update(rule_cwes.get(res.get("ruleId"), set()))
    return found


def _bandit_cwes(testdir, only_ids):
    out = subprocess.run(["bandit", "-r", "-q", "-f", "json", testdir],
                         capture_output=True, text=True, timeout=1800)
    try:
        data = json.loads(out.stdout)
    except Exception:
        return {}
    found = {}
    for r in data.get("results", []):
        m = re.search(r"(BenchmarkTest\d+)\.py", r.get("filename", ""))
        if not m:
            continue
        tid = m.group(1)
        if only_ids and tid not in only_ids:
            continue
        cwe = (r.get("issue_cwe") or {}).get("id")
        if cwe:
            found.setdefault(tid, set()).add(str(cwe))
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--repo", default="/kaggle/working/BenchmarkPython")
    ap.add_argument("--out", default="results/detection/owasp_python.json")
    args = ap.parse_args()

    try:
        from config import settings
        config = settings.SEMGREP_CONFIG
    except Exception:
        config = "p/default,p/security-audit,p/python,p/owasp-top-ten,p/cwe-top-25"
    config = ",".join(c for c in config.split(",") if not c.strip().endswith((".yml", ".yaml")))

    print(f"cloning benchmark to {args.repo} ...", flush=True)
    _clone(args.repo)
    csv_path = _find_csv(args.repo)
    testdir = _find_testcode_dir(args.repo)
    truth = _load_truth(csv_path, args.limit)
    ids = {t["id"] for t in truth}
    print(f"ground truth: {len(truth)} cases "
          f"({sum(t['real'] for t in truth)} real, {sum(not t['real'] for t in truth)} fake)",
          flush=True)
    print(f"testcode dir: {testdir}", flush=True)

    print(f"scanning with semgrep [{config}] + bandit ...", flush=True)
    reported = _semgrep_cwes(testdir, config, ids)
    bandit = _bandit_cwes(testdir, ids)
    for tid, cwes in bandit.items():
        reported.setdefault(tid, set()).update(cwes)
    print(f"flagged {len(reported)} files", flush=True)

    per_cat, overall = score_detection(truth, reported)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump({"language": "python", "source": "OWASP Benchmark Python v0.1",
                   "config": config + " + bandit",
                   "overall": overall, "per_category": per_cat}, fh, indent=2)

    print("\n=== OWASP Benchmark (Python) detection ===")
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
