"""CodeQL detection scoring for the OWASP Benchmark Python.

CodeQL does real data-flow (taint) analysis, unlike pattern-based Semgrep, so it
is expected to do much better on the taint categories (injection, path, xss)
where Semgrep scored near zero. This scores CodeQL on the SAME benchmark with the
SAME framework (detection.py), so the number is directly comparable to the
Semgrep Python result.

Licensing note: the CodeQL CLI is free only for OSS / academic use. The OWASP
Benchmark is open source, so this is fine. CodeQL is NOT bundled into VulnFix
itself (which must scan private code); it is used here only for benchmark
evaluation.

Python needs no build step (build-mode none). Needs the CodeQL CLI on PATH.
No GPU.

Usage:
    python eval/detect_codeql_python.py --repo /kaggle/working/BenchmarkPython
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


def _run(cmd, **kw):
    print("  $", " ".join(cmd[:6]), "..." if len(cmd) > 6 else "", flush=True)
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _find_csv(repo):
    for root, _d, files in os.walk(repo):
        for f in files:
            if re.match(r"expectedresults-.*\.csv", f):
                return os.path.join(root, f)
    raise FileNotFoundError("expectedresults CSV not found")


def _find_testcode_dir(repo):
    best = None
    for root, _d, files in os.walk(repo):
        n = sum(1 for f in files if re.match(r"BenchmarkTest.*\.py", f))
        if n and (best is None or n > best[1]):
            best = (root, n)
    if best is None:
        raise FileNotFoundError("no BenchmarkTest*.py files")
    return best[0]


def _load_truth(csv_path):
    rows = []
    with open(csv_path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = line.split(",")
            if len(p) < 4:
                continue
            rows.append({"id": p[0].replace(".py", ""), "category": p[1],
                         "real": p[2].strip().lower() == "true", "cwe": p[3].strip()})
    return rows


def _cwes_from_sarif(sarif_path):
    """Return {BenchmarkTestNNNNN -> set(cwe)} from a CodeQL SARIF file."""
    with open(sarif_path) as fh:
        sarif = json.load(fh)
    found = {}
    for run in sarif.get("runs", []) or []:
        rule_cwes = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            tags = " ".join((rule.get("properties") or {}).get("tags") or [])
            # CodeQL tags look like external/cwe/cwe-089
            rule_cwes[rule.get("id")] = set(re.findall(r"cwe[-/](\d+)", tags, re.I))
        for res in run.get("results", []) or []:
            uri = ((res.get("locations") or [{}])[0].get("physicalLocation", {})
                   .get("artifactLocation", {}).get("uri", ""))
            m = re.search(r"(BenchmarkTest\d+)\.py", uri)
            if not m:
                continue
            found.setdefault(m.group(1), set()).update(
                rule_cwes.get(res.get("ruleId"), set()))
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="/kaggle/working/BenchmarkPython")
    ap.add_argument("--db", default="/kaggle/working/codeql-py-db")
    ap.add_argument("--sarif", default="/kaggle/working/codeql_python.sarif")
    ap.add_argument("--suite", default="python-security-and-quality.qls")
    ap.add_argument("--out", default="results/detection/codeql_python.json")
    args = ap.parse_args()

    if subprocess.run(["which", "codeql"], capture_output=True).returncode != 0:
        print("ERROR: codeql not on PATH. Install the CodeQL CLI bundle first.")
        sys.exit(1)

    testdir = _find_testcode_dir(args.repo)
    csv_path = _find_csv(args.repo)
    truth = _load_truth(csv_path)
    print(f"ground truth: {len(truth)} cases, testcode: {testdir}", flush=True)

    # 1. create database (Python: no build)
    print("creating CodeQL database (no build needed for Python) ...", flush=True)
    r = _run(["codeql", "database", "create", args.db, "--language=python",
              "--source-root", testdir, "--overwrite"])
    if r.returncode != 0:
        print("DB CREATE FAILED:\n", r.stderr[-2000:]); sys.exit(1)
    if not os.path.exists(os.path.join(args.db, "codeql-database.yml")):
        print("WARNING: no codeql-database.yml, database may be empty")

    # 2. analyze with the security suite
    print(f"analyzing with {args.suite} (a few minutes) ...", flush=True)
    r = _run(["codeql", "database", "analyze", args.db, args.suite,
              "--format=sarif-latest", "--output", args.sarif,
              "--threads=0", "--rerun"])
    if r.returncode != 0:
        print("ANALYZE FAILED:\n", r.stderr[-2000:]); sys.exit(1)

    reported = _cwes_from_sarif(args.sarif)
    print(f"CodeQL flagged {len(reported)} files", flush=True)

    per_cat, overall = score_detection(truth, reported)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump({"language": "python", "engine": "codeql",
                   "source": "OWASP Benchmark Python v0.1", "suite": args.suite,
                   "overall": overall, "per_category": per_cat}, fh, indent=2)

    print("\n=== CodeQL on OWASP Benchmark (Python) ===")
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
