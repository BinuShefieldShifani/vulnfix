"""Measure whether keeping only high/medium-confidence findings lowers the
false-positive rate without losing too much recall.

Semgrep (SARIF) carries a security-severity / confidence in rule properties.
Bandit carries issue_confidence (HIGH/MEDIUM/LOW). We re-extract findings while
keeping the confidence, then score three filters: all, >=medium, high-only.
Reuses detection.py for scoring. No GPU.
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

_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0, None: 0}


def semgrep_with_conf(testdir, config):
    """Return {id: [(cwe_set, confidence_rank)]} -- each finding with its conf."""
    args = []
    for c in config.split(","):
        c = c.strip()
        if c:
            args += ["--config", c]
    out = subprocess.run(["semgrep", *args, "--sarif", "--quiet", "--timeout", "15", testdir],
                         capture_output=True, text=True, timeout=3600)
    try:
        sarif = json.loads(out.stdout)
    except Exception:
        return {}
    found = {}
    for run in sarif.get("runs", []) or []:
        rule_meta = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            props = rule.get("properties") or {}
            tags = " ".join(props.get("tags") or [])
            cwes = set(re.findall(r"cwe[-/](\d+)", tags, re.I))
            # semgrep confidence lives in properties.confidence or security-severity
            conf = (props.get("confidence") or "").upper()
            if not conf:
                sev = props.get("security-severity")
                try:
                    sev = float(sev)
                    conf = "HIGH" if sev >= 7 else ("MEDIUM" if sev >= 4 else "LOW")
                except (TypeError, ValueError):
                    conf = "MEDIUM"
            rule_meta[rule.get("id")] = (cwes, _RANK.get(conf, 2))
        for res in run.get("results", []) or []:
            uri = ((res.get("locations") or [{}])[0].get("physicalLocation", {})
                   .get("artifactLocation", {}).get("uri", ""))
            m = re.search(r"(BenchmarkTest\d+)\.py", uri)
            if not m:
                continue
            cwes, rank = rule_meta.get(res.get("ruleId"), (set(), 2))
            found.setdefault(m.group(1), []).append((cwes, rank))
    return found


def bandit_with_conf(testdir):
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
        cwe = (r.get("issue_cwe") or {}).get("id")
        rank = _RANK.get((r.get("issue_confidence") or "").upper(), 2)
        if cwe:
            found.setdefault(m.group(1), []).append(({str(cwe)}, rank))
    return found


def filter_by_conf(findings, min_rank):
    """findings: {id: [(cwe_set, rank)]} -> {id: set(cwe)} keeping rank>=min_rank."""
    out = {}
    for tid, lst in findings.items():
        cwes = set()
        for cwe_set, rank in lst:
            if rank >= min_rank:
                cwes |= cwe_set
        if cwes:
            out[tid] = cwes
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", default="results/detection/confidence_python.json")
    args = ap.parse_args()

    from eval.detect_owasp_python import _find_testcode_dir, _find_csv
    try:
        from config import settings
        config = settings.SEMGREP_CONFIG
    except Exception:
        config = "p/default,p/security-audit,p/python,p/owasp-top-ten,p/cwe-top-25"
    config = ",".join(c for c in config.split(",") if not c.strip().endswith((".yml", ".yaml")))

    testdir = _find_testcode_dir(args.repo)
    csv = _find_csv(args.repo)
    truth = []
    with open(csv) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            c = line.split(",")
            if len(c) >= 4:
                truth.append({"id": c[0].replace(".py", ""), "category": c[1],
                              "real": c[2].strip().lower() == "true", "cwe": c[3].strip()})

    print("scanning (semgrep + bandit) keeping confidence ...", flush=True)
    sem = semgrep_with_conf(testdir, config)
    ban = bandit_with_conf(testdir)
    # merge the two finding lists per id
    merged = {}
    for src in (sem, ban):
        for tid, lst in src.items():
            merged.setdefault(tid, []).extend(lst)

    results = {}
    for label, min_rank in [("all", 1), (">=medium", 2), ("high-only", 3)]:
        rep = filter_by_conf(merged, min_rank)
        _, overall = score_detection(truth, rep)
        results[label] = overall

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(results, open(args.out, "w"), indent=2)

    print(f"\n{'filter':<12}{'TPR':>7}{'FPR':>7}{'Youden':>8}")
    for label in ("all", ">=medium", "high-only"):
        o = results[label]
        print(f"{label:<12}{o['tpr']:>7}{o['fpr']:>7}{o['youden']:>8}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
