"""Juliet C# 1.3 (NIST SARD) detection scoring.

Juliet is structured differently from OWASP Benchmark: each .cs file contains a
vulnerable `bad()` method (marked with /* POTENTIAL FLAW */ on the dangerous
line) and one or more safe `good*()` methods. The CWE is encoded in the filename
(CWE<N>_...). So each file yields TWO ground-truth cases:
    - a REAL case (the bad method, should be flagged)
    - a FAKE case (the good method(s), should NOT be flagged)

A Semgrep finding is matched to a method by its line number. A finding inside a
bad method that reports the file's CWE is a true positive; the same inside a
good method is a false positive. This mirrors how Juliet is meant to be scored.

Honest note: Semgrep's C# ruleset is thinner than Java/Python, and Juliet's flow
variants are designed to defeat pattern matching, so scores here are expected to
be low. That is a real finding about free C# SAST maturity, not a setup error.

No GPU, no model. Needs Semgrep and the Juliet C# suite unzipped on disk.
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

# Map Juliet CWE -> a short category label (for the per-category table).
_CAT = {
    "78": "cmdi", "89": "sqli", "90": "ldapi", "22": "pathtraver",
    "79": "xss", "327": "crypto", "328": "hash", "330": "weakrand",
    "643": "xpathi", "502": "deserialization", "611": "xxe", "798": "hardcoded",
    "259": "hardcoded", "614": "securecookie", "601": "redirect", "918": "ssrf",
}


def _find_cs_files(root):
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.endswith(".cs") and f.startswith("CWE"):
                out.append(os.path.join(dirpath, f))
    return out


def _cwe_from_name(fname):
    m = re.match(r"CWE(\d+)_", os.path.basename(fname))
    return m.group(1) if m else None


def _method_spans(text):
    """Find bad()/good*() methods in real Juliet C#. Case-insensitive on the
    method name (Juliet uses Bad/Good with a capital), tolerant of modifiers
    (public/private/override/virtual/static/async) and of the #if preprocessor
    lines. Returns (kind, start_line, end_line), kind in {bad, good}, 1-based."""
    lines = text.splitlines()
    spans = []
    i = 0
    sig = re.compile(
        r"\b(?:public|private|protected|internal|static|override|virtual|sealed|async|\s)*"
        r"(?:void|string|int|object|bool|Task|[A-Za-z_][\w<>\[\],\. ]*?)\s+"
        r"(Bad|Good\w*)\s*\(", re.IGNORECASE)
    while i < len(lines):
        m = sig.search(lines[i])
        if m:
            low = m.group(1).lower()
            name = "bad" if low == "bad" else ("good" if low.startswith("good") else None)
            if name is None:
                i += 1
                continue
            depth = 0
            started = False
            j = i
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    started = True
                if started and depth <= 0:
                    break
                j += 1
            spans.append((name, i + 1, j + 1))
            i = j + 1
        else:
            i += 1
    return spans


def build_ground_truth(cs_files, limit):
    """Each file -> one real case (bad) + one fake case (good), keyed by file+method.
    Returns (ground_truth, file_meta) where file_meta maps file path to its spans
    and CWE for the reporting step."""
    gt = []
    meta = {}
    for path in cs_files:
        cwe = _cwe_from_name(path)
        if not cwe:
            continue
        cat = _CAT.get(cwe, f"cwe-{cwe}")
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        spans = _method_spans(text)
        has_bad = any(n == "bad" for n, _, _ in spans)
        has_good = any(n.startswith("good") for n, _, _ in spans)
        base = os.path.basename(path)
        if has_bad:
            gt.append({"id": base + "::bad", "category": cat, "real": True, "cwe": cwe})
        if has_good:
            gt.append({"id": base + "::good", "category": cat, "real": False, "cwe": cwe})
        meta[base] = {"path": path, "cwe": cwe, "spans": spans}
        if limit and len(meta) >= limit:
            break
    return gt, meta


def scan_and_attribute(meta, config):
    """Run Semgrep over the files in meta, attribute each finding to bad/good by
    line number, and build the `reported` map keyed id -> set(cwe)."""
    paths = [m["path"] for m in meta.values()]
    reported = {}
    # scan in batches by directory to keep the command sane
    dirs = sorted({os.path.dirname(p) for p in paths})
    args = []
    for c in config.split(","):
        c = c.strip()
        if c:
            args += ["--config", c]
    for d in dirs:
        out = subprocess.run(["semgrep", *args, "--sarif", "--quiet", "--timeout", "15", d],
                             capture_output=True, text=True, timeout=3600)
        try:
            sarif = json.loads(out.stdout)
        except Exception:
            continue
        for run in sarif.get("runs", []) or []:
            rule_cwes = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
                tags = " ".join((rule.get("properties") or {}).get("tags") or [])
                rule_cwes[rule.get("id")] = set(re.findall(r"CWE-(\d+)", tags))
            for res in run.get("results", []) or []:
                loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                uri = loc.get("artifactLocation", {}).get("uri", "")
                line = loc.get("region", {}).get("startLine", -1)
                base = os.path.basename(uri)
                if base not in meta:
                    continue
                cwes = rule_cwes.get(res.get("ruleId"), set())
                for name, s, e in meta[base]["spans"]:
                    if s <= line <= e:
                        kind = "bad" if name == "bad" else ("good" if name.startswith("good") else None)
                        if kind:
                            reported.setdefault(f"{base}::{kind}", set()).update(cwes)
                        break
    return reported


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--juliet-dir", required=True, help="unzipped Juliet C# testcases dir")
    ap.add_argument("--limit", type=int, default=0, help="max files total (0=all)")
    ap.add_argument("--per-cwe", type=int, default=40,
                    help="max files sampled per CWE category (0=all); keeps the scan bounded")
    ap.add_argument("--only-cwes", default="78,89,90,22,79,327,328,330,643,502,611,798",
                    help="comma CWE list to include (overlaps other benchmarks); empty=all")
    ap.add_argument("--out", default="results/detection/juliet_csharp.json")
    args = ap.parse_args()

    try:
        from config import settings
        config = settings.SEMGREP_CONFIG
    except Exception:
        config = "p/default,p/security-audit,p/csharp,p/owasp-top-ten,p/cwe-top-25"
    config = ",".join(c for c in config.split(",") if not c.strip().endswith((".yml", ".yaml")))
    # ensure a C# pack is present
    if "p/csharp" not in config:
        config += ",p/csharp"

    cs_files = _find_cs_files(args.juliet_dir)
    print(f"found {len(cs_files)} Juliet C# files", flush=True)
    wanted = {c.strip() for c in args.only_cwes.split(",") if c.strip()}
    if wanted:
        cs_files = [f for f in cs_files if _cwe_from_name(f) in wanted]
    if args.per_cwe and args.per_cwe > 0:
        from collections import defaultdict
        buckets = defaultdict(list)
        for f in sorted(cs_files):
            buckets[_cwe_from_name(f)].append(f)
        cs_files = []
        for cwe, fs in buckets.items():
            cs_files.extend(fs[:args.per_cwe])
    print(f"sampled {len(cs_files)} files across {len(set(_cwe_from_name(f) for f in cs_files))} CWEs", flush=True)
    gt, meta = build_ground_truth(cs_files, args.limit)
    print(f"ground truth: {len(gt)} cases "
          f"({sum(c['real'] for c in gt)} real, {sum(not c['real'] for c in gt)} fake) "
          f"from {len(meta)} files", flush=True)

    print(f"scanning with semgrep [{config}] ...", flush=True)
    reported = scan_and_attribute(meta, config)
    print(f"attributed findings to {len(reported)} methods", flush=True)

    per_cat, overall = score_detection(gt, reported)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump({"language": "csharp", "source": "Juliet C# 1.3 (NIST SARD)",
                   "config": config, "overall": overall, "per_category": per_cat}, fh, indent=2)

    print("\n=== Juliet C# 1.3 detection ===")
    print(f"{'category':<16}{'real':>5}{'TPR':>7}{'FPR':>7}{'Youden':>8}")
    for c in per_cat:
        print(f"{c['category']:<16}{c['real']:>5}"
              f"{(c['tpr'] if c['tpr'] is not None else 0):>7}"
              f"{(c['fpr'] if c['fpr'] is not None else 0):>7}"
              f"{(c['youden'] if c['youden'] is not None else 0):>8}")
    print(f"\nOVERALL  TPR={overall['tpr']}  FPR={overall['fpr']}  "
          f"Youden={overall['youden']}  macro={overall['macro_youden']}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
