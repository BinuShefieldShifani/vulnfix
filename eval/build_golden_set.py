"""Sample a balanced set of patches from committed eval runs for human labeling.

Reads the runs.jsonl files, dedupes near-identical patches, and samples ~N with a
spread across cases and outcomes (so the golden set isn't 55 identical SQLi
successes). Writes a to-label file; the labeling tool reads it next.

No model, no GPU. Run on the Mac.

Usage:
    python eval/build_golden_set.py --n 80
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random


RUN_FILES = [
    "results/eval/run8_home/runs.jsonl",
    "results/eval/run8_heldout/runs.jsonl",
    "results/eval/run7_traced/runs.jsonl",
]


def _load_rows():
    rows = []
    for path in RUN_FILES:
        if not os.path.exists(path):
            continue
        run = os.path.basename(os.path.dirname(path))
        for line in open(path):
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("patch_diff") and not str(r.get("status", "")).startswith("ERROR"):
                r["_run"] = run
                rows.append(r)
    return rows


def _diff_hash(diff):
    # normalize whitespace so trivially-different diffs dedupe
    norm = "\n".join(l.rstrip() for l in (diff or "").splitlines() if l.strip())
    return hashlib.sha1(norm.encode()).hexdigest()[:12]


def _outcome(r):
    # a compact objective label from the oracles, to help the human and to balance
    if r.get("exploit") == "exploited":
        return "still_vulnerable"
    if r.get("behavior") == "broken":
        return "secure_but_broken"
    if not r.get("compiles"):
        return "doesnt_compile"
    if r.get("exploit") == "safe":
        return "likely_good"
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=80)
    ap.add_argument("--out", default="results/golden/to_label.jsonl")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    rows = _load_rows()
    # dedupe identical diffs, keep first occurrence
    seen = {}
    for r in rows:
        h = _diff_hash(r["patch_diff"])
        if h not in seen:
            r["_diffhash"] = h
            seen[h] = r
    uniq = list(seen.values())
    print(f"{len(rows)} patches, {len(uniq)} unique diffs")

    # bucket by outcome for a balanced sample
    buckets = {}
    for r in uniq:
        buckets.setdefault(_outcome(r), []).append(r)
    print("unique by outcome:", {k: len(v) for k, v in buckets.items()})

    # sample proportionally but guarantee minority classes are represented
    picked = []
    # first, take up to n/len(buckets) from each, shuffled
    per = max(1, args.n // max(1, len(buckets)))
    for k, v in buckets.items():
        random.shuffle(v)
        picked.extend(v[:per])
    # top up to n from the remainder
    remaining = [r for r in uniq if r not in picked]
    random.shuffle(remaining)
    picked.extend(remaining[: max(0, args.n - len(picked))])
    picked = picked[:args.n]
    random.shuffle(picked)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        for i, r in enumerate(picked):
            fh.write(json.dumps({
                "idx": i,
                "case_id": r["case_id"],
                "run": r["_run"],
                "diffhash": r["_diffhash"],
                "status": r.get("status"),
                "validated": r.get("validated"),
                "exploit": r.get("exploit"),
                "behavior": r.get("behavior"),
                "compiles": r.get("compiles"),
                "oracle_outcome": _outcome(r),
                "patch_diff": r["patch_diff"],
            }) + "\n")
    print(f"wrote {len(picked)} patches to {args.out}")
    print("sampled by outcome:",
          {k: sum(1 for r in picked if _outcome(r) == k) for k in buckets})


if __name__ == "__main__":
    main()
