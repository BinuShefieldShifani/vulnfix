"""Terminal tool to hand-label the golden set.

Shows each patch one at a time: the case, the diff, and the objective oracle
result (so you label fast and consistently). You enter a verdict. Saves after
every label, so you can stop and resume anytime.

Your verdict is the ground truth the LLM judge is later calibrated against, so
label by what you actually think of the patch, not by what the oracle says
(the oracle is shown only as an aid; you can disagree with it).

Verdicts:
    g = good_fix          (secure AND still works)
    b = secure_but_broken (secure but changes/breaks behavior)
    v = still_vulnerable  (the fix doesn't actually fix it)
    c = doesnt_compile    (won't compile/parse)
    u = unsure            (skip judgment)
    s = skip for now      (revisit later)
    q = quit (progress is saved)

Usage:
    python eval/label_golden_set.py
"""
from __future__ import annotations

import json
import os
import sys

TO_LABEL = "results/golden/to_label.jsonl"
LABELS = "results/golden/labels.jsonl"

VERDICTS = {
    "g": "good_fix",
    "b": "secure_but_broken",
    "v": "still_vulnerable",
    "c": "doesnt_compile",
    "u": "unsure",
}


def _load_done():
    done = {}
    if os.path.exists(LABELS):
        for line in open(LABELS):
            try:
                r = json.loads(line)
                done[r["idx"]] = r
            except Exception:
                pass
    return done


def main():
    if not os.path.exists(TO_LABEL):
        print(f"{TO_LABEL} not found. Run build_golden_set.py first.")
        sys.exit(1)
    patches = [json.loads(l) for l in open(TO_LABEL)]
    done = _load_done()
    todo = [p for p in patches if p["idx"] not in done]
    print(f"{len(patches)} patches, {len(done)} already labeled, {len(todo)} to go.\n")

    out = open(LABELS, "a")
    for p in todo:
        os.system("clear" if os.name == "posix" else "cls")
        print("=" * 72)
        print(f"[{p['idx']+1}/{len(patches)}]  case: {p['case_id']}   run: {p['run']}")
        print(f"oracle says: outcome={p['oracle_outcome']}  "
              f"(exploit={p['exploit']} behavior={p['behavior']} "
              f"compiles={p['compiles']} validator={'validated' if p['validated'] else p['status']})")
        print("=" * 72)
        print(p["patch_diff"])
        print("=" * 72)
        print("g=good_fix  b=secure_but_broken  v=still_vulnerable  "
              "c=doesnt_compile  u=unsure  s=skip  q=quit")
        while True:
            ans = input("your verdict > ").strip().lower()
            if ans == "q":
                print("\nSaved. Resume anytime by re-running.")
                out.close()
                return
            if ans == "s":
                break
            if ans in VERDICTS:
                rec = {"idx": p["idx"], "case_id": p["case_id"],
                       "diffhash": p["diffhash"], "oracle_outcome": p["oracle_outcome"],
                       "human_verdict": VERDICTS[ans]}
                out.write(json.dumps(rec) + "\n")
                out.flush()
                break
            print("  please enter one of: g b v c u s q")
    out.close()
    print("\nAll patches reviewed. Golden set is in", LABELS)


if __name__ == "__main__":
    main()
