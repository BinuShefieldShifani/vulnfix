"""LLM-as-judge for patch quality, calibrated against the human golden set.

Two modes:
  pure     : the judge sees only the finding and the patch diff.
  assisted : the judge also sees the objective oracle results
             (exploit/behavior/compile).

The judge classifies each patch into the SAME five categories the human used:
  good_fix | secure_but_broken | still_vulnerable | doesnt_compile | unsure

Calibration = agreement between the judge's verdict and the human verdict on the
golden set. We report accuracy, per-class precision/recall, and a confusion
table, so we can say not just "it agrees X%" but WHERE it disagrees.

The model call is isolated so the scoring/calibration logic is testable in CI
with a stub judge (no model needed). Only the actual run needs Ollama.
"""
from __future__ import annotations

import json
import os
import re
from collections import defaultdict

CATEGORIES = ["good_fix", "secure_but_broken", "still_vulnerable",
              "doesnt_compile", "unsure"]

_RUBRIC = """You are reviewing an automatically generated security patch. Classify it into exactly ONE category:

- good_fix: the patch removes the vulnerability AND the code still works as intended.
- secure_but_broken: the patch removes the vulnerability BUT changes or breaks the function's behavior, or fails to run (e.g. imports an unavailable package).
- still_vulnerable: the patch does NOT actually stop the attack (e.g. SQL still built by string concat, os.system with a shell, path check that doesn't block ../, pickle/dill still used).
- doesnt_compile: the patched code has a syntax/compile error.
- unsure: genuinely cannot tell from what is shown.

Reply with ONLY the category word, nothing else."""


def build_prompt(finding_desc, diff, oracle=None):
    user = f"FINDING: {finding_desc}\n\nPATCH DIFF:\n{diff}\n"
    if oracle:
        user += (f"\nOBJECTIVE TEST RESULTS (from running the code):\n"
                 f"  exploit still works: {oracle.get('exploit')}\n"
                 f"  behavior preserved:  {oracle.get('behavior')}\n"
                 f"  compiles:            {oracle.get('compiles')}\n")
    return _RUBRIC, user


def parse_verdict(text):
    t = (text or "").strip().lower()
    for c in CATEGORIES:
        if c in t:
            return c
    # loose fallbacks
    if "vulnerab" in t or "exploit" in t:
        return "still_vulnerable"
    if "broken" in t or "behav" in t:
        return "secure_but_broken"
    if "compile" in t or "syntax" in t:
        return "doesnt_compile"
    if "good" in t or "correct" in t or "safe" in t:
        return "good_fix"
    return "unsure"


def calibrate(human_labels, judge_verdicts):
    """human_labels, judge_verdicts: {idx -> category}. Returns metrics dict."""
    common = sorted(set(human_labels) & set(judge_verdicts))
    n = len(common)
    correct = sum(1 for i in common if human_labels[i] == judge_verdicts[i])
    confusion = defaultdict(lambda: defaultdict(int))
    for i in common:
        confusion[human_labels[i]][judge_verdicts[i]] += 1

    # per-class precision/recall
    per_class = {}
    for c in CATEGORIES:
        tp = confusion[c][c]
        fn = sum(confusion[c][x] for x in CATEGORIES if x != c)
        fp = sum(confusion[h][c] for h in CATEGORIES if h != c)
        prec = round(tp / (tp + fp), 3) if (tp + fp) else None
        rec = round(tp / (tp + fn), 3) if (tp + fn) else None
        per_class[c] = {"precision": prec, "recall": rec, "support": tp + fn}

    # a safety-critical collapsed metric: did the judge catch BAD patches?
    # bad = anything not good_fix. We care most about not calling a bad patch good.
    bad_called_good = sum(1 for i in common
                          if human_labels[i] != "good_fix"
                          and judge_verdicts[i] == "good_fix")
    bad_total = sum(1 for i in common if human_labels[i] != "good_fix")

    return {
        "n": n,
        "accuracy": round(correct / n, 3) if n else None,
        "per_class": per_class,
        "confusion": {h: dict(confusion[h]) for h in confusion},
        "bad_patches_called_good": bad_called_good,
        "bad_patches_total": bad_total,
        "miss_rate_on_bad": round(bad_called_good / bad_total, 3) if bad_total else None,
    }
