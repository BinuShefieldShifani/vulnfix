"""Score a single patched file against the ground-truth oracles.

Given a case id and the patched source, measure four independent things:

  compiles       - py_compile / javac succeeds
  exploit        - "safe" | "exploited" | "error" | "na"
  behavior       - "ok" | "broken" | "error" | "na"
  (the validator verdict is attached separately by the harness, because it
   needs the validator package; the scorer stays dependency-light so CI can
   test it without the model.)

The scorer never calls the model. It runs the patched code against the fixed
exploit/behavior drivers from cases.py, in the sandbox, with a per-run writable
base directory for cases that need one (path traversal).
"""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, asdict

from eval.cases import CASE_ORACLES
from eval.sandbox import run_python, run_java


@dataclass
class PatchScore:
    case_id: str
    language: str
    compiles: bool
    exploit: str      # safe | exploited | error | na
    behavior: str     # ok | broken | error | na
    notes: str = ""

    def as_dict(self):
        return asdict(self)


def _py_compiles(src: str) -> bool:
    try:
        compile(src, "app.py", "exec")
        return True
    except SyntaxError:
        return False


def _verdict_from_output(out: str, good_token: str, bad_token: str) -> str:
    text = out or ""
    last = text.strip().splitlines()[-1] if text.strip() else ""
    if bad_token in text:
        return "bad"
    if last == good_token or good_token in text:
        return "good"
    return "error"


def score_python(case_id: str, patched: str) -> PatchScore:
    o = CASE_ORACLES[case_id]
    compiles = _py_compiles(patched)

    # a fresh writable base dir for cases that read VULNFIX_BASE (path traversal)
    base = tempfile.mkdtemp(prefix="vulnfix_base_")
    env = {"VULNFIX_BASE": os.path.join(base, "data")}

    exploit = "na"
    if o["exploit_driver"] and compiles:
        out = run_python(patched, o["exploit_driver"], extra_env=env).output
        v = _verdict_from_output(out, "SAFE", "EXPLOITED")
        exploit = {"good": "safe", "bad": "exploited", "error": "error"}[v]
    elif o["exploit_driver"] and not compiles:
        exploit = "error"

    behavior = "na"
    if o["behavior_driver"] and compiles:
        out = run_python(patched, o["behavior_driver"], extra_env=env).output
        v = _verdict_from_output(out, "BEHAVIOR_OK", "BEHAVIOR_FAIL")
        # anything that is not a clean OK counts as broken (exception, assert, etc.)
        behavior = "ok" if v == "good" else "broken"
    elif o["behavior_driver"] and not compiles:
        behavior = "broken"

    return PatchScore(case_id, "python", compiles, exploit, behavior)


def score_java(case_id: str, patched: str) -> PatchScore:
    o = CASE_ORACLES[case_id]
    exploit = "na"
    behavior = "na"
    compiles = True

    if o["exploit_driver"]:
        r = run_java(patched, o["exploit_driver"])
        if r.timed_out:
            exploit, compiles = "error", True
        elif "error:" in (r.output or "") and not r.stdout:
            compiles, exploit = False, "error"
        else:
            v = _verdict_from_output(r.output, "SAFE", "EXPLOITED")
            exploit = {"good": "safe", "bad": "exploited", "error": "error"}[v]
    else:
        # no runnable exploit (java-sqli): compile-only signal via a trivial driver
        trivial = ("public class Driver { public static void main(String[] a){"
                   " System.out.println(\"OK\"); } }")
        r = run_java(patched, trivial)
        compiles = r.ok or "OK" in (r.stdout or "")

    return PatchScore(case_id, "java", compiles, exploit, behavior)


def score_patch(case_id: str, patched: str) -> PatchScore:
    lang = CASE_ORACLES[case_id]["language"]
    return score_java(case_id, patched) if lang == "java" else score_python(case_id, patched)
