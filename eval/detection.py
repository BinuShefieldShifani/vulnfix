"""Shared detection-scoring framework for all languages.

A *detection* evaluation measures the scanner layer (Semgrep + Bandit), not the
fixer. Given a ground-truth table (per test case: is it really vulnerable, and
its expected CWE) and the set of CWEs the scanner reported for each case, it
computes the standard SAST benchmark metrics:

  TPR (recall / true-positive rate) = TP / (TP + FN)
  FPR (false-positive rate)         = FP / (FP + TN)
  Youden's J (the OWASP Benchmark score) = TPR - FPR

A scanner that flags everything gets TPR=1 but FPR=1, so J=0. A perfect scanner
gets J=1. This is exactly how the OWASP Benchmark scores tools, so the number is
directly comparable to the public scoreboard.

CWE matching: a case counts as "detected" only if the scanner reported a CWE
that matches (or is an accepted alias of) the case's expected CWE. This mirrors
the official scorer, which ignores findings whose CWE does not match the
category. Alias sets are shared with the validator.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict

# CWE aliases: scanners don't always tag the same bug with the same CWE number.
# These groups count as "the same finding" for matching. Kept broad but honest.
_CWE_ALIASES = {
    "22":  {"22", "23", "35", "73"},          # path traversal
    "78":  {"78", "77"},                        # command injection
    "79":  {"79", "80", "116"},                 # XSS
    "89":  {"89"},                              # SQL injection
    "90":  {"90"},                              # LDAP injection
    "327": {"327", "326", "328", "916"},        # broken/weak crypto
    "328": {"328", "327", "916"},               # weak hash
    "330": {"330", "338"},                      # weak randomness
    "501": {"501"},                             # trust boundary violation
    "614": {"614", "1004"},                     # insecure cookie
    "643": {"643"},                             # XPath injection
    "502": {"502", "20"},                       # deserialization
    "918": {"918"},                             # SSRF
    "601": {"601"},                             # open redirect
}


def _norm(cwe):
    return str(cwe).replace("CWE-", "").strip()


def _matches(expected, reported_set):
    exp = _norm(expected)
    allowed = _CWE_ALIASES.get(exp, {exp})
    return bool(allowed & {_norm(c) for c in reported_set})


@dataclass
class CategoryScore:
    category: str
    total: int
    real: int          # really-vulnerable cases
    fake: int          # false-positive cases
    tp: int
    fn: int
    fp: int
    tn: int

    @property
    def tpr(self):
        d = self.tp + self.fn
        return round(self.tp / d, 3) if d else None

    @property
    def fpr(self):
        d = self.fp + self.tn
        return round(self.fp / d, 3) if d else None

    @property
    def youden(self):
        if self.tpr is None or self.fpr is None:
            return None
        return round(self.tpr - self.fpr, 3)

    def as_dict(self):
        d = asdict(self)
        d.update(tpr=self.tpr, fpr=self.fpr, youden=self.youden)
        return d


def score_detection(ground_truth, reported):
    """ground_truth: list of dicts {id, category, real(bool), cwe}.
    reported: {id -> set of reported CWE strings} (empty/missing = nothing flagged).
    Returns (per_category list, overall dict)."""
    cats = {}
    for case in ground_truth:
        c = case["category"]
        cats.setdefault(c, {"total": 0, "real": 0, "fake": 0,
                            "tp": 0, "fn": 0, "fp": 0, "tn": 0})
        bucket = cats[c]
        bucket["total"] += 1
        flagged = _matches(case["cwe"], reported.get(case["id"], set()))
        if case["real"]:
            bucket["real"] += 1
            if flagged:
                bucket["tp"] += 1
            else:
                bucket["fn"] += 1
        else:
            bucket["fake"] += 1
            if flagged:
                bucket["fp"] += 1
            else:
                bucket["tn"] += 1

    per_cat = [CategoryScore(category=c, **v).as_dict()
               for c, v in sorted(cats.items())]

    TP = sum(v["tp"] for v in cats.values())
    FN = sum(v["fn"] for v in cats.values())
    FP = sum(v["fp"] for v in cats.values())
    TN = sum(v["tn"] for v in cats.values())
    tpr = round(TP / (TP + FN), 3) if (TP + FN) else None
    fpr = round(FP / (FP + TN), 3) if (FP + TN) else None
    youden = round(tpr - fpr, 3) if (tpr is not None and fpr is not None) else None
    # macro average weights each category equally (OWASP reports this too)
    cat_youdens = [c["youden"] for c in per_cat if c["youden"] is not None]
    macro = round(sum(cat_youdens) / len(cat_youdens), 3) if cat_youdens else None

    overall = {"cases": TP + FN + FP + TN, "tp": TP, "fn": FN, "fp": FP, "tn": TN,
               "tpr": tpr, "fpr": fpr, "youden": youden, "macro_youden": macro}
    return per_cat, overall
