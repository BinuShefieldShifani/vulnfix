"""Test the ensemble union scoring: the combined result must detect anything
either engine detects, and never score lower than the better single engine on
true positives."""
from eval.detect_combined import union_reported
from eval.detection import score_detection


def test_union_merges_findings():
    a = {"t1": {"89"}}
    b = {"t1": {"78"}, "t2": {"22"}}
    u = union_reported(a, b)
    assert u["t1"] == {"89", "78"}
    assert u["t2"] == {"22"}


def test_combined_detects_what_either_finds():
    gt = [
        {"id": "s1", "category": "sqli", "real": True, "cwe": "89"},   # only semgrep
        {"id": "c1", "category": "cmdi", "real": True, "cwe": "78"},   # only codeql
    ]
    semgrep = {"s1": {"89"}}
    codeql = {"c1": {"78"}}
    _, sem_overall = score_detection(gt, semgrep)
    _, cq_overall = score_detection(gt, codeql)
    _, comb_overall = score_detection(gt, union_reported(semgrep, codeql))
    assert sem_overall["tpr"] == 0.5
    assert cq_overall["tpr"] == 0.5
    assert comb_overall["tpr"] == 1.0   # union catches both
