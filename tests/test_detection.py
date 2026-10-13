"""Tests for the detection-scoring math. Pure logic, no scanner, no GPU."""
from eval.detection import score_detection


def test_perfect_scanner():
    # flags every real vuln, no false positives -> youden 1.0
    gt = [
        {"id": "t1", "category": "sqli", "real": True, "cwe": "89"},
        {"id": "t2", "category": "sqli", "real": False, "cwe": "89"},
    ]
    reported = {"t1": {"89"}}  # flagged the real one, not the fake one
    per_cat, overall = score_detection(gt, reported)
    assert overall["tpr"] == 1.0
    assert overall["fpr"] == 0.0
    assert overall["youden"] == 1.0


def test_flag_everything_scores_zero():
    # a scanner that flags all cases gets tpr 1 but fpr 1 -> youden 0
    gt = [
        {"id": "t1", "category": "sqli", "real": True, "cwe": "89"},
        {"id": "t2", "category": "sqli", "real": False, "cwe": "89"},
    ]
    reported = {"t1": {"89"}, "t2": {"89"}}
    _, overall = score_detection(gt, reported)
    assert overall["tpr"] == 1.0
    assert overall["fpr"] == 1.0
    assert overall["youden"] == 0.0


def test_flag_nothing_scores_zero():
    gt = [
        {"id": "t1", "category": "cmdi", "real": True, "cwe": "78"},
        {"id": "t2", "category": "cmdi", "real": False, "cwe": "78"},
    ]
    _, overall = score_detection(gt, {})
    assert overall["tpr"] == 0.0
    assert overall["fpr"] == 0.0
    assert overall["youden"] == 0.0


def test_cwe_alias_counts_as_match():
    # scanner reports CWE-77, expected is 78 (command injection) -> should match
    gt = [{"id": "t1", "category": "cmdi", "real": True, "cwe": "78"}]
    _, overall = score_detection(gt, {"t1": {"77"}})
    assert overall["tpr"] == 1.0


def test_wrong_cwe_does_not_match():
    # scanner reports an unrelated CWE -> not a detection
    gt = [{"id": "t1", "category": "sqli", "real": True, "cwe": "89"}]
    _, overall = score_detection(gt, {"t1": {"330"}})
    assert overall["tpr"] == 0.0


def test_per_category_breakdown():
    gt = [
        {"id": "s1", "category": "sqli", "real": True, "cwe": "89"},
        {"id": "s2", "category": "sqli", "real": True, "cwe": "89"},
        {"id": "c1", "category": "cmdi", "real": True, "cwe": "78"},
        {"id": "c2", "category": "cmdi", "real": False, "cwe": "78"},
    ]
    reported = {"s1": {"89"}, "c1": {"78"}, "c2": {"78"}}  # miss s2, false-flag c2
    per_cat, overall = score_detection(gt, reported)
    by = {c["category"]: c for c in per_cat}
    assert by["sqli"]["tpr"] == 0.5 and by["sqli"]["fpr"] is None
    assert by["cmdi"]["tpr"] == 1.0 and by["cmdi"]["fpr"] == 1.0
    assert by["cmdi"]["youden"] == 0.0
    assert overall["macro_youden"] is not None
