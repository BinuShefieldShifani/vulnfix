"""CI test for the summary math only (no model, no GPU). Checks the key gaps:
validated-but-exploitable and validated-but-broken.
"""
from eval.summary import summarize


def test_validated_but_exploitable_gap():
    rows = {"py-cmdi": [
        {"status": "validated", "validated": True, "exploit": "safe"},
        {"status": "validated", "validated": True, "exploit": "safe"},
        {"status": "validated", "validated": True, "exploit": "exploited"},
        {"status": "validated", "validated": True, "exploit": "exploited"},
    ]}
    s = summarize(rows, 4, {"py-cmdi": True}, {"py-cmdi": False})[0]
    assert s["validated_rate"] == 1.0
    assert s["truly_fixed_rate"] == 0.5
    assert s["validated_but_exploitable"] == 0.5
    assert s["errors"] == 0
    assert s["behavior_ok_rate"] is None


def test_errors_excluded_from_rates():
    rows = {"py-yaml": [
        {"status": "validated", "validated": True, "exploit": "safe", "behavior": "ok"},
        {"status": "ERROR: X"},
    ]}
    s = summarize(rows, 2, {"py-yaml": True}, {"py-yaml": True})[0]
    assert s["errors"] == 1
    assert s["truly_fixed_rate"] == 1.0
    assert s["behavior_ok_rate"] == 1.0


def test_behavior_broken_gap():
    rows = {"py-eval": [
        {"status": "validated", "validated": True, "exploit": "safe", "behavior": "broken"},
        {"status": "validated", "validated": True, "exploit": "safe", "behavior": "ok"},
    ]}
    s = summarize(rows, 2, {"py-eval": True}, {"py-eval": True})[0]
    assert s["behavior_ok_rate"] == 0.5
    assert s["validated_but_broken"] == 0.5
