"""Test the judge calibration math and verdict parsing. No model."""
from eval.judge import parse_verdict, calibrate, CATEGORIES


def test_parse_clean_verdicts():
    assert parse_verdict("good_fix") == "good_fix"
    assert parse_verdict("still_vulnerable") == "still_vulnerable"
    assert parse_verdict("The patch is secure_but_broken.") == "secure_but_broken"


def test_parse_loose():
    assert parse_verdict("this is still vulnerable to injection") == "still_vulnerable"
    assert parse_verdict("looks like a good correct fix") in ("good_fix",)
    assert parse_verdict("gibberish") == "unsure"


def test_calibrate_perfect_agreement():
    human = {0: "good_fix", 1: "still_vulnerable", 2: "secure_but_broken"}
    judge = dict(human)
    m = calibrate(human, judge)
    assert m["accuracy"] == 1.0
    assert m["miss_rate_on_bad"] == 0.0


def test_calibrate_catches_missed_bad_patches():
    # judge calls two bad patches "good" -> miss rate should reflect it
    human = {0: "still_vulnerable", 1: "secure_but_broken", 2: "good_fix"}
    judge = {0: "good_fix", 1: "good_fix", 2: "good_fix"}
    m = calibrate(human, judge)
    assert m["bad_patches_total"] == 2
    assert m["bad_patches_called_good"] == 2
    assert m["miss_rate_on_bad"] == 1.0
    assert m["accuracy"] == round(1/3, 3)


def test_confusion_populated():
    human = {0: "good_fix", 1: "good_fix"}
    judge = {0: "good_fix", 1: "still_vulnerable"}
    m = calibrate(human, judge)
    assert m["confusion"]["good_fix"]["good_fix"] == 1
    assert m["confusion"]["good_fix"]["still_vulnerable"] == 1
