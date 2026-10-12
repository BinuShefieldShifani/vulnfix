"""Extra checks for the robust behavior gate: a skip is reported in notes and
never silently passes a broken patch. Appended to the existing gate tests.
Needs semgrep; skips without it."""
import shutil
import pytest
import validator
from models import Finding

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")

EVAL_ORIGINAL = "def compute(expr):\n    return eval(expr)\n"
EVAL_BROKEN_FIX = "import ast\ndef compute(expr):\n    return ast.literal_eval(expr)\n"
BEHAVIOR_TEST = "from app import compute\nassert compute('2 + 3') == 5\nprint('BEHAVIOR_OK')\n"


def _v(original, patched, bt):
    f = Finding(rule_id="python.lang.security.audit.eval-detected",
                file_path="app.py", cwe=["CWE-95"])
    return validator.validator_node({
        "finding": f, "source_code": original,
        "patched_code": patched, "behavior_test": bt})["validation"]


@needs_semgrep
def test_broken_fix_blocked_and_noted():
    v = _v(EVAL_ORIGINAL, EVAL_BROKEN_FIX, BEHAVIOR_TEST)
    assert not v.validated
    assert "behavior test failed" in v.notes


@needs_semgrep
def test_run_function_returns_tuple():
    # the runner must return (issue, ran) now, not a bare string
    issue, ran = validator._run_behavior_test("app.py", EVAL_BROKEN_FIX, BEHAVIOR_TEST)
    assert ran is True and issue == "behavior test failed"
    # no test supplied -> no run, no issue
    issue2, ran2 = validator._run_behavior_test("app.py", EVAL_BROKEN_FIX, None)
    assert ran2 is False and issue2 == ""
