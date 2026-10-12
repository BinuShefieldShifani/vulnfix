"""The behavior gate: a patch that is secure but breaks behavior must NOT be
validated once a behavior test is supplied, and behavior is ignored when no
test is given. Needs semgrep; skips without it."""
import shutil
import pytest
import validator
from models import Finding

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")

EVAL_ORIGINAL = "def compute(expr):\n    return eval(expr)\n"
# secure but broken: literal_eval can't do arithmetic
EVAL_BROKEN_FIX = "import ast\ndef compute(expr):\n    return ast.literal_eval(expr)\n"
# secure and working: a tiny safe arithmetic evaluator
EVAL_GOOD_FIX = (
    "import ast, operator\n"
    "_OPS={ast.Add:operator.add, ast.Sub:operator.sub, ast.Mult:operator.mul,\n"
    "      ast.Div:operator.truediv, ast.USub:operator.neg, ast.UAdd:operator.pos}\n"
    "def _ev(n):\n"
    "    if isinstance(n, ast.Expression): return _ev(n.body)\n"
    "    if isinstance(n, ast.Constant): return n.value\n"
    "    if isinstance(n, ast.BinOp): return _OPS[type(n.op)](_ev(n.left), _ev(n.right))\n"
    "    if isinstance(n, ast.UnaryOp): return _OPS[type(n.op)](_ev(n.operand))\n"
    "    raise ValueError('bad')\n"
    "def compute(expr):\n"
    "    return _ev(ast.parse(expr, mode='eval'))\n"
)
BEHAVIOR_TEST = "from app import compute\nassert compute('2 + 3') == 5\nprint('BEHAVIOR_OK')\n"


def _validate(original, patched, behavior_test=None):
    finding = Finding(rule_id="python.lang.security.audit.eval-detected",
                      file_path="app.py", cwe=["CWE-95"])
    out = validator.validator_node({
        "finding": finding, "source_code": original,
        "patched_code": patched, "behavior_test": behavior_test})
    return out["validation"]


@needs_semgrep
def test_broken_fix_rejected_when_behavior_test_present():
    v = _validate(EVAL_ORIGINAL, EVAL_BROKEN_FIX, BEHAVIOR_TEST)
    assert not v.validated
    assert "behavior" in v.notes.lower()


@needs_semgrep
def test_broken_fix_passes_security_without_behavior_test():
    # with no behavior test, the secure-but-broken patch still validates (old behavior)
    v = _validate(EVAL_ORIGINAL, EVAL_BROKEN_FIX, None)
    assert v.validated


@needs_semgrep
def test_good_fix_validates_with_behavior_test():
    v = _validate(EVAL_ORIGINAL, EVAL_GOOD_FIX, BEHAVIOR_TEST)
    assert v.validated, (v.notes, v.guardrail_issues)
