"""CI tests for the hallucination checker. Uses only stdlib modules so it's
deterministic on any machine. No model, no GPU."""
from eval.hallucination import check_python


def test_real_import_and_api_no_hallucination():
    r = check_python("import hashlib\ndef h(p):\n    return hashlib.sha256(p).hexdigest()\n")
    assert r.import_hallucinations == 0
    assert r.api_hallucinations == 0


def test_nonexistent_module_is_import_hallucination():
    r = check_python("import definitely_not_a_real_module_xyz\ndef f():\n    pass\n")
    assert r.import_hallucinations == 1


def test_fake_attribute_on_real_module_is_api_hallucination():
    r = check_python("import hashlib\ndef h(x):\n    return hashlib.not_a_real_function(x)\n")
    assert r.api_hallucinations == 1
    # the real import must not be flagged
    assert r.import_hallucinations == 0


def test_attr_on_unimportable_module_is_unverifiable_not_hallucination():
    r = check_python("import nope_not_real_pkg\ndef f():\n    return nope_not_real_pkg.go()\n")
    assert r.import_hallucinations == 1
    # attribute can't be checked, so it's unverifiable, not counted as api hallucination
    assert r.api_hallucinations == 0
    assert any(a["status"] == "unverifiable" for a in r.attributes)


def test_syntax_error_yields_empty_report():
    r = check_python("def broken(:\n   pass\n")
    assert r.import_hallucinations == 0
    assert r.api_hallucinations == 0


def test_real_stdlib_api_present():
    r = check_python("import os\ndef f(p):\n    return os.path.join('/a', p)\n")
    # os.path is an attribute of os -> ok
    assert all(a["status"] in ("ok", "unverifiable") for a in r.attributes)
    assert r.api_hallucinations == 0
