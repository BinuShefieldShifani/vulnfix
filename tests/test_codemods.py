"""Codemods must produce fixes that pass the exploit + behavior oracles,
deterministically (no model)."""
from eval.codemods import try_codemod
from eval.sandbox import run_python


def test_ldap_codemod_fixes_injection():
    src = 'def build_filter(username):\n    return "(uid=" + username + ")"\n'
    fixed, name = try_codemod(["CWE-90"], src)
    assert fixed is not None
    driver = ('from app import build_filter\n'
              'f = build_filter("*)(uid=*")\n'
              'print("EXPLOITED" if "*)(uid=*" in f else "SAFE")\n')
    assert run_python(fixed, driver).output.strip().splitlines()[-1] == "SAFE"
    bdriver = ('from app import build_filter\n'
               'f = build_filter("alice")\n'
               'assert "alice" in f and f.startswith("(uid=")\n'
               'print("BEHAVIOR_OK")\n')
    assert "BEHAVIOR_OK" in run_python(fixed, bdriver).output


def test_openredirect_codemod_blocks_external():
    src = 'def redirect_target(next_url):\n    return next_url\n'
    fixed, name = try_codemod(["CWE-601"], src)
    assert fixed is not None
    driver = ('from app import redirect_target\n'
              'out = redirect_target("https://evil.example.com")\n'
              'print("EXPLOITED" if str(out).startswith("https://evil") else "SAFE")\n')
    assert run_python(fixed, driver).output.strip().splitlines()[-1] == "SAFE"
    bdriver = ('from app import redirect_target\n'
               'assert str(redirect_target("/x")).endswith("/x")\n'
               'print("BEHAVIOR_OK")\n')
    assert "BEHAVIOR_OK" in run_python(fixed, bdriver).output


def test_codemod_returns_none_for_unknown_cwe():
    fixed, name = try_codemod(["CWE-89"], "some sql code")
    assert fixed is None


def test_codemod_skips_already_safe_ldap():
    safe = 'def build_filter(u):\n    return "(uid=" + _ldap_escape(u) + ")"\n'
    fixed, name = try_codemod(["CWE-90"], safe)
    assert fixed is None
