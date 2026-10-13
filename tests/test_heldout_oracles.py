"""Prove the held-out oracles are correct: each vulnerable original is detected
as EXPLOITED, and a known-correct fix is SAFE with behavior preserved. No model,
no GPU. Java cases are structure-only here (compile/scanner-checked in the harness).
"""
import importlib.util
import os
import pytest
from eval.sandbox import run_python

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location(
    "cases_heldout", os.path.join(HERE, "..", "eval", "cases_heldout.py"))
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
ORA = H.HELDOUT_ORACLES
CASES = {c["id"]: c for c in H.HELDOUT_CASES}

ALL = ["py-ssrf","py-weakrand","py-openredirect","py-tmpfile","py-chmod","py-ldap","java-xxe","java-deser"]
PY_SCORED = ["py-ssrf","py-weakrand","py-openredirect","py-tmpfile","py-chmod","py-ldap"]

GOOD = {
 "py-ssrf":'import urllib.request\nfrom urllib.parse import urlparse\ndef fetch(url):\n    p=urlparse(url)\n    if p.scheme not in ("http","https"): raise ValueError("blocked")\n    if p.hostname in ("localhost","127.0.0.1","0.0.0.0","169.254.169.254"): raise ValueError("blocked")\n    return urllib.request.urlopen(url).read()\n',
 "py-weakrand":'import secrets, string\ndef make_token(n=16):\n    return "".join(secrets.choice(string.ascii_letters) for _ in range(n))\n',
 "py-openredirect":'def redirect_target(next_url):\n    if not str(next_url).startswith("/") or str(next_url).startswith("//"): return "/"\n    return next_url\n',
 "py-tmpfile":'import tempfile, os\ndef make_tmp():\n    fd,p=tempfile.mkstemp()\n    with os.fdopen(fd,"w") as f: f.write("data")\n    return p\n',
 "py-chmod":'import os\ndef save(path,data):\n    with open(path,"w") as f: f.write(data)\n    os.chmod(path,0o600)\n    return path\n',
 "py-ldap":'def build_filter(username):\n    esc="".join("\\\\%02x"%ord(ch) if ch in "*()\\\\\\x00" else ch for ch in username)\n    return "(uid="+esc+")"\n',
}


def test_all_cases_present():
    assert set(CASES) == set(ALL)


def test_eight_distinct_new_cwes():
    cwes = {c["cwe"] for c in H.HELDOUT_CASES}
    assert len(cwes) == 8
    # none of these are the custom-rule CWEs (78/95/22 core shapes)
    assert "CWE-918" in cwes and "CWE-330" in cwes


@pytest.mark.parametrize("cid", PY_SCORED)
def test_vuln_original_is_exploited(cid):
    o = ORA[cid]
    out = run_python(CASES[cid]["code"], o["exploit_driver"]).output
    assert out.strip().splitlines()[-1] == "EXPLOITED", out


@pytest.mark.parametrize("cid", list(GOOD))
def test_good_fix_is_safe_and_works(cid):
    o = ORA[cid]
    ex = run_python(GOOD[cid], o["exploit_driver"]).output
    assert ex.strip().splitlines()[-1] == "SAFE", ex
    if o["behavior_driver"]:
        bh = run_python(GOOD[cid], o["behavior_driver"]).output
        assert "BEHAVIOR_OK" in bh, bh
