"""Sanity tests for the evaluation oracles: structure plus the known-good /
known-bad Python patches. Proves the oracles themselves are correct before we
trust them to score model output. No LLM, no GPU. Java oracles are checked for
structure only here; they run for real in the harness on a machine with Java.
"""
import importlib.util
import os

import pytest

from eval.sandbox import run_python

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location(
    "eval_cases", os.path.join(HERE, "..", "eval", "cases.py"))
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)
ORACLES = cases.CASE_ORACLES

ALL_IDS = ["py-sqli", "py-cmdi", "py-eval", "py-pickle", "py-md5", "py-secret",
           "py-path", "py-yaml", "java-sqli", "java-cmdi", "neg-safe-sql"]


def test_all_cases_present():
    assert set(ORACLES) == set(ALL_IDS)


@pytest.mark.parametrize("cid", ALL_IDS)
def test_case_shape(cid):
    o = ORACLES[cid]
    assert o["language"] in ("python", "java")
    assert "exploit_driver" in o and "behavior_driver" in o


# Known-correct Python fixes: exploit must be SAFE, behavior OK where defined.
GOOD = {
    "py-sqli": 'import sqlite3\ndef get_user(conn, username):\n    cur=conn.cursor()\n    cur.execute("SELECT * FROM users WHERE username = ?", (username,))\n    return cur.fetchone()\n',
    "py-cmdi": 'import subprocess\ndef ping(host):\n    subprocess.run(["echo", host], check=False)\n',
    "py-md5": 'import hashlib, os\ndef hash_password(pw):\n    salt=os.urandom(16)\n    return salt.hex()+":"+hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 100000).hex()\n',
    "py-yaml": 'import yaml\ndef parse(text):\n    return yaml.safe_load(text)\n',
    "py-path": 'import os\nfrom pathlib import Path\nBASE=Path(os.environ["VULNFIX_BASE"]).resolve()\ndef read_file(filename):\n    t=(BASE/filename).resolve()\n    if not t.is_relative_to(BASE): raise ValueError("escape")\n    return open(t).read()\n',
    "neg-safe-sql": 'import sqlite3\ndef get_user(conn, username):\n    cur=conn.cursor()\n    cur.execute("SELECT * FROM users WHERE username = ?", (username,))\n    return cur.fetchone()\n',
}


@pytest.mark.parametrize("cid", list(GOOD))
def test_good_fix_is_safe(cid, tmp_path):
    o = ORACLES[cid]
    env = {"VULNFIX_BASE": str(tmp_path / "base")}
    ex = run_python(GOOD[cid], o["exploit_driver"], extra_env=env).output
    assert ex.strip().splitlines()[-1] == "SAFE", ex
    if o["behavior_driver"]:
        bh = run_python(GOOD[cid], o["behavior_driver"], extra_env=env).output
        assert "BEHAVIOR_OK" in bh, bh


# Known-bad patches must be caught, each on the right dimension.
def test_cmdi_fstring_is_exploited():
    bad = 'import os\ndef ping(host):\n    os.system(f"echo {host}")\n'
    out = run_python(bad, ORACLES["py-cmdi"]["exploit_driver"]).output
    assert "EXPLOITED" in out, out


def test_path_join_is_exploited(tmp_path):
    env = {"VULNFIX_BASE": str(tmp_path / "base")}
    bad = ('import os\n'
           'BASE=os.environ["VULNFIX_BASE"]\n'
           'def read_file(filename):\n'
           '    return open(os.path.join(BASE, filename)).read()\n')
    out = run_python(bad, ORACLES["py-path"]["exploit_driver"], extra_env=env).output
    assert "EXPLOITED" in out, out


def test_eval_literal_eval_breaks_behavior():
    bad = 'import ast\ndef compute(expr):\n    return ast.literal_eval(expr)\n'
    out = run_python(bad, ORACLES["py-eval"]["behavior_driver"]).output
    assert "BEHAVIOR_OK" not in out, out


def test_md5_fixed_salt_breaks_behavior():
    bad = 'import hashlib\ndef hash_password(pw):\n    return hashlib.pbkdf2_hmac("sha256", pw.encode(), b"salt", 100000)\n'
    out = run_python(bad, ORACLES["py-md5"]["behavior_driver"]).output
    assert "BEHAVIOR_OK" not in out, out
