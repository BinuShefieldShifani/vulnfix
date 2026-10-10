"""CI tests for the scorer, using fixed patches (no model). Confirms the
scorer maps known-good and known-bad patches to the right verdicts across all
four dimensions. Java tests skip without the toolchain.
"""
import shutil

import pytest

from eval.scorer import score_patch

needs_java = pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None,
    reason="java toolchain not installed")

GOOD = {
    "py-sqli": 'import sqlite3\ndef get_user(conn, username):\n    cur=conn.cursor()\n    cur.execute("SELECT * FROM users WHERE username = ?", (username,))\n    return cur.fetchone()\n',
    "py-cmdi": 'import subprocess\ndef ping(host):\n    subprocess.run(["echo", host], check=False)\n',
    "py-yaml": 'import yaml\ndef parse(text):\n    return yaml.safe_load(text)\n',
    "py-md5": 'import hashlib, os\ndef hash_password(pw):\n    salt=os.urandom(16)\n    return salt.hex()+":"+hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 100000).hex()\n',
    "py-path": 'import os\nfrom pathlib import Path\nBASE=Path(os.environ["VULNFIX_BASE"]).resolve()\ndef read_file(filename):\n    t=(BASE/filename).resolve()\n    if not t.is_relative_to(BASE): raise ValueError("escape")\n    return open(t).read()\n',
    "py-secret": 'import os, requests\nAPI_TOKEN=os.getenv("API_TOKEN")\ndef call():\n    return requests.get("https://api.example.com", headers={"Authorization": API_TOKEN})\n',
}


@pytest.mark.parametrize("cid", list(GOOD))
def test_good_patch_scores_well(cid):
    s = score_patch(cid, GOOD[cid])
    assert s.compiles
    if s.exploit != "na":
        assert s.exploit == "safe", s
    if s.behavior != "na":
        assert s.behavior == "ok", s


def test_fstring_cmdi_is_exploited():
    s = score_patch("py-cmdi", 'import os\ndef ping(host):\n    os.system(f"echo {host}")\n')
    assert s.exploit == "exploited", s


def test_pathjoin_is_exploited():
    bad = ('import os\nBASE=os.environ["VULNFIX_BASE"]\n'
           'def read_file(filename):\n    return open(os.path.join(BASE, filename)).read()\n')
    s = score_patch("py-path", bad)
    assert s.exploit == "exploited", s


def test_literal_eval_breaks_behavior():
    s = score_patch("py-eval", 'import ast\ndef compute(expr):\n    return ast.literal_eval(expr)\n')
    assert s.exploit == "safe"       # it is safe
    assert s.behavior == "broken"    # but it no longer computes


def test_fixed_salt_md5_breaks_behavior():
    s = score_patch("py-md5", 'import hashlib\ndef hash_password(pw):\n    return hashlib.pbkdf2_hmac("sha256", pw.encode(), b"salt", 100000)\n')
    assert s.behavior == "broken", s


def test_syntax_error_does_not_compile():
    s = score_patch("py-sqli", "def get_user(:\n    pass\n")
    assert not s.compiles


def test_secret_still_present_is_exploited():
    bad = 'import requests\nAPI_TOKEN="sk-live-9f8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c"\ndef call():\n    return requests.get("https://x", headers={"Authorization": API_TOKEN})\n'
    s = score_patch("py-secret", bad)
    assert s.exploit == "exploited", s


@needs_java
def test_java_cmdi_good_is_safe():
    good = ('public class Example {\n'
            '    public void ping(String host) throws Exception {\n'
            '        ProcessBuilder pb = new ProcessBuilder("echo", host);\n'
            '        pb.start().waitFor();\n'
            '    }\n}\n')
    s = score_patch("java-cmdi", good)
    assert s.compiles and s.exploit == "safe", s


def test_noncompiling_python_is_compile_fail_not_error():
    # exploit/behavior should read compile_fail, not error/broken, when code won't compile
    s = score_patch("py-cmdi", "def ping(:\n    pass\n")
    assert not s.compiles
    assert s.exploit == "compile_fail", s
