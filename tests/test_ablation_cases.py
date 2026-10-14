"""Prove the ablation oracles: each vulnerable original is EXPLOITED, and a
known-correct fix is SAFE (+ behavior OK where defined). Java cases run only
where the toolchain is present. No model, no GPU."""
import importlib.util
import os
import shutil
import pytest

from eval.sandbox import run_python, run_java

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location(
    "cases_ablation", os.path.join(HERE, "..", "eval", "cases_ablation.py"))
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
CASES = {c["id"]: c for c in A.ABLATION_CASES}
ORA = A.ABLATION_ORACLES

needs_java = pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None,
    reason="java toolchain not installed")

# known-correct fixes for every case
GOOD = {
    "abl-sqli-format": 'import sqlite3\ndef get_user(conn,name):\n    return conn.execute("SELECT * FROM users WHERE name=?",(name,)).fetchone()\n',
    "abl-cmdi-shelltrue": 'import subprocess\ndef run(host):\n    subprocess.run(["echo",host])\n',
    "abl-weak-des": 'import hashlib\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n',
    "abl-weak-session": 'import secrets\ndef new_session():\n    return secrets.token_hex(16)\n',
    "abl-zip-traversal": 'import zipfile, os\ndef unpack(zip_path,dest):\n    with zipfile.ZipFile(zip_path) as z:\n        for n in z.namelist():\n            t=os.path.realpath(os.path.join(dest,n))\n            if not t.startswith(os.path.realpath(dest)): raise ValueError("bad")\n        z.extractall(dest)\n',
    "abl-tls-noverify": 'import ssl\ndef make_context():\n    return ssl.create_default_context()\n',
    "abl-yaml-fullload": 'import yaml\ndef parse(text):\n    return yaml.safe_load(text)\n',
    "abl-xxe-lxml": 'from lxml import etree\ndef parse(xml):\n    p=etree.XMLParser(resolve_entities=False, no_network=True)\n    return etree.fromstring(xml.encode(), p).text\n',
    "abl-requests-noverify": 'import requests\ndef fetch(url):\n    return requests.get(url, verify=True)\n',
    "abl-worldreadable-key": 'import os\ndef save_key(data):\n    with open("key.pem","w") as f: f.write(data)\n    os.chmod("key.pem", 0o600)\n    return "key.pem"\n',
    "abl-assert-auth": 'def withdraw(user, amount, balance):\n    if amount > balance:\n        raise ValueError("insufficient funds")\n    return balance - amount\n',
    "abl-sqli-percent": 'import sqlite3\ndef find(conn, email):\n    return conn.execute("SELECT * FROM u WHERE email = ?", (email,)).fetchone()\n',
}
GOOD_JAVA = {
    "abl-java-cmdi": 'public class Example {\n    public void ping(String host) throws Exception {\n        new ProcessBuilder("ping","-c","1",host).start().waitFor();\n    }\n}\n',
    "abl-java-sqli": 'import java.sql.*;\npublic class Example {\n    public String build(String name) {\n        return "SELECT * FROM users WHERE name = ?";\n    }\n}\n',
    "abl-java-md5": 'import java.security.MessageDigest;\npublic class Example {\n    public byte[] hash(byte[] data) throws Exception {\n        return MessageDigest.getInstance("SHA-256").digest(data);\n    }\n}\n',
}

PY_IDS = [c["id"] for c in A.ABLATION_CASES if c["language"] == "python"]
JAVA_IDS = [c["id"] for c in A.ABLATION_CASES if c["language"] == "java"]


def test_fifteen_cases_ten_cwes():
    assert len(A.ABLATION_CASES) == 15
    assert len({c["cwe"] for c in A.ABLATION_CASES}) >= 9


@pytest.mark.parametrize("cid", PY_IDS)
def test_python_vuln_exploited(cid):
    o = ORA[cid]
    out = run_python(CASES[cid]["code"], o["exploit_driver"]).output
    assert out.strip().splitlines()[-1] == "EXPLOITED", out


@pytest.mark.parametrize("cid", PY_IDS)
def test_python_fix_safe(cid):
    o = ORA[cid]
    out = run_python(GOOD[cid], o["exploit_driver"]).output
    assert out.strip().splitlines()[-1] == "SAFE", out
    if o["behavior_driver"]:
        bh = run_python(GOOD[cid], o["behavior_driver"]).output
        assert "BEHAVIOR_OK" in bh, bh


@needs_java
@pytest.mark.parametrize("cid", JAVA_IDS)
def test_java_vuln_exploited(cid):
    o = ORA[cid]
    out = run_java(CASES[cid]["code"], o["exploit_driver"]).output
    assert out.strip().splitlines()[-1] == "EXPLOITED", out


@needs_java
@pytest.mark.parametrize("cid", JAVA_IDS)
def test_java_fix_safe(cid):
    o = ORA[cid]
    out = run_java(GOOD_JAVA[cid], o["exploit_driver"]).output
    assert out.strip().splitlines()[-1] == "SAFE", out
