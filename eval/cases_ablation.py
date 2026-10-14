"""Additional hand-built runnable fix-cases for a well-powered retrieval
ablation (and extra generalization coverage). Same shape as cases.py /
cases_heldout.py: each has a vulnerable standalone function plus an exploit
oracle and (where meaningful) a behavior oracle. All stdlib-runnable.
"""

ABLATION_CASES = [
    # CWE-89 SQL injection via str.format
    {
        "id": "abl-sqli-format", "name": "SQL injection via str.format",
        "language": "python", "cwe": "CWE-89", "file": "app.py",
        "rule_id": "python.sqli.format",
        "code": '''import sqlite3
def get_user(conn, name):
    q = "SELECT * FROM users WHERE name = '{}'".format(name)
    return conn.execute(q).fetchone()
''',
        "exploit_driver": '''
import sqlite3
from app import get_user
c = sqlite3.connect(":memory:")
c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT)")
c.execute("INSERT INTO users(name) VALUES('admin')")
row = get_user(c, "x' OR '1'='1")
print("EXPLOITED" if row else "SAFE")
''',
        "behavior_driver": '''
import sqlite3
from app import get_user
c = sqlite3.connect(":memory:")
c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT)")
c.execute("INSERT INTO users(name) VALUES('alice')")
r = get_user(c, "alice")
assert r is not None and r[1] == "alice"
print("BEHAVIOR_OK")
''',
    },

    # CWE-78 command injection via subprocess shell=True
    {
        "id": "abl-cmdi-shelltrue", "name": "Command injection via shell=True",
        "language": "python", "cwe": "CWE-78", "file": "app.py",
        "rule_id": "python.cmdi.shelltrue",
        "code": '''import subprocess
def run(host):
    subprocess.run("echo " + host, shell=True)
''',
        "exploit_driver": '''
import os
from app import run
m = os.path.join(os.getcwd(), "pwned")
try:
    run("localhost; touch " + m)
except Exception:
    pass
print("EXPLOITED" if os.path.exists(m) else "SAFE")
''',
        "behavior_driver": None,
    },

    # CWE-327 weak cipher: DES
    {
        "id": "abl-weak-des", "name": "Weak cipher DES",
        "language": "python", "cwe": "CWE-327", "file": "app.py",
        "rule_id": "python.crypto.des",
        "code": '''import hashlib
def digest(data):
    # DES-like weak: using md5 as a stand-in weak primitive flagged by scanners
    return hashlib.new("md4", data).hexdigest()
''',
        # source-level oracle: md4/des are the weak primitives; a safe fix uses sha256+
        "exploit_driver": '''
with open("app.py") as f:
    src = f.read()
weak = any(w in src for w in ['"md4"', "'md4'", '"des"', "'des'", "DES.new", "pyDes"])
print("EXPLOITED" if weak else "SAFE")
''',
        "behavior_driver": '''
from app import digest
d = digest(b"hello")
assert isinstance(d, str) and len(d) > 0
print("BEHAVIOR_OK")
''',
    },

    # CWE-330 insecure random for session id
    {
        "id": "abl-weak-session", "name": "Insecure random session id",
        "language": "python", "cwe": "CWE-330", "file": "app.py",
        "rule_id": "python.random.session",
        "code": '''import random
def new_session():
    return str(random.randint(0, 999999))
''',
        "exploit_driver": '''
import random
from app import new_session
random.seed(7)
a = new_session()
random.seed(7)
b = new_session()
print("EXPLOITED" if a == b else "SAFE")
''',
        "behavior_driver": '''
from app import new_session
s = new_session()
assert isinstance(s, str) and len(s) > 0
print("BEHAVIOR_OK")
''',
    },

    # CWE-22 zipfile extraction traversal
    {
        "id": "abl-zip-traversal", "name": "Zip extraction path traversal",
        "language": "python", "cwe": "CWE-22", "file": "app.py",
        "rule_id": "python.zip.traversal",
        "code": '''import zipfile
def unpack(zip_path, dest):
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(dest)
''',
        # source oracle: naked extractall() with no member validation is the bug
        "exploit_driver": '''
with open("app.py") as f:
    src = f.read()
# safe fixes validate members / use a checked loop; naked extractall is vulnerable
has_extractall = "extractall" in src
has_guard = any(g in src for g in ["startswith", "realpath", "commonpath", "is_relative_to", "abspath"])
print("EXPLOITED" if (has_extractall and not has_guard) else "SAFE")
''',
        "behavior_driver": None,
    },

    # CWE-295 TLS verification disabled
    {
        "id": "abl-tls-noverify", "name": "TLS certificate verification disabled",
        "language": "python", "cwe": "CWE-295", "file": "app.py",
        "rule_id": "python.tls.noverify",
        "code": '''import ssl
def make_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
''',
        "exploit_driver": '''
import ssl
from app import make_context
ctx = make_context()
insecure = (ctx.verify_mode == ssl.CERT_NONE) or (ctx.check_hostname is False)
print("EXPLOITED" if insecure else "SAFE")
''',
        "behavior_driver": '''
from app import make_context
import ssl
ctx = make_context()
assert isinstance(ctx, ssl.SSLContext)
print("BEHAVIOR_OK")
''',
    },

    # CWE-502 YAML unsafe load (full loader)
    {
        "id": "abl-yaml-fullload", "name": "YAML unsafe full load",
        "language": "python", "cwe": "CWE-502", "file": "app.py",
        "rule_id": "python.yaml.fullload",
        "code": '''import yaml
def parse(text):
    return yaml.unsafe_load(text)
''',
        "exploit_driver": '''
import os
from app import parse
m = os.path.join(os.getcwd(), "pwned")
payload = "!!python/object/apply:os.system ['touch " + m + "']"
try:
    parse(payload)
except Exception:
    pass
print("EXPLOITED" if os.path.exists(m) else "SAFE")
''',
        "behavior_driver": '''
from app import parse
assert parse("a: 1") == {"a": 1}
print("BEHAVIOR_OK")
''',
    },

    # CWE-611 XXE via lxml with external entities
    {
        "id": "abl-xxe-lxml", "name": "XXE via lxml resolve_entities",
        "language": "python", "cwe": "CWE-611", "file": "app.py",
        "rule_id": "python.xxe.lxml",
        "code": '''from lxml import etree
def parse(xml):
    p = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.fromstring(xml.encode(), p).text
''',
        # source oracle: resolve_entities=True (or missing hardening) is the bug
        "exploit_driver": '''
with open("app.py") as f:
    src = f.read()
vuln = "resolve_entities=True" in src or ("XMLParser()" in src and "resolve_entities" not in src)
print("EXPLOITED" if vuln else "SAFE")
''',
        "behavior_driver": None,
    },

    # CWE-295 requests verify=False
    {
        "id": "abl-requests-noverify", "name": "requests verify disabled",
        "language": "python", "cwe": "CWE-295", "file": "app.py",
        "rule_id": "python.requests.noverify",
        "code": '''import requests
def fetch(url):
    return requests.get(url, verify=False)
''',
        "exploit_driver": '''
with open("app.py") as f:
    src = f.read()
print("EXPLOITED" if "verify=False" in src else "SAFE")
''',
        "behavior_driver": None,
    },

    # CWE-732 overly permissive umask/chmod on a key file
    {
        "id": "abl-worldreadable-key", "name": "World-readable private key",
        "language": "python", "cwe": "CWE-732", "file": "app.py",
        "rule_id": "python.perms.key",
        "code": '''import os
def save_key(data):
    with open("key.pem", "w") as f:
        f.write(data)
    os.chmod("key.pem", 0o644)
    return "key.pem"
''',
        "exploit_driver": '''
import os, stat
from app import save_key
p = save_key("secret")
mode = stat.S_IMODE(os.stat(p).st_mode)
# world- or group-readable private key material is the flaw
print("EXPLOITED" if (mode & 0o077) else "SAFE")
''',
        "behavior_driver": '''
from app import save_key
p = save_key("x")
assert open(p).read() == "x"
print("BEHAVIOR_OK")
''',
    },

    # CWE-367 assert used for a security check (stripped with -O)
    {
        "id": "abl-assert-auth", "name": "Security check via assert",
        "language": "python", "cwe": "CWE-617", "file": "app.py",
        "rule_id": "python.assert.auth",
        "code": '''def withdraw(user, amount, balance):
    assert amount <= balance, "insufficient funds"
    return balance - amount
''',
        # source oracle: a security/guard check implemented as assert is the bug
        "exploit_driver": '''
with open("app.py") as f:
    src = f.read()
# vulnerable if the guard is an assert and there's no real raise/if-check
has_assert_guard = "assert amount" in src
has_real_check = "raise" in src or ("if amount" in src and "raise" in src)
print("EXPLOITED" if (has_assert_guard and not has_real_check) else "SAFE")
''',
        "behavior_driver": '''
from app import withdraw
assert withdraw("u", 30, 100) == 70
print("BEHAVIOR_OK")
''',
    },

    # CWE-089 SQL injection via %-formatting
    {
        "id": "abl-sqli-percent", "name": "SQL injection via percent format",
        "language": "python", "cwe": "CWE-89", "file": "app.py",
        "rule_id": "python.sqli.percent",
        "code": '''import sqlite3
def find(conn, email):
    return conn.execute("SELECT * FROM u WHERE email = '%s'" % email).fetchone()
''',
        "exploit_driver": '''
import sqlite3
from app import find
c = sqlite3.connect(":memory:")
c.execute("CREATE TABLE u(id INTEGER PRIMARY KEY, email TEXT)")
c.execute("INSERT INTO u(email) VALUES('a@b.com')")
row = find(c, "x' OR '1'='1")
print("EXPLOITED" if row else "SAFE")
''',
        "behavior_driver": '''
import sqlite3
from app import find
c = sqlite3.connect(":memory:")
c.execute("CREATE TABLE u(id INTEGER PRIMARY KEY, email TEXT)")
c.execute("INSERT INTO u(email) VALUES('a@b.com')")
assert find(c, "a@b.com") is not None
print("BEHAVIOR_OK")
''',
    },

    # CWE-78 Java command injection via Runtime.exec with concatenation
    {
        "id": "abl-java-cmdi", "name": "Java command injection",
        "language": "java", "cwe": "CWE-78", "file": "Example.java",
        "rule_id": "java.cmdi.runtime",
        "code": '''public class Example {
    public void ping(String host) throws Exception {
        Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
    }
}
''',
        "exploit_driver": '''
public class Driver {
    public static void main(String[] a) throws Exception {
        java.io.File m = new java.io.File("pwned");
        try { new Example().ping("localhost ; touch pwned"); } catch (Exception e) {}
        Thread.sleep(400);
        System.out.println(m.exists() ? "EXPLOITED" : "SAFE");
    }
}
''',
        "behavior_driver": None,
    },

    # CWE-89 Java SQL injection via Statement concat
    {
        "id": "abl-java-sqli", "name": "Java SQL injection",
        "language": "java", "cwe": "CWE-89", "file": "Example.java",
        "rule_id": "java.sqli.stmt",
        "code": '''import java.sql.*;
public class Example {
    public String build(String name) {
        return "SELECT * FROM users WHERE name = '" + name + "'";
    }
}
''',
        "exploit_driver": '''
public class Driver {
    public static void main(String[] a) {
        String q = new Example().build("x' OR '1'='1");
        // if the attacker quote survives into the query structure, it's injectable
        boolean injectable = q.contains("OR '1'='1") && q.contains("'x'");
        System.out.println(injectable ? "EXPLOITED" : "SAFE");
    }
}
''',
        "behavior_driver": None,
    },

    # CWE-327 Java weak hash MD5
    {
        "id": "abl-java-md5", "name": "Java weak hash MD5",
        "language": "java", "cwe": "CWE-327", "file": "Example.java",
        "rule_id": "java.crypto.md5",
        "code": '''import java.security.MessageDigest;
public class Example {
    public byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
''',
        "exploit_driver": '''
public class Driver {
    public static void main(String[] a) throws Exception {
        // reflect on the source-equivalent: check the algorithm used is weak
        try {
            byte[] out = new Example().hash("x".getBytes());
            // MD5 produces 16 bytes; a safe fix (SHA-256) produces 32
            System.out.println(out.length == 16 ? "EXPLOITED" : "SAFE");
        } catch (Exception e) { System.out.println("SAFE"); }
    }
}
''',
        "behavior_driver": None,
    },
]

ABLATION_ORACLES = {
    c["id"]: {"language": c["language"],
              "exploit_driver": c["exploit_driver"],
              "behavior_driver": c["behavior_driver"]}
    for c in ABLATION_CASES
}
