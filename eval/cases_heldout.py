"""Held-out generalization set: CWEs the custom rules were NOT built for.

This is the robustness test. The home set (testcases.py) and the custom rules in
vulnfix_rules.yml were developed together, so strong home-set numbers could be
overfitting. These cases cover different CWEs the rules never saw, so the security
check falls back to public scanners (p/default + Bandit). Where those scanners do
not flag the original bug, the validator will honestly return "inconclusive" — that
inconclusive rate is itself a measurement of scanner coverage on new threats.

Same shape as testcases.py (each has id, name, language, cwe, rule_id, file, code)
plus eval/cases.py-style oracles (exploit_driver, behavior_driver). The harness
reads both together.
"""

HELDOUT_CASES = [
    # ---- SSRF (CWE-918) ----
    {
        "id": "py-ssrf",
        "name": "Python - server-side request forgery",
        "language": "python", "cwe": "CWE-918", "file": "app.py",
        "rule_id": "python.ssrf.audit",
        "code": '''import urllib.request


def fetch(url):
    return urllib.request.urlopen(url).read()
''',
        # Exploit: a safe fix must refuse non-allowlisted hosts / internal addresses.
        # We point at a link-local/loopback style target; a safe fix should raise,
        # an unsafe one will attempt the request (we treat "attempted" as exploited).
        "exploit_driver": '''
from app import fetch
# file:// is a classic SSRF escalation: a safe fix must not read local files.
import os, tempfile
secret = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
secret.write(b"TOPSECRET"); secret.close()
got = ""
try:
    got = fetch("file://" + secret.name)
    got = got.decode() if isinstance(got, bytes) else str(got)
except Exception:
    got = ""
print("EXPLOITED" if "TOPSECRET" in got else "SAFE")
''',
        "behavior_driver": None,
    },

    # ---- Weak randomness for security token (CWE-330) ----
    {
        "id": "py-weakrand",
        "name": "Python - insecure randomness for token",
        "language": "python", "cwe": "CWE-330", "file": "app.py",
        "rule_id": "python.weak-random.audit",
        "code": '''import random
import string


def make_token(n=16):
    return "".join(random.choice(string.ascii_letters) for _ in range(n))
''',
        # Exploit check: seed the stdlib RNG; if the token is reproducible from a
        # known seed, it is predictable -> exploitable. A secrets-based fix is not.
        "exploit_driver": '''
import random
from app import make_token
random.seed(1234)
a = make_token()
random.seed(1234)
b = make_token()
print("EXPLOITED" if a == b else "SAFE")
''',
        "behavior_driver": '''
from app import make_token
t = make_token(16)
assert isinstance(t, str) and len(t) == 16
print("BEHAVIOR_OK")
''',
    },

    # ---- Open redirect (CWE-601) ----
    {
        "id": "py-openredirect",
        "name": "Python - open redirect",
        "language": "python", "cwe": "CWE-601", "file": "app.py",
        "rule_id": "python.open-redirect.audit",
        "code": '''def redirect_target(next_url):
    # returns the Location a web handler would redirect to
    return next_url
''',
        # Exploit: an attacker-controlled absolute URL to another host must not be
        # returned as-is. A safe fix confines redirects to the local site.
        "exploit_driver": '''
from app import redirect_target
out = redirect_target("https://evil.example.com/phish")
print("EXPLOITED" if str(out).startswith("https://evil.example.com") else "SAFE")
''',
        "behavior_driver": '''
from app import redirect_target
# a legitimate relative path should still be allowed through
out = redirect_target("/dashboard")
assert out == "/dashboard" or str(out).endswith("/dashboard")
print("BEHAVIOR_OK")
''',
    },

    # ---- Insecure temporary file (CWE-377) ----
    {
        "id": "py-tmpfile",
        "name": "Python - insecure temporary file",
        "language": "python", "cwe": "CWE-377", "file": "app.py",
        "rule_id": "python.insecure-tempfile.audit",
        "code": '''import tempfile


def make_tmp():
    p = tempfile.mktemp()
    with open(p, "w") as f:
        f.write("data")
    return p
''',
        # Source-level oracle: mktemp() is the insecure construct (predictable name,
        # TOCTOU). A safe fix uses mkstemp/NamedTemporaryFile. The race itself is not
        # deterministically triggerable, so we detect the construct, not a live race.
        "exploit_driver": '''
with open("app.py") as f:
    src = f.read()
print("EXPLOITED" if "mktemp(" in src else "SAFE")
''',
        "behavior_driver": '''
import os
from app import make_tmp
p = make_tmp()
assert os.path.exists(p)
print("BEHAVIOR_OK")
''',
    },

    # ---- World-writable file permissions (CWE-732) ----
    {
        "id": "py-chmod",
        "name": "Python - overly permissive file permissions",
        "language": "python", "cwe": "CWE-732", "file": "app.py",
        "rule_id": "python.insecure-permissions.audit",
        "code": '''import os


def save(path, data):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, 0o777)
    return path
''',
        # Runtime oracle: after the fix, the written file must not be world-writable.
        "exploit_driver": '''
import os, stat
from app import save
p = save("out.txt", "x")
mode = stat.S_IMODE(os.stat(p).st_mode)
print("EXPLOITED" if (mode & 0o002) else "SAFE")
''',
        "behavior_driver": '''
from app import save
p = save("out2.txt", "hi")
assert open(p).read() == "hi"
print("BEHAVIOR_OK")
''',
    },

    # ---- LDAP injection (CWE-90) ----
    {
        "id": "py-ldap",
        "name": "Python - LDAP injection",
        "language": "python", "cwe": "CWE-90", "file": "app.py",
        "rule_id": "python.ldap-injection.audit",
        "code": '''def build_filter(username):
    return "(uid=" + username + ")"
''',
        # Exploit: a wildcard/injection payload changes the filter meaning. A safe
        # fix escapes LDAP special chars, so the payload cannot alter structure.
        "exploit_driver": '''
from app import build_filter
f = build_filter("*)(uid=*")
# if the dangerous metacharacters survive unescaped, the filter is injectable
print("EXPLOITED" if "*)(uid=*" in f else "SAFE")
''',
        "behavior_driver": '''
from app import build_filter
f = build_filter("alice")
assert "alice" in f and f.startswith("(uid=")
print("BEHAVIOR_OK")
''',
    },

    # ---- XXE (CWE-611, Java) ----
    {
        "id": "java-xxe",
        "name": "Java - XML external entity",
        "language": "java", "cwe": "CWE-611", "file": "Example.java",
        "rule_id": "java.xxe.audit",
        "code": '''import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;

public class Example {
    public String parse(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        DocumentBuilder b = f.newDocumentBuilder();
        Document d = b.parse(new ByteArrayInputStream(xml.getBytes()));
        return d.getDocumentElement().getTextContent();
    }
}
''',
        # Java XXE exploit needs a DOCTYPE with an external entity; a hardened
        # factory (disallow-doctype-decl) throws. We keep exploit None here because
        # it depends on parser/network setup; compile + rule/scanner coverage apply.
        "exploit_driver": None,
        "behavior_driver": None,
    },

    # ---- Insecure deserialization (CWE-502, Java) ----
    {
        "id": "java-deser",
        "name": "Java - insecure object deserialization",
        "language": "java", "cwe": "CWE-502", "file": "Example.java",
        "rule_id": "java.deserialization.audit",
        "code": '''import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class Example {
    public Object load(byte[] data) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data));
        return in.readObject();
    }
}
''',
        "exploit_driver": None,
        "behavior_driver": None,
    },
]

HELDOUT_BY_ID = {c["id"]: c for c in HELDOUT_CASES}

# Oracles in the eval/cases.py shape, keyed by id, for the ones that have them.
HELDOUT_ORACLES = {
    c["id"]: {"language": c["language"],
              "exploit_driver": c["exploit_driver"],
              "behavior_driver": c["behavior_driver"]}
    for c in HELDOUT_CASES
}
