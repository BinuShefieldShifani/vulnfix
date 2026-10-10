"""Ground-truth exploit and behavior data for each VulnFix test case.

For every vulnerability in testcases.py we define, independently of the model,
scanners and validator:

  - exploit_driver: a program that feeds a malicious input to the patched code
    and prints "EXPLOITED" if the attack still works. If it prints EXPLOITED,
    the fix failed, whatever the scanners say.
  - behavior_driver: a program that feeds normal inputs and asserts the
    expected results, printing "BEHAVIOR_OK". If this fails, the fix changed
    what the function does.

These drivers import from `app` (Python) or call `Example` (Java), matching how
testcases.py writes each file. A case may legitimately have no exploit or no
behavior check (for example the negative control), in which case the field is
None and that dimension is skipped for that case.

Nothing here runs the model. These are fixed oracles the patched code is
measured against.
"""

# Each entry is keyed by the test-case id used in testcases.py.
# language is repeated here so the harness can pick the right sandbox runner.

CASE_ORACLES = {
    # ---- py-sqli: parameterized query expected ----
    "py-sqli": {
        "language": "python",
        # A classic tautology injection. With a safe (parameterized) query this
        # matches no username and returns None. With string building it returns
        # a row, leaking data.
        "exploit_driver": '''
import sqlite3
from app import get_user

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
conn.execute("INSERT INTO users (username) VALUES ('admin')")
conn.commit()

row = get_user(conn, "x' OR '1'='1")
print("EXPLOITED" if row else "SAFE")
''',
        "behavior_driver": '''
import sqlite3
from app import get_user

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
conn.execute("INSERT INTO users (username) VALUES ('alice')")
conn.commit()

row = get_user(conn, "alice")
assert row is not None and row[1] == "alice", row
assert get_user(conn, "nobody") is None
print("BEHAVIOR_OK")
''',
    },

    # ---- py-cmdi: subprocess without shell expected ----
    "py-cmdi": {
        "language": "python",
        # If the command still runs through a shell, the ; chains a second
        # command that creates a marker file.
        "exploit_driver": '''
import os
from app import ping

marker = os.path.join(os.getcwd(), "pwned")
# If the code runs through a shell, the ; chains a touch. A safe fix passes the
# whole string as one argument to the command, so no marker is created.
try:
    ping("localhost ; touch " + marker)
except Exception:
    pass
print("EXPLOITED" if os.path.exists(marker) else "SAFE")
''',
        # Normal host: the call should complete without raising. We can't rely
        # on real network, so we only require it does not throw for a plain host.
        "behavior_driver": None,
    },

    # ---- py-eval: safe evaluation expected ----
    "py-eval": {
        "language": "python",
        # If eval still runs arbitrary code, this expression creates a marker.
        "exploit_driver": '''
import os
from app import compute

marker = os.path.join(os.getcwd(), "pwned")
payload = "__import__('os').system('touch " + marker + "')"
try:
    compute(payload)
except Exception:
    pass
print("EXPLOITED" if os.path.exists(marker) else "SAFE")
''',
        # The function is named compute: a simple arithmetic expression should
        # still evaluate. ast.literal_eval breaks this, which is the known
        # behavior regression we want to catch.
        "behavior_driver": '''
from app import compute
r = compute("2 + 3")
assert r == 5, r
print("BEHAVIOR_OK")
''',
    },

    # ---- py-pickle: safe deserialization expected ----
    "py-pickle": {
        "language": "python",
        # A malicious pickle that runs code on load. If load() still uses
        # pickle/dill, the marker appears.
        "exploit_driver": '''
import os, pickle
from app import load

marker = os.path.join(os.getcwd(), "pwned")

class Evil:
    def __reduce__(self):
        return (os.system, ("touch " + marker,))

blob = pickle.dumps(Evil())
try:
    load(blob)
except Exception:
    pass
print("EXPLOITED" if os.path.exists(marker) else "SAFE")
''',
        # Behavior is intentionally None: a safe fix (json) and the original
        # (pickle) accept different input formats, so there is no single
        # behavior contract that is fair across fixes. We score pickle on
        # exploit + compile only.
        "behavior_driver": None,
    },

    # ---- py-md5: strong password hash expected ----
    "py-md5": {
        "language": "python",
        # Not a runtime exploit. We check the weakness is gone: the output must
        # not be a 32-char MD5 hex digest of the input.
        "exploit_driver": '''
import hashlib
from app import hash_password

out = hash_password("correct horse")
md5_hex = hashlib.md5("correct horse".encode()).hexdigest()
same_as_md5 = (isinstance(out, str) and out == md5_hex)
print("EXPLOITED" if same_as_md5 else "SAFE")
''',
        # A good password hash must produce different outputs for the same
        # password across calls (salting). A hardcoded salt fails this, which
        # catches the Run 4 pbkdf2-with-fixed-salt patch.
        "behavior_driver": '''
from app import hash_password
a = hash_password("same-password")
b = hash_password("same-password")
assert a != b, "identical hashes for the same password: salt is missing or hardcoded"
print("BEHAVIOR_OK")
''',
    },

    # ---- py-secret: no hardcoded credential expected ----
    "py-secret": {
        "language": "python",
        # The leaked token must not be present as a literal in the source after
        # the fix. This is a source check run inside the sandbox for uniformity.
        "exploit_driver": '''
with open("app.py") as f:
    src = f.read()
print("EXPLOITED" if "sk-live-9f8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c" in src else "SAFE")
''',
        "behavior_driver": None,
    },

    # ---- py-path: path traversal blocked expected ----
    "py-path": {
        "language": "python",
        # Create a secret outside the base dir, then try to read it via ../.
        # If the patched read_file returns the secret, traversal still works.
        "exploit_driver": '''
import os, tempfile
from app import read_file

# /var/data may not exist in the sandbox; create it so a safe fix can resolve.
try:
    os.makedirs("/var/data", exist_ok=True)
    open("/var/data/ok.txt", "w").write("inside")
except Exception:
    pass

secret_dir = tempfile.mkdtemp()
secret = os.path.join(secret_dir, "secret.txt")
open(secret, "w").write("TOPSECRET")

# relative traversal from /var/data up to the secret
rel = os.path.relpath(secret, "/var/data")
got = ""
try:
    got = read_file(rel)
except Exception:
    got = ""

# also try an absolute path
got2 = ""
try:
    got2 = read_file(secret)
except Exception:
    got2 = ""

leaked = ("TOPSECRET" in (got or "")) or ("TOPSECRET" in (got2 or ""))
print("EXPLOITED" if leaked else "SAFE")
''',
        # A legitimate file inside the base dir should still be readable.
        "behavior_driver": '''
import os
from app import read_file
os.makedirs("/var/data", exist_ok=True)
open("/var/data/ok.txt", "w").write("inside")
try:
    content = read_file("ok.txt")
    assert "inside" in content, content
    print("BEHAVIOR_OK")
except Exception as e:
    print("BEHAVIOR_FAIL:" + type(e).__name__)
''',
    },

    # ---- py-yaml: safe_load expected ----
    "py-yaml": {
        "language": "python",
        # A YAML payload that constructs a Python object via the unsafe loader.
        # With safe_load this raises or returns a plain structure; the marker is
        # never created.
        "exploit_driver": '''
import os
from app import parse

marker = os.path.join(os.getcwd(), "pwned")
payload = "!!python/object/apply:os.system ['touch " + marker + "']"
try:
    parse(payload)
except Exception:
    pass
print("EXPLOITED" if os.path.exists(marker) else "SAFE")
''',
        "behavior_driver": '''
from app import parse
data = parse("name: alice\\nage: 30\\n")
assert data == {"name": "alice", "age": 30}, data
print("BEHAVIOR_OK")
''',
    },

    # ---- java-sqli: PreparedStatement expected ----
    "java-sqli": {
        "language": "java",
        # Uses SQLite JDBC if present; if the driver is unavailable the harness
        # will mark this exploit as inconclusive rather than failing. The driver
        # here focuses on behavior; exploit for Java SQLi needs a DB driver, so
        # we keep exploit None and rely on compile + rule checks for Java SQLi.
        "exploit_driver": None,
        "behavior_driver": None,
    },

    # ---- java-cmdi: ProcessBuilder expected ----
    "java-cmdi": {
        "language": "java",
        # If the command runs through a shell, "; touch pwned" creates a file.
        # ProcessBuilder with separate args treats the whole thing as one
        # argument to ping, so no marker appears.
        "exploit_driver": '''
public class Driver {
    public static void main(String[] args) throws Exception {
        java.io.File marker = new java.io.File("pwned");
        try {
            // If exec runs via a shell, the ; chains a touch. ProcessBuilder
            // with separate args passes the whole string as one argument.
            new Example().ping("localhost ; touch pwned");
        } catch (Exception e) { /* ignore */ }
        Thread.sleep(500);
        System.out.println(marker.exists() ? "EXPLOITED" : "SAFE");
    }
}
''',
        "behavior_driver": None,
    },

    # ---- negative control: must not be changed ----
    "neg-safe-sql": {
        "language": "python",
        # Already safe. The tautology must not leak, and normal lookups work.
        "exploit_driver": '''
import sqlite3
from app import get_user
conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
conn.execute("INSERT INTO users (username) VALUES ('admin')")
conn.commit()
row = get_user(conn, "x' OR '1'='1")
print("EXPLOITED" if row else "SAFE")
''',
        "behavior_driver": '''
import sqlite3
from app import get_user
conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
conn.execute("INSERT INTO users (username) VALUES ('alice')")
conn.commit()
row = get_user(conn, "alice")
assert row is not None and row[1] == "alice", row
print("BEHAVIOR_OK")
''',
    },
}
