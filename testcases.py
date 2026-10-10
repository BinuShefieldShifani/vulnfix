"""Labeled test cases for evaluating the remediation pipeline. Each spans a
CWE class the system should handle. `rule_id` is a human label — validation is
driven by what Semgrep actually detects, not this string. Negative controls
contain no vulnerability and should NOT be 'fixed'."""

TEST_CASES = [
    {
        "id": "py-sqli",
        "name": "Python — SQL injection (string format)",
        "language": "python", "cwe": "CWE-89", "file": "app.py",
        "rule_id": "python.lang.security.audit.formatted-sql-query",
        "code": '''import sqlite3


def get_user(conn, username):
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cur.execute(query)
    return cur.fetchone()
''',
    },
    {
        "id": "py-cmdi",
        "name": "Python — OS command injection",
        "language": "python", "cwe": "CWE-78", "file": "app.py",
        "rule_id": "python.lang.security.audit.dangerous-os-system",
        "code": '''import os


def ping(host):
    os.system("ping -c 1 " + host)
''',
    },
    {
        "id": "py-eval",
        "name": "Python — code injection (eval)",
        "language": "python", "cwe": "CWE-95", "file": "app.py",
        "rule_id": "python.lang.security.audit.eval-detected",
        "code": '''def compute(expr):
    return eval(expr)
''',
    },
    {
        "id": "py-pickle",
        "name": "Python — unsafe deserialization (pickle)",
        "language": "python", "cwe": "CWE-502", "file": "app.py",
        "rule_id": "python.lang.security.deserialization.pickle",
        "code": '''import pickle


def load(blob):
    return pickle.loads(blob)
''',
    },
    {
        "id": "py-md5",
        "name": "Python — weak hash for password (MD5)",
        "language": "python", "cwe": "CWE-327", "file": "app.py",
        "rule_id": "python.lang.security.audit.md5-used-as-password",
        "code": '''import hashlib


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
''',
    },
    {
        "id": "py-secret",
        "name": "Python — hardcoded credentials",
        "language": "python", "cwe": "CWE-798", "file": "app.py",
        "rule_id": "python.lang.security.audit.hardcoded-password",
        "code": '''import requests

API_TOKEN = "sk-live-9f8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c"


def call():
    return requests.get("https://api.example.com",
                        headers={"Authorization": API_TOKEN})
''',
    },
    {
        "id": "py-path",
        "name": "Python — path traversal",
        "language": "python", "cwe": "CWE-22", "file": "app.py",
        "rule_id": "python.lang.security.audit.path-traversal",
        "code": '''def read_file(filename):
    with open("/var/data/" + filename) as f:
        return f.read()
''',
    },
    {
        "id": "py-yaml",
        "name": "Python — insecure YAML load",
        "language": "python", "cwe": "CWE-502", "file": "app.py",
        "rule_id": "python.lang.security.audit.insecure-yaml-load",
        "code": '''import yaml


def parse(text):
    return yaml.load(text)
''',
    },
    {
        "id": "java-sqli",
        "name": "Java — SQL injection (Statement concat)",
        "language": "java", "cwe": "CWE-89", "file": "Example.java",
        "rule_id": "java.lang.security.audit.sqli.jdbc-sqli",
        "code": '''import java.sql.*;

public class Example {
    public ResultSet getUser(Connection conn, String name) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
''',
    },
    {
        "id": "java-cmdi",
        "name": "Java — command injection (Runtime.exec)",
        "language": "java", "cwe": "CWE-78", "file": "Example.java",
        "rule_id": "java.lang.security.audit.command-injection",
        "code": '''public class Example {
    public void ping(String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
''',
    },
    {
        "id": "neg-safe-sql",
        "name": "Negative control — already parameterized query",
        "language": "python", "cwe": "(none)", "file": "app.py",
        "rule_id": "(none)",
        "code": '''import sqlite3


def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()
''',
    },
]

CASES_BY_NAME = {c["name"]: c for c in TEST_CASES}