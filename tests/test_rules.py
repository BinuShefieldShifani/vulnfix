"""Regression tests for the custom Semgrep rules in vulnfix_rules.yml.

Each case is either an original bug, a known bad patch (from the June run),
or a correct fix. Bugs and bad patches must be flagged; correct fixes and the
negative control must not be.
"""
import json
import os
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULES = os.path.join(ROOT, "vulnfix_rules.yml")

CASES = [
    ("cmdi_original", "app.py", True, '''import os

def ping(host):
    os.system("ping -c 1 " + host)
'''),
    ("cmdi_june_bad_patch", "app.py", True, '''import os

def ping(host):
    os.system(f'ping -c 1 {host}')
'''),
    ("cmdi_correct_fix", "app.py", False, '''import subprocess

def ping(host):
    subprocess.run(["ping", "-c", "1", host], check=False)
'''),
    ("path_original", "app.py", True, '''def read_file(filename):
    with open("/var/data/" + filename) as f:
        return f.read()
'''),
    ("path_june_bad_patch", "app.py", True, '''from pathlib import Path

def read_file(filename):
    safe_path = Path('/var/data/') / filename
    with open(safe_path) as f:
        return f.read()
'''),
    ("path_run4_bad_patch", "app.py", True, '''import os

def read_file(filename):
    with open(os.path.join('/var/data/', filename)) as f:
        return f.read()
'''),
    ("path_correct_fix", "app.py", False, '''from pathlib import Path

BASE = Path("/var/data").resolve()

def read_file(filename):
    target = (BASE / filename).resolve()
    if not target.is_relative_to(BASE):
        raise ValueError("path escapes base directory")
    with open(target) as f:
        return f.read()
'''),
    ("eval_original", "app.py", True, '''def compute(expr):
    return eval(expr)
'''),
    ("eval_june_bad_patch", "app.py", True, '''import ast

def compute(expr):
    try:
        tree = ast.parse(expr, mode='eval')
        if isinstance(tree, ast.Expression) and isinstance(tree.body, (ast.BinOp, ast.UnaryOp, ast.Constant)):
            return eval(compile(tree, filename='<ast>', mode='eval'))
        else:
            raise ValueError('Invalid expression')
    except Exception as e:
        raise ValueError(f'Error evaluating expression: {e}')
'''),
    ("eval_correct_fix", "app.py", False, '''import ast

def compute(expr):
    return ast.literal_eval(expr)
'''),
    ("java_cmdi_original", "Example.java", True, '''public class Example {
    public void ping(String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
'''),
    ("java_cmdi_correct_fix", "Example.java", False, '''public class Example {
    public void ping(String host) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
        pb.start().waitFor();
    }
}
'''),
    ("negative_control", "app.py", False, '''import sqlite3


def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()
'''),
]


@pytest.fixture(scope="module")
def scan_results(tmp_path_factory):
    """Write every case into its own folder and scan them all in one Semgrep run."""
    base = tmp_path_factory.mktemp("rule_cases")
    for name, fname, _, code in CASES:
        (base / name).mkdir()
        (base / name / fname).write_text(code)
    out = subprocess.run(
        ["semgrep", "--config", RULES, "--json", "--quiet", str(base)],
        capture_output=True, text=True, timeout=600,
    )
    data = json.loads(out.stdout or "{}")
    assert not data.get("errors"), f"Semgrep rule errors: {data.get('errors')}"
    hits = {}
    for r in data.get("results", []):
        case = os.path.basename(os.path.dirname(r["path"]))
        hits.setdefault(case, []).append(r["check_id"])
    return hits


@pytest.mark.parametrize("name,fname,should_flag,code", CASES, ids=[c[0] for c in CASES])
def test_rule(scan_results, name, fname, should_flag, code):
    flagged = bool(scan_results.get(name))
    assert flagged == should_flag, (
        f"{name}: expected {'a hit' if should_flag else 'no hit'}, "
        f"got {scan_results.get(name, [])}"
    )
