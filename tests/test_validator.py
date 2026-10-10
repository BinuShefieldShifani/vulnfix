"""Tests for validator.py that need no LLM: the compile check, CWE matching,
and the full validator node on known good and bad patches.

Tests that need a tool (semgrep or the Java toolchain) skip when it is absent,
so the suite is green on a laptop and fully exercised on CI.
"""
import shutil

import pytest

import validator
from models import Finding

needs_javac = pytest.mark.skipif(
    shutil.which("javac") is None, reason="javac not installed")
needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")

# --- compile check ------------------------------------------------------------

def test_python_compiles():
    assert validator._compile_check("app.py", "def f(x):\n    return x + 1\n") == ""


def test_python_syntax_error_is_reported():
    assert "SyntaxError" in validator._compile_check("app.py", "def f(:\n    return 1\n")


JAVA_RUN3_BAD = '''import java.io.IOException;
import java.util.Arrays;

public class Example {
    public void ping(String host) throws IOException {
        if (host == null || host.isEmpty() || !isValidHost(host)) {
            throw new IllegalArgumentException("Invalid host");
        }
        ProcessBuilder pb = new ProcessBuilder(Arrays.asList("ping", "-c", "1", host));
        pb.redirectErrorStream(true);
        Process process = pb.start();
        process.waitFor();
    }

    private boolean isValidHost(String host) {
        return host.matches("^[a-zA-Z0-9.-]+$");
    }
}
'''

JAVA_RUN4_GOOD = '''import java.io.IOException;

public class Example {
    public void ping(String host) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
        Process process = pb.start();
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("Ping failed with exit code: " + exitCode);
        }
    }
}
'''

JAVA_CMDI_ORIGINAL = '''public class Example {
    public void ping(String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
'''


@needs_javac
def test_java_run3_patch_does_not_compile():
    assert "InterruptedException" in validator._compile_check("Example.java", JAVA_RUN3_BAD)


@needs_javac
def test_java_run4_patch_compiles():
    assert validator._compile_check("Example.java", JAVA_RUN4_GOOD) == ""

# --- CWE matching ---------------------------------------------------------------

def test_unrelated_hit_is_ignored():
    # Bandit B113 (missing requests timeout) is CWE-400, unrelated to a hardcoded secret
    assert not validator._is_related({"cwes": {"CWE-400"}}, ["CWE-798"])


def test_related_cwe_alias_matches():
    # Bandit tags hardcoded passwords as CWE-259, which counts for CWE-798
    assert validator._is_related({"cwes": {"CWE-259"}}, ["CWE-798"])


def test_no_finding_cwe_matches_everything():
    assert validator._is_related({"cwes": {"CWE-400"}}, [])

# --- full validator node ----------------------------------------------------------

def _validate(file_path, cwe, original, patched):
    finding = Finding(rule_id="test", file_path=file_path, cwe=cwe)
    out = validator.validator_node(
        {"finding": finding, "source_code": original, "patched_code": patched})
    return out["validation"]


PY_CMDI_ORIGINAL = '''import os


def ping(host):
    os.system("ping -c 1 " + host)
'''


@needs_semgrep
def test_fstring_bypass_is_rejected():
    """The June bad patch: same shell call, now with an f-string."""
    v = _validate("app.py", ["CWE-78"], PY_CMDI_ORIGINAL, '''import os


def ping(host):
    os.system(f'ping -c 1 {host}')
''')
    assert v.ran_semgrep
    assert not v.validated


@needs_semgrep
def test_subprocess_list_fix_is_validated():
    v = _validate("app.py", ["CWE-78"], PY_CMDI_ORIGINAL, '''import subprocess


def ping(host):
    subprocess.run(["ping", "-c", "1", host], check=False)
''')
    assert v.validated, v.notes


@needs_semgrep
def test_dill_swap_is_rejected():
    """The model's trick from the pickle retest: dill has the same flaw."""
    v = _validate("app.py", ["CWE-502"], '''import pickle


def load(blob):
    return pickle.loads(blob)
''', '''import dill


def load(blob):
    return dill.loads(blob)
''')
    assert not v.validated


@needs_semgrep
def test_negative_control_is_inconclusive():
    safe = '''import sqlite3


def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()
'''
    v = _validate("app.py", [], safe, safe)
    assert v.inconclusive
    assert not v.validated


@needs_javac
@needs_semgrep
def test_non_compiling_java_patch_is_rejected():
    v = _validate("Example.java", ["CWE-78"], JAVA_CMDI_ORIGINAL, JAVA_RUN3_BAD)
    assert not v.validated
    assert any("does not compile" in g for g in v.guardrail_issues)


@needs_javac
@needs_semgrep
def test_compiling_java_patch_is_validated():
    v = _validate("Example.java", ["CWE-78"], JAVA_CMDI_ORIGINAL, JAVA_RUN4_GOOD)
    assert v.validated, (v.notes, v.guardrail_issues)
