"""Unit tests for the sandbox runner. No LLM, no GPU."""
import os
import shutil

import pytest

from eval.sandbox import run_python, run_java

needs_java = pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None,
    reason="java toolchain not installed")


def test_python_success():
    r = run_python("def add(a, b):\n    return a + b\n",
                   "from app import add\nassert add(2, 3) == 5\nprint('ok')")
    assert r.ok and "ok" in r.stdout


def test_python_assertion_failure_is_not_ok():
    r = run_python("def add(a, b):\n    return a + b\n",
                   "from app import add\nassert add(2, 3) == 6")
    assert not r.ok
    assert "AssertionError" in r.output


def test_python_timeout():
    r = run_python("def loop():\n    while True:\n        pass\n",
                   "from app import loop\nloop()", timeout=2.0)
    assert r.timed_out and not r.ok


def test_python_driver_sees_side_effect_file():
    # proves the driver can check for files the code under test creates
    r = run_python(
        "import os\ndef touch(p):\n    open(p, 'w').close()\n",
        "import os\nfrom app import touch\n"
        "touch('marker')\nprint('EXISTS' if os.path.exists('marker') else 'NO')")
    assert "EXISTS" in r.stdout


@needs_java
def test_java_success():
    src = "public class Example {\n    public int add(int a, int b) { return a + b; }\n}\n"
    drv = ("public class Driver {\n  public static void main(String[] a) {\n"
           "    if (new Example().add(2,3) == 5) System.out.println(\"ok\");\n"
           "    else throw new RuntimeException(\"bad\");\n  }\n}\n")
    r = run_java(src, drv)
    assert r.ok and "ok" in r.stdout


@needs_java
def test_java_compile_failure_is_reported():
    src = "public class Example {\n    public void oops() { int x = ; }\n}\n"
    drv = "public class Driver { public static void main(String[] a) {} }\n"
    r = run_java(src, drv)
    assert not r.ok
    assert "error" in r.output.lower()
