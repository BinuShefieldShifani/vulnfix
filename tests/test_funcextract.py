"""Tests for function-level extraction and splice-back across Python, Java, C#.
Pure logic, no model. Verifies: the right enclosing function is found, splicing
leaves the rest of the file untouched, and the spliced file is still valid."""
import ast
from eval.funcextract import extract_function, splice_function


# ---- Python ----
PY_FILE = '''import os

def helper(x):
    return x + 1

def vulnerable(cmd):
    os.system("echo " + cmd)   # line 7, the vulnerable sink
    return True

def unrelated():
    return 42
'''

def test_python_extracts_enclosing_function():
    span = extract_function(PY_FILE, 7, "python")
    assert span is not None
    assert span.name == "vulnerable"
    assert "os.system" in span.source
    # must NOT include the other functions
    assert "helper" not in span.source
    assert "unrelated" not in span.source


def test_python_splice_preserves_rest():
    span = extract_function(PY_FILE, 7, "python")
    fixed_fn = 'def vulnerable(cmd):\n    import subprocess\n    subprocess.run(["echo", cmd])\n    return True\n'
    out = splice_function(PY_FILE, span, fixed_fn)
    # the fix is in
    assert "subprocess.run" in out
    assert "os.system" not in out
    # the untouched functions are preserved
    assert "def helper(x):" in out
    assert "def unrelated():" in out
    # still valid python
    ast.parse(out)


def test_python_picks_innermost():
    # line inside 'vulnerable' must pick it, not module level
    span = extract_function(PY_FILE, 7, "python")
    assert span.name == "vulnerable"


# ---- Java ----
JAVA_FILE = '''public class Example {
    public void helper() {
        int x = 1;
    }
    public void ping(String host) throws Exception {
        Runtime.getRuntime().exec("ping " + host);
    }
    public int add(int a, int b) {
        return a + b;
    }
}
'''

def test_java_extracts_enclosing_method():
    # the exec line is line 6
    span = extract_function(JAVA_FILE, 6, "java")
    assert span is not None
    assert span.name == "ping"
    assert "exec" in span.source
    assert "add" not in span.source


def test_java_splice_preserves_rest():
    span = extract_function(JAVA_FILE, 6, "java")
    fixed = '    public void ping(String host) throws Exception {\n        new ProcessBuilder("ping", host).start();\n    }\n'
    out = splice_function(JAVA_FILE, span, fixed)
    assert "ProcessBuilder" in out
    assert "Runtime.getRuntime().exec" not in out
    assert "public void helper()" in out
    assert "public int add(int a, int b)" in out


# ---- C# ----
CS_FILE = '''public class Example {
    public string Build(string name) {
        return "SELECT * FROM u WHERE n = '" + name + "'";
    }
    public int Add(int a, int b) {
        return a + b;
    }
}
'''

def test_csharp_extracts_enclosing_method():
    span = extract_function(CS_FILE, 3, "csharp")
    assert span is not None
    assert span.name == "Build"
    assert "SELECT" in span.source
    assert "Add" not in span.source


def test_csharp_splice_preserves_rest():
    span = extract_function(CS_FILE, 3, "csharp")
    fixed = '    public string Build(string name) {\n        return "SELECT * FROM u WHERE n = @n";\n    }\n'
    out = splice_function(CS_FILE, span, fixed)
    assert "@n" in out
    assert "public int Add" in out


# ---- fallback ----
def test_unknown_language_returns_none():
    assert extract_function("some code", 1, "ruby") is None


def test_line_outside_any_function_returns_none():
    span = extract_function(PY_FILE, 1, "python")  # line 1 is 'import os'
    assert span is None
