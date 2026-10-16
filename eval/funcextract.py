"""Function-level extraction and splice-back for Python, Java, and C#.

Whole-file patching fails on large/multi-function files: the model rewrites
everything and mangles unrelated code (observed on a Flask app: invented classes,
broken literals, deleted main block). A real SAST finding points at a specific
line, so we extract just the ENCLOSING function around that line, fix only that,
and splice it back, leaving the rest of the file untouched.

Python uses the stdlib AST (exact and reliable). Java and C# use brace matching
(good for well-formed code, heuristic). If extraction can't confidently find the
enclosing function, callers fall back to whole-file patching (never worse).

Pure logic, no model, no GPU.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass
class FunctionSpan:
    name: str
    start_line: int      # 1-based, inclusive
    end_line: int        # 1-based, inclusive
    source: str          # the function's source text


# ---------------- Python (AST-based, exact) ----------------

def _extract_python(file_source: str, line: int):
    try:
        tree = ast.parse(file_source)
    except SyntaxError:
        return None
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None)
            if end is None:
                continue
            if start <= line <= end:
                # choose the innermost (smallest span) enclosing function
                if best is None or (end - start) < (best.end_line - best.start_line):
                    lines = file_source.splitlines()
                    src = "\n".join(lines[start - 1:end])
                    best = FunctionSpan(node.name, start, end, src)
    return best


# ---------------- Brace languages (Java, C#) ----------------

_METHOD_SIG = re.compile(
    r"\b(?:public|private|protected|internal|static|final|override|virtual|"
    r"async|sealed|abstract|\s)*"
    r"[\w<>\[\],\.\?]+\s+(\w+)\s*\([^;{]*\)\s*(?:throws[\w\s,\.]*)?\{")


def _extract_brace(file_source: str, line: int):
    lines = file_source.splitlines()
    # scan for method signatures; for each, brace-match to find its end
    candidates = []
    i = 0
    while i < len(lines):
        m = _METHOD_SIG.search(lines[i])
        if m:
            name = m.group(1)
            depth = 0
            started = False
            j = i
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    started = True
                if started and depth <= 0:
                    break
                j += 1
            start, end = i + 1, j + 1   # 1-based inclusive
            if start <= line <= end:
                candidates.append(FunctionSpan(
                    name, start, end, "\n".join(lines[start - 1:end])))
            i = j + 1
        else:
            i += 1
    if not candidates:
        return None
    # innermost (smallest) enclosing
    return min(candidates, key=lambda s: s.end_line - s.start_line)


def extract_function(file_source: str, line: int, language: str):
    """Return the FunctionSpan enclosing `line`, or None if not confidently found."""
    lang = (language or "").lower()
    if lang == "python":
        return _extract_python(file_source, line)
    if lang in ("java", "csharp", "cs", "c#"):
        return _extract_brace(file_source, line)
    return None


def splice_function(file_source: str, span: FunctionSpan, new_function: str):
    """Replace the function at `span` with `new_function`, keep the rest intact."""
    lines = file_source.splitlines(keepends=True)
    before = "".join(lines[:span.start_line - 1])
    after = "".join(lines[span.end_line:])
    new = new_function if new_function.endswith("\n") else new_function + "\n"
    # preserve a trailing newline boundary
    if before and not before.endswith("\n"):
        before += "\n"
    return before + new + after
