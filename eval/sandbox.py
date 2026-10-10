"""Run a snippet of Python or Java in a locked-down subprocess.

Why a subprocess and not exec(): the code under test is both attacker input
and model-written, so it must not run in the harness process. Each run gets
its own temp directory, a wall-clock timeout, and no inherited environment.
Network is not available inside Kaggle/CI runners by default for these calls,
and the working directory is isolated and deleted afterwards.

Nothing here imports the model or the validator. These are pure mechanics.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass


@dataclass
class RunResult:
    ok: bool            # process exited 0
    timed_out: bool
    stdout: str
    stderr: str
    returncode: int | None

    @property
    def output(self) -> str:
        return (self.stdout or "") + (self.stderr or "")


def _run(cmd, cwd, timeout, env=None):
    try:
        p = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True,
            timeout=timeout, env=env,
        )
        return RunResult(p.returncode == 0, False, p.stdout, p.stderr, p.returncode)
    except subprocess.TimeoutExpired as e:
        return RunResult(False, True, e.stdout or "", e.stderr or "", None)
    except (OSError, subprocess.SubprocessError) as e:
        return RunResult(False, False, "", str(e), None)


def _clean_env():
    # Minimal environment: keep PATH so interpreters are found, drop the rest.
    keep = {}
    for k in ("PATH", "HOME", "LANG", "LC_ALL"):
        if k in os.environ:
            keep[k] = os.environ[k]
    return keep


def run_python(source: str, driver: str, timeout: float = 15.0) -> RunResult:
    """Write `source` as app.py, then run `driver` (which may import from app)."""
    workdir = tempfile.mkdtemp(prefix="vulnfix_py_")
    try:
        with open(os.path.join(workdir, "app.py"), "w") as fh:
            fh.write(source)
        with open(os.path.join(workdir, "driver.py"), "w") as fh:
            fh.write(driver)
        return _run(["python", "driver.py"], workdir, timeout, _clean_env())
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _java_class_name(source: str, default: str) -> str:
    m = re.search(r"public\s+(?:final\s+|abstract\s+)*class\s+(\w+)", source)
    return m.group(1) if m else default


def run_java(source: str, driver: str, timeout: float = 60.0) -> RunResult:
    """Compile `source` plus a Driver class and run Driver.main.

    `source` holds the patched class (for example Example). `driver` is the
    body of a `public class Driver { public static void main ... }` that
    exercises it. Returns the compile failure if it does not build.
    """
    if shutil.which("javac") is None or shutil.which("java") is None:
        return RunResult(False, False, "", "java toolchain not available", None)
    workdir = tempfile.mkdtemp(prefix="vulnfix_java_")
    try:
        cls = _java_class_name(source, "Example")
        with open(os.path.join(workdir, cls + ".java"), "w") as fh:
            fh.write(source)
        with open(os.path.join(workdir, "Driver.java"), "w") as fh:
            fh.write(driver)
        compiled = _run(["javac", cls + ".java", "Driver.java"], workdir, timeout, _clean_env())
        if not compiled.ok:
            return compiled
        return _run(["java", "Driver"], workdir, timeout, _clean_env())
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
