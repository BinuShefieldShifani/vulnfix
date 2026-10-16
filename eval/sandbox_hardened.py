"""Hardened, opt-in runner for untrusted code.

The default sandbox (eval/sandbox.py) runs code in a subprocess with a timeout,
fast and fine for the eval harness. This hardened runner adds OS-level limits
for contexts where you run genuinely untrusted input: memory, CPU-time,
process-count, and file-size caps, plus an isolated, auto-cleaned working dir
and a stripped environment.

Network is intentionally NOT blocked here (some exploit/behavior oracles bind
localhost). A production deployment would additionally restrict egress and run
inside a container / gVisor / Firecracker sandbox, see HARDENING.md.

Limits use resource.setrlimit, which is POSIX/Linux-only. On platforms without
it (macOS without full support, Windows) the runner degrades gracefully: it
still isolates the working dir, strips the env, and enforces the wall-clock
timeout, but skips the rlimits and says so in the result.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass

try:
    import resource  # POSIX only
    _HAVE_RLIMIT = True
except Exception:
    _HAVE_RLIMIT = False


@dataclass
class HardenedResult:
    ok: bool
    timed_out: bool
    killed_by_limit: bool
    stdout: str
    stderr: str
    returncode: int | None
    limits_applied: bool          # were the OS rlimits actually set?

    @property
    def output(self):
        return (self.stdout or "") + (self.stderr or "")


# default limits: generous enough for real fixes, tight enough to stop abuse
DEFAULT_LIMITS = {
    "mem_mb": 512,       # address-space cap
    "cpu_sec": 20,       # CPU-time cap (separate from wall-clock)
    "nproc": 64,         # max processes/threads (blocks fork bombs)
    "fsize_mb": 50,      # max file size a child may write
}


def _preexec(limits):
    """Runs in the child AFTER fork, BEFORE exec. Sets rlimits."""
    def apply():
        try:
            m = limits["mem_mb"] * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (m, m))
        except Exception:
            pass
        try:
            c = limits["cpu_sec"]
            resource.setrlimit(resource.RLIMIT_CPU, (c, c))
        except Exception:
            pass
        try:
            resource.setrlimit(resource.RLIMIT_NPROC,
                               (limits["nproc"], limits["nproc"]))
        except Exception:
            pass
        try:
            f = limits["fsize_mb"] * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (f, f))
        except Exception:
            pass
        # new session so we can't signal the parent's process group
        try:
            os.setsid()
        except Exception:
            pass
    return apply


def _clean_env():
    keep = {}
    for k in ("PATH", "HOME", "LANG", "LC_ALL"):
        if k in os.environ:
            keep[k] = os.environ[k]
    return keep


def run_python_hardened(source: str, driver: str, timeout: float = 20.0,
                        limits: dict | None = None, extra_env: dict | None = None):
    lim = {**DEFAULT_LIMITS, **(limits or {})}
    workdir = tempfile.mkdtemp(prefix="vulnfix_hard_")
    try:
        with open(os.path.join(workdir, "app.py"), "w") as fh:
            fh.write(source)
        with open(os.path.join(workdir, "driver.py"), "w") as fh:
            fh.write(driver)
        env = _clean_env()
        if extra_env:
            env.update(extra_env)
        kwargs = dict(cwd=workdir, capture_output=True, text=True,
                      timeout=timeout, env=env)
        if _HAVE_RLIMIT:
            kwargs["preexec_fn"] = _preexec(lim)
        try:
            p = subprocess.run(["python", "driver.py"], **kwargs)
            rc = p.returncode
            # rlimit kills show up as negative returncodes (signals) or MemoryError
            killed = (rc is not None and rc < 0) or ("MemoryError" in (p.stderr or ""))
            return HardenedResult(rc == 0, False, killed, p.stdout, p.stderr,
                                  rc, _HAVE_RLIMIT)
        except subprocess.TimeoutExpired as e:
            return HardenedResult(False, True, False, e.stdout or "",
                                  e.stderr or "", None, _HAVE_RLIMIT)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
