"""Tests that the hardened sandbox limits actually bite. The resource limits are
Linux-only; the memory/process tests skip where setrlimit is unavailable, but
the isolation and timeout tests run everywhere."""
import sys
import pytest
from eval.sandbox_hardened import run_python_hardened, _HAVE_RLIMIT

needs_rlimit = pytest.mark.skipif(not _HAVE_RLIMIT, reason="setrlimit unavailable")


def test_normal_code_runs():
    r = run_python_hardened("def f(x):\n    return x*2\n",
                            "from app import f\nprint('R', f(21))")
    assert r.ok and "R 42" in r.stdout


def test_wall_clock_timeout_everywhere():
    r = run_python_hardened("def loop():\n    while True: pass\n",
                            "from app import loop\nloop()", timeout=2.0)
    assert r.timed_out and not r.ok


def test_isolated_workdir_is_cleaned():
    # the child writes a file; after the call the temp dir is gone
    r = run_python_hardened("x=1\n",
                            "open('side.txt','w').write('hi')\nprint('wrote')")
    assert "wrote" in r.stdout
    # nothing leaks to cwd
    import os
    assert not os.path.exists("side.txt")


@needs_rlimit
def test_memory_bomb_is_killed():
    # try to allocate ~2GB; the 512MB cap should kill it
    bomb = "def go():\n    x = bytearray(2_000_000_000)\n    return len(x)\n"
    r = run_python_hardened(bomb, "from app import go\ngo()\nprint('SURVIVED')",
                            limits={"mem_mb": 256})
    assert "SURVIVED" not in r.stdout
    assert r.killed_by_limit or not r.ok


@needs_rlimit
def test_cpu_limit_is_set():
    # a long busy loop should be cut by the CPU-time limit (not just wall clock)
    r = run_python_hardened(
        "def burn():\n    s=0\n    for i in range(10**12): s+=i\n    return s\n",
        "from app import burn\nburn()\nprint('DONE')",
        timeout=30.0, limits={"cpu_sec": 2})
    assert "DONE" not in r.stdout
    assert not r.ok


def test_limits_applied_flag_matches_platform():
    r = run_python_hardened("print('ok')\n", "print('ok')")
    assert r.limits_applied == _HAVE_RLIMIT
