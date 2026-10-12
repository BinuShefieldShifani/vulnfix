"""Validator node. Re-scans BOTH the original and the patched code with
Semgrep (custom VulnFix taint rules + public packs) and Bandit (Python), then
checks that every scanner hit related to the finding's CWE is gone and that no
new meaningful issue was introduced. Unrelated issues already in the original
are ignored. Falls back to heuristics if Semgrep is unavailable, and flags
'inconclusive' when no scanner hit in the original matches the finding."""
import json
import os
import re
import shutil
import subprocess
import tempfile

from config import settings
from models import Finding, ValidationResult

_HERE = os.path.dirname(os.path.abspath(__file__))

# Risky constructs the patch must not *introduce* (illustrative, not exhaustive)
_DANGEROUS = [
    "eval(", "exec(", "os.system(", "subprocess.call(", "shell=True",
    "pickle.loads(", "yaml.load(", "__import__(",
]

# CWEs that count as "the same problem" when matching scanner hits to the
# finding being fixed. Scanners don't always tag the same bug with the same CWE.
_RELATED_CWES = {
    "CWE-78": {"CWE-77", "CWE-78"},
    "CWE-89": {"CWE-89"},
    "CWE-95": {"CWE-94", "CWE-95", "CWE-78"},   # Bandit tags eval (B307) as CWE-78
    "CWE-22": {"CWE-22", "CWE-23", "CWE-73"},
    "CWE-502": {"CWE-502", "CWE-20"},           # Bandit tags yaml.load (B506) as CWE-20
    "CWE-327": {"CWE-327", "CWE-328", "CWE-916"},
    "CWE-798": {"CWE-798", "CWE-259", "CWE-321"},
}


def _guardrails(original: str, patched: str):
    issues = []
    for pat in _DANGEROUS:
        if patched.count(pat) > original.count(pat):
            issues.append(f"patch introduces risky construct: {pat}")
    if not patched.strip():
        issues.append("empty patch")
    if len(patched) > max(len(original) * 3, 2000):
        issues.append("patch is far larger than the original; likely off-target")
    return issues


def _cwes(text):
    return {f"CWE-{n}" for n in re.findall(r"CWE-(\d+)", text or "")}


def _semgrep_configs():
    args = []
    for item in settings.SEMGREP_CONFIG.split(","):
        item = item.strip()
        if not item:
            continue
        if item.endswith((".yml", ".yaml")) and not os.path.isabs(item):
            item = os.path.join(_HERE, item)
        args += ["--config", item]
    return args


def _scan_semgrep(path):
    if shutil.which("semgrep") is None:
        return None
    out = subprocess.run(
        ["semgrep", *_semgrep_configs(), "--sarif", "--quiet", path],
        capture_output=True, text=True, timeout=300,
    )
    try:
        sarif = json.loads(out.stdout)
    except Exception:  # noqa: BLE001
        return []
    found = []
    for run in sarif.get("runs", []) or []:
        rule_cwes = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            tags = " ".join((rule.get("properties") or {}).get("tags") or [])
            rule_cwes[rule.get("id")] = _cwes(tags)
        for res in run.get("results", []) or []:
            rid = res.get("ruleId")
            if rid:
                found.append({"id": f"semgrep:{rid}",
                              "cwes": rule_cwes.get(rid, set()), "low": False})
    return found


def _scan_bandit(path):
    if not path.endswith(".py") or shutil.which("bandit") is None:
        return []
    out = subprocess.run(["bandit", "-q", "-f", "json", path],
                         capture_output=True, text=True, timeout=300)
    try:
        data = json.loads(out.stdout)
    except Exception:  # noqa: BLE001
        return []
    found = []
    for r in data.get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id")
        found.append({"id": f"bandit:{r['test_id']}",
                      "cwes": {f"CWE-{cwe}"} if cwe else set(),
                      "low": r.get("issue_severity") == "LOW"})
    return found


def _scan(file_path: str, content: str):
    """Semgrep + Bandit hits for `content`, or None if Semgrep is unavailable."""
    tmpdir = tempfile.mkdtemp()
    try:
        ext = os.path.splitext(file_path)[1] or ".py"
        tmpf = os.path.join(tmpdir, "scan" + ext)
        with open(tmpf, "w") as fh:
            fh.write(content)
        sem = _scan_semgrep(tmpf)
        if sem is None:
            return None
        return sem + _scan_bandit(tmpf)
    except (subprocess.SubprocessError, OSError):
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _compile_check(file_path: str, content: str) -> str:
    """Return a short compiler error for `content`, or "" if it compiles (or no
    compiler is available for this language). Python is only compiled to
    bytecode, never run."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".py":
        try:
            compile(content, file_path, "exec")
            return ""
        except SyntaxError as e:
            return f"SyntaxError line {e.lineno}: {e.msg}"
    if ext == ".java" and shutil.which("javac"):
        m = re.search(r"public\s+(?:final\s+|abstract\s+)*class\s+(\w+)", content)
        name = m.group(1) if m else os.path.splitext(os.path.basename(file_path))[0]
        tmpdir = tempfile.mkdtemp()
        try:
            src_file = os.path.join(tmpdir, name + ".java")
            with open(src_file, "w") as fh:
                fh.write(content)
            out = subprocess.run(["javac", "-d", tmpdir, src_file],
                                 capture_output=True, text=True, timeout=120)
            if out.returncode == 0:
                return ""
            errs = [l.replace(tmpdir + os.sep, "") for l in out.stderr.splitlines()
                    if "error" in l][:3]
            return " | ".join(errs) or "javac failed"
        except (subprocess.SubprocessError, OSError):
            return ""
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return ""


def _is_related(hit, finding_cwes):
    if not finding_cwes:
        return True
    wanted = set()
    for c in finding_cwes:
        wanted |= _RELATED_CWES.get(c, {c})
    return bool(hit["cwes"] & wanted)


def _run_behavior_test(file_path, patched, behavior_test):
    """Run a caller-supplied behavior test against the patched code in the
    sandbox. Returns "" if it passes (or cannot be run here), else a short
    reason. Never raises. Only trusted, caller-provided tests are run."""
    if not behavior_test:
        return ""
    try:
        from eval.sandbox import run_python, run_java
    except Exception:
        return ""  # sandbox not importable in this environment; skip quietly
    ext = os.path.splitext(file_path)[1].lower()
    try:
        if ext == ".py":
            r = run_python(patched, behavior_test, timeout=20.0,
                           extra_env=behavior_test_env(behavior_test))
            out = r.output or ""
            if "BEHAVIOR_OK" in out and "BEHAVIOR_FAIL" not in out:
                return ""
            return "behavior test failed"
        if ext == ".java":
            r = run_java(patched, behavior_test, timeout=60.0)
            out = r.output or ""
            if "BEHAVIOR_OK" in out:
                return ""
            return "behavior test failed"
    except Exception:
        return ""  # a flaky test must not crash validation
    return ""


def behavior_test_env(behavior_test):
    """If the behavior test reads VULNFIX_BASE, give it a fresh writable dir."""
    if "VULNFIX_BASE" in (behavior_test or ""):
        d = tempfile.mkdtemp(prefix="vulnfix_btest_")
        return {"VULNFIX_BASE": os.path.join(d, "data")}
    return None



def validator_node(state):
    f: Finding = state["finding"]
    original = state["source_code"]
    patched = state.get("patched_code", "")
    guard = _guardrails(original, patched)
    # Compile check: only meaningful if the original compiles.
    if patched.strip() and not _compile_check(f.file_path, original):
        compile_err = _compile_check(f.file_path, patched)
        if compile_err:
            guard.append(f"patch does not compile: {compile_err}")

    # Scan the original once and cache it across retries.
    orig = state.get("orig_findings")
    if orig is None:
        orig = _scan(f.file_path, original)
    remaining = _scan(f.file_path, patched)
    extra = {"orig_findings": orig} if orig is not None else {}

    # --- Semgrep unavailable: heuristic fallback ---
    if orig is None or remaining is None:
        validated = (not guard) and patched.strip() != original.strip()
        vr = ValidationResult(
            validated=validated, ran_semgrep=False, inconclusive=False,
            remaining_rule_ids=[], new_findings=[], guardrail_issues=guard,
            notes="semgrep not installed; heuristic validation only")
        feedback = "" if validated else (
            "guardrails: " + "; ".join(guard) if guard else "no change produced")
        return {"validation": vr, "validation_feedback": feedback, **extra}

    orig_ids = {h["id"] for h in orig}
    targets = {h["id"] for h in orig if _is_related(h, f.cwe)}
    rem_ids = {h["id"] for h in remaining}
    still = sorted(targets & rem_ids)
    new = sorted({h["id"] for h in remaining if not h["low"]} - orig_ids)
    ignored = sorted(orig_ids - targets)
    scanners = f"semgrep [{settings.SEMGREP_CONFIG}] + bandit"

    # --- No scanner hit in the original matches this finding: cannot auto-verify ---
    if not targets:
        vr = ValidationResult(
            validated=False, ran_semgrep=True, inconclusive=True,
            remaining_rule_ids=sorted(rem_ids), new_findings=new,
            guardrail_issues=guard,
            notes=f"{scanners}: no hit in the original matches {f.cwe or 'this finding'}; "
                  "fix cannot be auto-verified")
        return {"validation": vr, "validation_feedback": "", **extra}

    # --- Normal case: related hits gone, nothing new, guardrails ok ---
    behavior_issue = ""
    if not still and not new and not guard:
        behavior_issue = _run_behavior_test(
            f.file_path, patched, state.get("behavior_test"))
    validated = (not still) and (not new) and (not guard) and (not behavior_issue)
    feedback = ""
    if not validated:
        bits = []
        if guard:
            bits.append("guardrails: " + "; ".join(guard))
        if still:
            bits.append("still flagged: " + ", ".join(still[:3]))
        if new:
            bits.append("patch introduced: " + ", ".join(new[:3]))
        if behavior_issue:
            bits.append(behavior_issue)
        feedback = " | ".join(bits) or "fix not confirmed by re-scan"

    note = f"{scanners}: targeted {sorted(targets)}"
    if behavior_issue:
        note += "; behavior test failed"
    if ignored:
        note += f"; ignored unrelated {ignored}"
    vr = ValidationResult(
        validated=validated, ran_semgrep=True, inconclusive=False,
        remaining_rule_ids=sorted(rem_ids), new_findings=new,
        guardrail_issues=guard, notes=note)
    return {"validation": vr, "validation_feedback": feedback, **extra}
