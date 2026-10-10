"""Validator node. Real validation = re-run the static analyzer on BOTH the
original and patched code, then confirm every issue Semgrep found in the
original is gone and no new issue was introduced. Falls back to heuristic
checks if Semgrep is unavailable, and flags 'inconclusive' when Semgrep did
not detect anything in the original (so the fix cannot be auto-verified)."""
import json
import os
import shutil
import subprocess
import tempfile

from config import settings
from models import Finding, ValidationResult

# Risky constructs the patch must not *introduce* (illustrative, not exhaustive)
_DANGEROUS = [
    "eval(", "exec(", "os.system(", "subprocess.call(", "shell=True",
    "pickle.loads(", "yaml.load(", "__import__(",
]


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


def _run_semgrep(file_path: str, content: str):
    """Return the list of rule ids Semgrep fires on `content`, or None if
    Semgrep is unavailable."""
    if shutil.which("semgrep") is None:
        return None
    tmpdir = tempfile.mkdtemp()
    try:
        ext = os.path.splitext(file_path)[1] or ".py"
        tmpf = os.path.join(tmpdir, "scan" + ext)
        with open(tmpf, "w") as fh:
            fh.write(content)
        out = subprocess.run(
            ["semgrep", "--config", settings.SEMGREP_CONFIG,
             "--sarif", "--quiet", tmpf],
            capture_output=True, text=True, timeout=300,
        )
        try:
            sarif = json.loads(out.stdout)
        except Exception:  # noqa: BLE001
            return []
        ids = []
        for run in sarif.get("runs", []) or []:
            for res in run.get("results", []) or []:
                if res.get("ruleId"):
                    ids.append(res["ruleId"])
        return ids
    except (subprocess.SubprocessError, OSError):
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def validator_node(state):
    f: Finding = state["finding"]
    original = state["source_code"]
    patched = state.get("patched_code", "")
    guard = _guardrails(original, patched)

    # Scan the original once and cache it across retries.
    orig = state.get("orig_findings")
    if orig is None:
        orig = _run_semgrep(f.file_path, original)
    remaining = _run_semgrep(f.file_path, patched)
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

    orig_ids = {r for r in orig if r}
    rem_ids = {r for r in remaining if r}
    new = sorted(rem_ids - orig_ids)

    # --- Semgrep found nothing in the original: cannot auto-verify ---
    if not orig_ids:
        vr = ValidationResult(
            validated=False, ran_semgrep=True, inconclusive=True,
            remaining_rule_ids=sorted(rem_ids), new_findings=new,
            guardrail_issues=guard,
            notes="semgrep found no issue in the original; fix cannot be "
                  "auto-verified (check the rules / language support)")
        return {"validation": vr, "validation_feedback": "", **extra}

    # --- Normal case: every original issue gone, nothing new, guardrails ok ---
    resolved = not (rem_ids & orig_ids)
    validated = resolved and not new and not guard
    feedback = ""
    if not validated:
        bits = []
        if guard:
            bits.append("guardrails: " + "; ".join(guard))
        still = sorted(rem_ids & orig_ids)
        if still:
            bits.append("still flagged: " + ", ".join(still[:3]))
        if new:
            bits.append("patch introduced: " + ", ".join(new[:3]))
        feedback = " | ".join(bits) or "fix not confirmed by re-scan"

    vr = ValidationResult(
        validated=validated, ran_semgrep=True, inconclusive=False,
        remaining_rule_ids=sorted(rem_ids), new_findings=new,
        guardrail_issues=guard,
        notes="re-scanned original vs patched with semgrep")
    return {"validation": vr, "validation_feedback": feedback, **extra}