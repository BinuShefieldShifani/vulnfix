"""SARIF-in / report-out: VulnFix consumes the standard SARIF that scanners
emit, remediates each finding, and produces three outputs that fit a real CI
pipeline:

  - SARIF-out: the original SARIF with each result annotated with VulnFix's
    outcome (status, patch, validation), so a SARIF dashboard shows what was
    auto-fixed.
  - Markdown report: a PR/ticket-ready summary (what was fixed, what needs
    human review).
  - Applyable patch: the validated/approved diffs concatenated into a unified
    patch you can `git apply`, plus a PR description.

Only VERIFIED fixes (validated, or human-approved) go into the applyable patch.
Inconclusive/unvalidated findings appear in the report as "needs review", never
in the patch, VulnFix never auto-applies an unverified fix.

The format logic here is pure and CI-testable with fake results. The actual
remediation (run_from_sarif) needs the model; the emitters do not.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field


@dataclass
class FindingResult:
    """One finding after remediation."""
    rule_id: str
    file_path: str
    start_line: int
    cwe: list
    status: str                 # validated | unvalidated | inconclusive | error
    patch_diff: str = ""
    validation: dict = field(default_factory=dict)
    approved: bool = False      # set True once a human approves (from the queue)

    @property
    def is_applyable(self):
        # only verified AND human-approved fixes are safe to apply
        return self.status == "validated" and self.approved


def run_from_sarif(sarif_path, src_root="."):
    """Parse SARIF, remediate each finding, return a list of FindingResult.
    Needs the model (imports graph). Kept thin so the emitters stay testable."""
    import os
    from sarif import parse_sarif
    from graph import remediate_finding

    findings = parse_sarif(sarif_path)
    results = []
    for f in findings:
        src_file = os.path.join(src_root, os.path.basename(f.file_path))
        source = open(src_file).read() if os.path.exists(src_file) else f.snippet
        try:
            r = remediate_finding(f, source)
            v = r.validation
            results.append(FindingResult(
                rule_id=f.rule_id, file_path=f.file_path, start_line=f.start_line,
                cwe=list(f.cwe), status=r.status, patch_diff=r.patch_diff or "",
                validation={"validated": bool(v and v.validated),
                            "inconclusive": bool(v and v.inconclusive),
                            "notes": (v.notes if v else "")}))
        except Exception as e:  # noqa: BLE001
            results.append(FindingResult(
                rule_id=f.rule_id, file_path=f.file_path, start_line=f.start_line,
                cwe=list(f.cwe), status=f"error: {type(e).__name__}"))
    return results


# ---------------- emitters (pure, testable) ----------------

def to_sarif(original_sarif: dict, results):
    """Annotate each SARIF result with VulnFix's outcome. Matches results to
    SARIF entries by (ruleId, file, startLine)."""
    out = copy.deepcopy(original_sarif)
    by_key = {(r.rule_id, r.file_path, r.start_line): r for r in results}
    for run in out.get("runs", []) or []:
        for res in run.get("results", []) or []:
            rid = res.get("ruleId", "")
            for loc in res.get("locations", []) or []:
                phys = loc.get("physicalLocation", {}) or {}
                uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                line = (phys.get("region", {}) or {}).get("startLine", 1)
                fr = by_key.get((rid, uri, line))
                if fr:
                    res.setdefault("properties", {})["vulnfix"] = {
                        "status": fr.status,
                        "applyable": fr.is_applyable,
                        "validation": fr.validation,
                        "patch_diff": fr.patch_diff,
                    }
    return out


def to_markdown(results):
    n = len(results)
    fixed = [r for r in results if r.status == "validated"]
    review = [r for r in results if r.status in ("unvalidated", "inconclusive")]
    errs = [r for r in results if r.status.startswith("error")]
    lines = []
    lines.append("# VulnFix remediation report\n")
    lines.append(f"**{len(fixed)} fixed and verified**, "
                 f"{len(review)} need human review, {len(errs)} errored "
                 f"(of {n} findings).\n")
    lines.append("| Finding | File:Line | CWE | Status |")
    lines.append("|---|---|---|---|")
    for r in results:
        badge = {"validated": "✅ fixed", "inconclusive": "⚠️ review",
                 "unvalidated": "⚠️ review"}.get(r.status, "❌ " + r.status)
        lines.append(f"| `{r.rule_id}` | {r.file_path}:{r.start_line} | "
                     f"{', '.join(r.cwe) or '-'} | {badge} |")
    if fixed:
        lines.append("\n## Verified fixes\n")
        for r in fixed:
            lines.append(f"### {r.rule_id} — {r.file_path}:{r.start_line}\n")
            lines.append("```diff\n" + (r.patch_diff or "") + "\n```\n")
    if review:
        lines.append("\n## Needs human review\n")
        for r in review:
            note = r.validation.get("notes", "")
            lines.append(f"- `{r.rule_id}` ({r.file_path}:{r.start_line}): "
                         f"{r.status} — {note}")
    return "\n".join(lines) + "\n"


def to_patch(results, approved_only=True):
    """Concatenate applyable diffs into one unified patch, plus a PR description.
    By default only human-approved validated fixes are included."""
    if approved_only:
        apply = [r for r in results if r.is_applyable]
    else:
        apply = [r for r in results if r.status == "validated"]
    patch = "".join(r.patch_diff for r in apply if r.patch_diff)
    desc = [f"# VulnFix: {len(apply)} verified fix(es)\n"]
    for r in apply:
        desc.append(f"- {r.rule_id} ({', '.join(r.cwe) or 'n/a'}) "
                    f"in {r.file_path}")
    pr_description = "\n".join(desc) + "\n"
    return patch, pr_description
