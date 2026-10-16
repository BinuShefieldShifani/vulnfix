"""Tests for the SARIF-in / report-out emitters. Pure format logic, no model.
Verifies the round-trip and that only verified+approved fixes become applyable."""
import json
from eval.report import FindingResult, to_sarif, to_markdown, to_patch


def _results():
    return [
        FindingResult(rule_id="py.sqli", file_path="app.py", start_line=7,
                      cwe=["CWE-89"], status="validated",
                      patch_diff="--- a/app.py\n+++ b/app.py\n@@ fixed sqli @@\n",
                      validation={"validated": True}, approved=True),
        FindingResult(rule_id="py.pickle", file_path="app.py", start_line=20,
                      cwe=["CWE-502"], status="unvalidated",
                      validation={"notes": "dill still unsafe"}),
        FindingResult(rule_id="py.ssrf", file_path="svc.py", start_line=3,
                      cwe=["CWE-918"], status="inconclusive",
                      validation={"notes": "no scanner baseline"}),
    ]


def test_markdown_summarizes_buckets():
    md = to_markdown(_results())
    assert "1 fixed and verified" in md
    assert "2 need human review" in md
    assert "✅ fixed" in md and "⚠️ review" in md
    # the verified fix's diff is included
    assert "fixed sqli" in md
    # the unverified ones are NOT shown as fixes, only flagged for review
    assert "dill still unsafe" in md


def test_patch_only_includes_approved_validated():
    patch, desc = to_patch(_results())
    # only the approved validated sqli fix is in the patch
    assert "fixed sqli" in patch
    # pickle (unvalidated) and ssrf (inconclusive) must NOT be in the patch
    assert "pickle" not in patch and "ssrf" not in patch
    assert "1 verified fix" in desc


def test_patch_excludes_validated_but_unapproved():
    # a validated fix that a human has NOT approved must not auto-apply
    rs = [FindingResult(rule_id="x", file_path="a.py", start_line=1, cwe=[],
                        status="validated", patch_diff="DIFF", approved=False)]
    patch, _ = to_patch(rs)   # approved_only=True by default
    assert patch == ""        # nothing applyable without approval


def test_sarif_out_annotates_results():
    original = {"runs": [{"results": [
        {"ruleId": "py.sqli",
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "app.py"},
             "region": {"startLine": 7}}}]}]}]}
    out = to_sarif(original, _results())
    props = out["runs"][0]["results"][0]["properties"]["vulnfix"]
    assert props["status"] == "validated"
    assert props["applyable"] is True
    assert "fixed sqli" in props["patch_diff"]


def test_sarif_out_leaves_unmatched_untouched():
    original = {"runs": [{"results": [
        {"ruleId": "unknown.rule",
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "other.py"},
             "region": {"startLine": 99}}}]}]}]}
    out = to_sarif(original, _results())
    # no vulnfix annotation on a result we have no finding for
    assert "vulnfix" not in out["runs"][0]["results"][0].get("properties", {})
