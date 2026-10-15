"""Tests for the human-approval workflow and audit log. The key guarantees:
a patch cannot be applied without human approval, every decision is logged, and
the audit trail is tamper-evident. No model, no GPU."""
import json
import os
import tempfile
import pytest

from eval.approval import ApprovalQueue, Status


def _q():
    d = tempfile.mkdtemp()
    return ApprovalQueue(store_dir=d)


def _submit(q):
    return q.submit(case_id="py-sqli", language="python", cwe="CWE-89",
                    original_code="bad", patch_diff="--- diff", patched_code="good",
                    engine="llm",
                    validation={"exploit": "safe", "behavior": "ok", "compiles": True})


def test_submitted_patch_is_pending():
    q = _q()
    pid = _submit(q)
    assert q.get(pid)["status"] == Status.PENDING.value
    assert len(q.pending()) == 1


def test_cannot_apply_without_approval():
    q = _q()
    pid = _submit(q)
    with pytest.raises(ValueError):
        q.apply(pid, actor="deployer")   # not approved -> must fail


def test_approve_then_apply():
    q = _q()
    pid = _submit(q)
    q.approve(pid, actor="alice", reason="looks correct")
    assert q.get(pid)["status"] == Status.APPROVED.value
    code = q.apply(pid, actor="deployer")
    assert code == "good"
    assert q.get(pid)["status"] == Status.APPLIED.value


def test_rejected_patch_cannot_be_applied():
    q = _q()
    pid = _submit(q)
    q.reject(pid, actor="bob", reason="changes behavior")
    with pytest.raises(ValueError):
        q.apply(pid, actor="deployer")


def test_audit_trail_records_every_decision():
    q = _q()
    pid = _submit(q)
    q.approve(pid, actor="alice", reason="ok")
    q.apply(pid, actor="deployer")
    events = [e["event"] for e in q.audit_trail()]
    assert events == ["submitted", "approved", "applied"]
    # the approver and reason are captured
    approved = [e for e in q.audit_trail() if e["event"] == "approved"][0]
    assert approved["actor"] == "alice"
    assert approved["detail"]["reason"] == "ok"


def test_audit_is_tamper_evident():
    q = _q()
    pid = _submit(q)
    q.approve(pid, actor="alice")
    assert q.verify_audit() is True
    # tamper: flip an actor in the raw file
    lines = open(q.audit_path).readlines()
    rec = json.loads(lines[1]); rec["actor"] = "mallory"
    lines[1] = json.dumps(rec) + "\n"
    open(q.audit_path, "w").writelines(lines)
    assert q.verify_audit() is False   # the hash chain catches it


def test_pending_excludes_decided():
    q = _q()
    p1 = _submit(q); p2 = _submit(q)
    q.approve(p1, actor="alice")
    pending_ids = [p["id"] for p in q.pending()]
    assert p2 in pending_ids and p1 not in pending_ids
