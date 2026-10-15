"""Human-approval workflow and append-only audit log.

VulnFix never auto-applies a patch. Every validated fix becomes a PENDING
approval record carrying the full evidence a reviewer needs: the original code,
the diff, the validation result (exploit/behavior/compile), and which engine
produced it. A human approves or rejects it; every decision is appended to an
immutable audit log with who, when, and why.

Lifecycle:  generated -> validated -> PENDING -> approved/rejected -> applied/discarded

The audit log is append-only JSONL: each line is one event, never edited or
deleted. This is the trail enterprises need for compliance.

Pure logic, no GPU, no model. The Streamlit UI calls these functions.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum


class Status(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    DISCARDED = "discarded"


@dataclass
class PatchRecord:
    """A patch awaiting human decision, with the evidence to decide on."""
    id: str
    created_at: float
    case_id: str
    language: str
    cwe: str
    original_code: str
    patch_diff: str
    patched_code: str
    engine: str                      # "codemod:<name>" or "llm"
    validation: dict                 # exploit/behavior/compile/validated
    status: str = Status.PENDING.value

    def as_dict(self):
        return asdict(self)


def _now():
    return time.time()


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class ApprovalQueue:
    """Manages pending patches and the append-only audit log."""

    def __init__(self, store_dir="results/approval"):
        self.dir = store_dir
        os.makedirs(self.dir, exist_ok=True)
        self.queue_path = os.path.join(self.dir, "queue.jsonl")
        self.audit_path = os.path.join(self.dir, "audit.jsonl")

    # --- audit log: append-only, never edited ---
    def _audit(self, event, patch_id, actor, detail=None):
        rec = {"event": event, "patch_id": patch_id, "actor": actor,
               "at": _iso(_now()), "ts": _now()}
        if detail:
            rec["detail"] = detail
        # chain each entry to the previous one's hash for tamper-evidence
        prev = self._last_audit_hash()
        rec["prev_hash"] = prev
        rec["hash"] = hashlib.sha256(
            (prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest()[:16]
        with open(self.audit_path, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        return rec

    def _last_audit_hash(self):
        if not os.path.exists(self.audit_path):
            return "genesis"
        last = "genesis"
        for line in open(self.audit_path):
            try:
                last = json.loads(line).get("hash", last)
            except Exception:
                pass
        return last

    # --- submit a validated patch for review ---
    def submit(self, case_id, language, cwe, original_code, patch_diff,
               patched_code, engine, validation, actor="pipeline"):
        rec = PatchRecord(
            id=uuid.uuid4().hex[:12], created_at=_now(),
            case_id=case_id, language=language, cwe=cwe,
            original_code=original_code, patch_diff=patch_diff,
            patched_code=patched_code, engine=engine, validation=validation)
        with open(self.queue_path, "a") as fh:
            fh.write(json.dumps(rec.as_dict()) + "\n")
        self._audit("submitted", rec.id, actor,
                    {"case_id": case_id, "engine": engine})
        return rec.id

    # --- read current queue state (latest status per patch) ---
    def _load_queue(self):
        patches = {}
        if os.path.exists(self.queue_path):
            for line in open(self.queue_path):
                try:
                    r = json.loads(line)
                    patches[r["id"]] = r          # later lines override (status updates)
                except Exception:
                    pass
        return patches

    def pending(self):
        return [p for p in self._load_queue().values()
                if p["status"] == Status.PENDING.value]

    def get(self, patch_id):
        return self._load_queue().get(patch_id)

    def _update_status(self, patch_id, new_status):
        p = self.get(patch_id)
        if not p:
            return None
        p = dict(p)
        p["status"] = new_status
        with open(self.queue_path, "a") as fh:
            fh.write(json.dumps(p) + "\n")
        return p

    # --- human decisions (the only way a patch advances) ---
    def approve(self, patch_id, actor, reason=""):
        p = self.get(patch_id)
        if not p or p["status"] != Status.PENDING.value:
            raise ValueError("patch not pending")
        self._update_status(patch_id, Status.APPROVED.value)
        self._audit("approved", patch_id, actor, {"reason": reason})
        return True

    def reject(self, patch_id, actor, reason=""):
        p = self.get(patch_id)
        if not p or p["status"] != Status.PENDING.value:
            raise ValueError("patch not pending")
        self._update_status(patch_id, Status.REJECTED.value)
        self._audit("rejected", patch_id, actor, {"reason": reason})
        return True

    def apply(self, patch_id, actor):
        """A patch can ONLY be applied if a human approved it first."""
        p = self.get(patch_id)
        if not p:
            raise ValueError("no such patch")
        if p["status"] != Status.APPROVED.value:
            raise ValueError(f"cannot apply: status is {p['status']}, not approved")
        self._update_status(patch_id, Status.APPLIED.value)
        self._audit("applied", patch_id, actor)
        return p["patched_code"]

    # --- audit verification ---
    def verify_audit(self):
        """Recompute the hash chain; returns True if untampered."""
        prev = "genesis"
        for line in open(self.audit_path) if os.path.exists(self.audit_path) else []:
            rec = json.loads(line)
            stored = rec.get("hash")
            check = dict(rec)
            check.pop("hash", None)
            expect = hashlib.sha256(
                (prev + json.dumps(check, sort_keys=True)).encode()).hexdigest()[:16]
            if stored != expect or rec.get("prev_hash") != prev:
                return False
            prev = stored
        return True

    def audit_trail(self):
        if not os.path.exists(self.audit_path):
            return []
        return [json.loads(l) for l in open(self.audit_path)]
