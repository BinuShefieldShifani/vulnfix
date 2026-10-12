"""Pydantic schemas (structured I/O) and the LangGraph state channel."""
from typing import List, Optional, TypedDict

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A single normalized SAST/DAST finding."""
    rule_id: str
    message: str = ""
    file_path: str
    start_line: int = 1
    end_line: Optional[int] = None
    severity: str = "warning"
    cwe: List[str] = Field(default_factory=list)
    snippet: str = ""


class ValidationResult(BaseModel):
    validated: bool
    ran_semgrep: bool
    remaining_rule_ids: List[str] = Field(default_factory=list)
    new_findings: List[str] = Field(default_factory=list)
    inconclusive: bool = False
    guardrail_issues: List[str] = Field(default_factory=list)
    notes: str = ""


class RemediationResult(BaseModel):
    finding: Finding
    root_cause: str = ""
    patch_diff: str = ""
    patched_code: str = ""
    verification_test: str = ""
    validation: Optional[ValidationResult] = None
    attempts: int = 0
    status: str = "unknown"  # validated | unvalidated | error


class GraphState(TypedDict, total=False):
    """Channels passed between LangGraph nodes. Nodes return partial dicts
    that are merged into this state."""
    finding: Finding
    source_code: str
    behavior_test: str
    retrieved_context: str
    analysis: str
    root_cause: str
    fix_strategy: str
    patched_code: str
    patch_diff: str
    verification_test: str
    validation: ValidationResult
    validation_feedback: str
    orig_findings: list
    attempts: int
    result: RemediationResult