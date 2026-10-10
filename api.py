"""Dockerizable REST API for CI/CD integration.

Run:  uvicorn api:app --host 0.0.0.0 --port 8080

POST /remediate        single finding + source -> RemediationResult
POST /remediate-batch  full SARIF + {path: source} map -> results
"""
from typing import Dict, List

from fastapi import FastAPI
from pydantic import BaseModel

from graph import remediate_finding
from models import Finding, RemediationResult
from sarif import parse_sarif

app = FastAPI(title="VulnFix Remediation API", version="0.1.0")


class RemediateRequest(BaseModel):
    rule_id: str
    file_path: str
    source_code: str
    message: str = ""
    start_line: int = 1
    cwe: List[str] = []


class BatchRequest(BaseModel):
    sarif: dict
    sources: Dict[str, str]  # file_path -> source code


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/remediate", response_model=RemediationResult)
def remediate(req: RemediateRequest):
    finding = Finding(
        rule_id=req.rule_id, message=req.message, file_path=req.file_path,
        start_line=req.start_line, cwe=req.cwe,
    )
    return remediate_finding(finding, req.source_code)


@app.post("/remediate-batch")
def remediate_batch(req: BatchRequest):
    results = []
    for f in parse_sarif(req.sarif):
        src = req.sources.get(f.file_path)
        if src is None:
            continue
        results.append(remediate_finding(f, src))
    return {"count": len(results), "results": results}
