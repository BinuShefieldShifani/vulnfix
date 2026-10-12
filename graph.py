"""Assemble the agent pipeline as a LangGraph state machine:

    retriever -> static_analyst -> root_cause -> patch_generator -> validator
                                                       ^                  |
                                                       |  (retry if failed
                                                       +-- and attempts left)
                                                                          |
                                                                  finalize -> END

Guardrails and grounding (retrieved fix patterns) run inside the nodes.
"""
import json
import os

from langgraph.graph import END, START, StateGraph

from agents import (patch_generator_node, retriever_node, root_cause_node,
                    static_analyst_node)
from config import settings
from models import Finding, GraphState, RemediationResult
from validator import validator_node


def _route_after_validation(state) -> str:
    vr = state.get("validation")
    # Stop on success or when the fix can't be auto-verified (inconclusive).
    if vr and (vr.validated or vr.inconclusive):
        return "finalize"
    if state.get("attempts", 0) < settings.MAX_PATCH_ATTEMPTS:
        return "patch_generator"   # feedback loop: try again
    return "finalize"              # give up, return best effort unvalidated


def _finalize_node(state):
    vr = state.get("validation")
    if vr and vr.validated:
        status = "validated"
    elif vr and vr.inconclusive:
        status = "inconclusive"
    else:
        status = "unvalidated"
    return {"result": RemediationResult(
        finding=state["finding"],
        root_cause=state.get("root_cause", ""),
        patch_diff=state.get("patch_diff", ""),
        patched_code=state.get("patched_code", ""),
        verification_test=state.get("verification_test", ""),
        validation=vr,
        attempts=state.get("attempts", 0),
        status=status,
    )}


def build_graph():
    b = StateGraph(GraphState)
    b.add_node("retriever", retriever_node)
    b.add_node("static_analyst", static_analyst_node)
    b.add_node("root_cause", root_cause_node)
    b.add_node("patch_generator", patch_generator_node)
    b.add_node("validator", validator_node)
    b.add_node("finalize", _finalize_node)

    b.add_edge(START, "retriever")
    b.add_edge("retriever", "static_analyst")
    b.add_edge("static_analyst", "root_cause")
    b.add_edge("root_cause", "patch_generator")
    b.add_edge("patch_generator", "validator")
    b.add_conditional_edges("validator", _route_after_validation, {
        "patch_generator": "patch_generator",
        "finalize": "finalize",
    })
    b.add_edge("finalize", END)
    return b.compile()


def remediate_finding(finding: Finding, source_code: str,
                      behavior_test: str = None) -> RemediationResult:
    graph = build_graph()
    final = graph.invoke(
        {"finding": finding, "source_code": source_code, "attempts": 0,
         "behavior_test": behavior_test},
        config={"recursion_limit": 25},
    )
    return final["result"]


if __name__ == "__main__":
    import argparse
    from sarif import parse_sarif

    ap = argparse.ArgumentParser(description="Run the remediation pipeline.")
    ap.add_argument("--sarif", required=True, help="Path to a SARIF report")
    ap.add_argument("--src-root", default=".",
                    help="Root dir the SARIF file paths are relative to")
    args = ap.parse_args()

    findings = parse_sarif(args.sarif)
    print(f"Parsed {len(findings)} finding(s)\n")
    for f in findings:
        path = os.path.join(args.src_root, f.file_path)
        if not os.path.exists(path):
            print(f"  skip {f.file_path}: not found under {args.src_root}")
            continue
        with open(path) as fh:
            src = fh.read()
        result = remediate_finding(f, src)
        print(json.dumps(json.loads(result.model_dump_json()), indent=2))
        print("-" * 60)