"""Streamlit UI for the agentic vulnerability remediation pipeline.

Run:  streamlit run app.py

Modes: built-in Test suite, Manual finding, or Upload SARIF. Captures
per-run metrics and an accumulating results table you can export/screenshot.
"""
import csv
import io
import json
import os
import time

import requests
import streamlit as st

from config import settings
from graph import build_graph
from models import Finding
from sarif import parse_sarif
from testcases import TEST_CASES, CASES_BY_NAME

st.set_page_config(page_title="VulnFix — Agentic Remediation", layout="wide")

NODE_LABELS = {
    "retriever": "Retriever", "static_analyst": "Static Analyst",
    "root_cause": "Root-Cause Reasoner", "patch_generator": "Patch Generator",
    "validator": "Validator", "finalize": "Finalize",
}

if "results" not in st.session_state:
    st.session_state["results"] = []


# --- helpers ----------------------------------------------------------------
def check_services(ollama_url, chroma_url):
    out = {}
    try:
        r = requests.get(f"{ollama_url}/api/tags", timeout=10)
        r.raise_for_status()
        out["ollama"] = [m["name"] for m in r.json().get("models", [])]
    except Exception as e:  # noqa: BLE001
        out["ollama_error"] = str(e)
    for ver in ("v2", "v1"):
        try:
            if requests.get(f"{chroma_url}/api/{ver}/heartbeat", timeout=10).ok:
                out["chroma"] = f"reachable ({ver})"
                break
        except Exception as e:  # noqa: BLE001
            out["chroma_error"] = str(e)
    return out


def diff_stats(diff: str):
    added = sum(1 for ln in diff.splitlines()
                if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff.splitlines()
                  if ln.startswith("-") and not ln.startswith("---"))
    return added, removed


def run_remediation(finding, source, log_box):
    graph = build_graph()
    acc, lines = {}, []
    initial = {"finding": finding, "source_code": source, "attempts": 0}
    for update in graph.stream(initial, config={"recursion_limit": 25},
                               stream_mode="updates"):
        for node, partial in update.items():
            if partial:
                acc.update(partial)
            lines.append(f"✓ {NODE_LABELS.get(node, node)}")
            log_box.markdown("  \n".join(lines))
    return acc.get("result"), acc


def record_result(case_name, language, cwe, result, elapsed):
    v = result.validation
    added, removed = diff_stats(result.patch_diff or "")
    st.session_state["results"].append({
        "Case": case_name, "Lang": language, "CWE": cwe,
        "Status": result.status,
        "Attempts": result.attempts,
        "Time (s)": round(elapsed, 1),
        "Semgrep": "yes" if (v and v.ran_semgrep) else "no",
        "New issues": len(v.new_findings) if v else 0,
        "Lines +/-": f"+{added}/-{removed}",
    })


def show_result(result, state, elapsed):
    if result is None:
        st.error("Pipeline returned no result.")
        return
    v = result.validation

    if result.status == "validated":
        st.success(f"✅ Validated — fix confirmed by re-scan "
                   f"({result.attempts} attempt(s))")
    elif result.status == "inconclusive":
        st.info("ℹ️ Inconclusive — Semgrep didn't detect the original issue, "
                "so the fix couldn't be auto-verified (rules/language support).")
    else:
        st.warning(f"⚠️ Unvalidated — review manually "
                   f"({result.attempts} attempt(s))")

    added, removed = diff_stats(result.patch_diff or "")
    m = st.columns(5)
    m[0].metric("Status", result.status)
    m[1].metric("Attempts", result.attempts)
    m[2].metric("Time (s)", f"{elapsed:.1f}")
    m[3].metric("Lines changed", f"+{added}/-{removed}")
    m[4].metric("New issues", len(v.new_findings) if v else 0)

    st.subheader("Root cause")
    st.markdown(result.root_cause or "_(none)_")

    st.subheader("Proposed patch")
    st.code(result.patch_diff or "(no diff)", language="diff")

    c1, c2 = st.columns(2)
    with c1:
        with st.expander("Patched file"):
            st.code(result.patched_code or "", language="python")
    with c2:
        with st.expander("Verification test"):
            st.code(result.verification_test or "(none generated)",
                    language="python")

    st.subheader("Validation")
    if v:
        st.json({
            "validated": v.validated, "inconclusive": v.inconclusive,
            "ran_semgrep": v.ran_semgrep,
            "remaining_rule_ids": v.remaining_rule_ids,
            "new_findings": v.new_findings,
            "guardrail_issues": v.guardrail_issues, "notes": v.notes,
        })
    with st.expander("Retrieved context (grounding)"):
        st.text(state.get("retrieved_context", "(none)"))
    with st.expander("Full result JSON"):
        st.code(json.dumps(json.loads(result.model_dump_json()), indent=2),
                language="json")


# --- sidebar ----------------------------------------------------------------
st.sidebar.title("⚙️ Settings")
ollama_url = st.sidebar.text_input("Ollama URL", settings.OLLAMA_BASE_URL)
chroma_url = st.sidebar.text_input("Chroma URL", settings.CHROMA_HOST)
code_model = st.sidebar.text_input("Code model", settings.CODE_MODEL)
reasoning_model = st.sidebar.text_input("Reasoning model", settings.REASONING_MODEL)
embed_model = st.sidebar.text_input("Embedding model", settings.EMBED_MODEL)
max_attempts = st.sidebar.number_input("Max patch attempts", 1, 5,
                                       settings.MAX_PATCH_ATTEMPTS)

if st.sidebar.button("Check services"):
    info = check_services(ollama_url, chroma_url)
    if "ollama" in info:
        st.sidebar.success(f"Ollama OK — {', '.join(info['ollama']) or 'no models'}")
    else:
        st.sidebar.error(f"Ollama: {info.get('ollama_error')}")
    if "chroma" in info:
        st.sidebar.success(f"Chroma {info['chroma']}")
    else:
        st.sidebar.warning(f"Chroma: {info.get('chroma_error', 'unreachable')}")

settings.OLLAMA_BASE_URL = ollama_url
settings.CHROMA_HOST = chroma_url
settings.CODE_MODEL = code_model
settings.REASONING_MODEL = reasoning_model
settings.EMBED_MODEL = embed_model
settings.MAX_PATCH_ATTEMPTS = int(max_attempts)


# --- main -------------------------------------------------------------------
st.title("🛡️ VulnFix — Agentic Vulnerability Remediation")
st.caption("Retriever → Static Analyst → Root-Cause → Patch Generator → "
           "Validator (Semgrep re-scan). Fully local via Ollama + Chroma.")

mode = st.radio("Input mode", ["Test suite", "Manual finding", "Upload SARIF"],
                horizontal=True)

to_run = []  # list of (case_name, language, cwe, Finding, source_code)

if mode == "Test suite":
    name = st.selectbox("Test case", [c["name"] for c in TEST_CASES])
    case = CASES_BY_NAME[name]
    st.code(case["code"],
            language="java" if case["language"] == "java" else "python")
    cwe = case["cwe"]
    if st.button("Run all cases"):
        for c in TEST_CASES:
            to_run.append((c["name"], c["language"], c["cwe"], Finding(
                rule_id=c["rule_id"], message=c["name"], file_path=c["file"],
                start_line=1,
                cwe=[c["cwe"]] if c["cwe"].startswith("CWE") else [],
            ), c["code"]))
    elif st.button("🚀 Run this case", type="primary"):
        to_run.append((case["name"], case["language"], cwe, Finding(
            rule_id=case["rule_id"], message=case["name"],
            file_path=case["file"], start_line=1,
            cwe=[cwe] if cwe.startswith("CWE") else [],
        ), case["code"]))

elif mode == "Manual finding":
    c1, c2 = st.columns([2, 1])
    with c2:
        rule_id = st.text_input("Rule ID", "")
        cwe_in = st.text_input("CWE (comma-separated)", "")
        file_path = st.text_input("File name", "input.py")
        message = st.text_input("Message", "")
    with c1:
        source = st.text_area("Source code", "", height=320)
    if st.button("🚀 Run remediation", type="primary",
                 disabled=not (rule_id and source.strip())):
        to_run.append(("manual", "python", cwe_in, Finding(
            rule_id=rule_id, message=message, file_path=file_path,
            cwe=[c.strip() for c in cwe_in.split(",") if c.strip()],
        ), source))

else:  # Upload SARIF
    sf = st.file_uploader("SARIF report", type=["sarif", "json"])
    srcs = st.file_uploader("Source file(s)", accept_multiple_files=True)
    if sf and srcs:
        sources = {os.path.basename(s.name): s.read().decode("utf-8", "replace")
                   for s in srcs}
        findings = parse_sarif(json.loads(sf.read().decode()))
        st.info(f"Parsed {len(findings)} finding(s).")
        if st.button("🚀 Run remediation", type="primary"):
            for fnd in findings:
                src = sources.get(os.path.basename(fnd.file_path))
                if src is not None:
                    to_run.append((fnd.file_path, "python",
                                   ",".join(fnd.cwe), fnd, src))

# --- execute ----------------------------------------------------------------
for case_name, lang, cwe, finding, source in to_run:
    st.divider()
    st.markdown(f"### {case_name}  ·  `{finding.rule_id}`")
    log_box = st.empty()
    with st.spinner("Agents working..."):
        try:
            t0 = time.perf_counter()
            result, state = run_remediation(finding, source, log_box)
            elapsed = time.perf_counter() - t0
            record_result(case_name, lang, cwe, result, elapsed)
            show_result(result, state, elapsed)
        except Exception as e:  # noqa: BLE001
            st.error(f"Pipeline error: {e}\n\nIs Ollama running with the "
                     f"selected models pulled?")

# --- results table ----------------------------------------------------------
rows = st.session_state["results"]
if rows:
    st.divider()
    st.subheader("📊 Session results")
    n = len(rows)
    val = sum(1 for r in rows if r["Status"] == "validated")
    inc = sum(1 for r in rows if r["Status"] == "inconclusive")
    avg_t = sum(r["Time (s)"] for r in rows) / n
    s = st.columns(4)
    s[0].metric("Runs", n)
    s[1].metric("Validated", f"{val}/{n}  ({100 * val / n:.0f}%)")
    s[2].metric("Inconclusive", inc)
    s[3].metric("Avg time (s)", f"{avg_t:.1f}")
    st.dataframe(rows, use_container_width=True)

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
    st.download_button("⬇️ Download results CSV", buf.getvalue(),
                       "vulnfix_results.csv", "text/csv")
    if st.button("Clear results"):
        st.session_state["results"] = []
        st.rerun()