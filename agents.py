"""The LLM-backed agent nodes. Each node takes the graph state and returns a
partial dict that LangGraph merges back in. JSON parsing is defensive because
local models are inconsistent about clean JSON output."""
import difflib
import os
import json
import re

from langchain_ollama import ChatOllama

from config import settings
from models import Finding
from retriever import retrieve_context
try:
    from eval.fix_guidance import build_guidance
except Exception:
    build_guidance = lambda lang, cwe: ''
try:
    from eval.funcextract import extract_function, splice_function
except Exception:
    extract_function = lambda *a, **k: None
    splice_function = lambda *a, **k: None
try:
    from eval.codemods import try_codemod
except Exception:
    def try_codemod(cwe, src): return (None, None)


def _llm(model: str, temperature: float = 0.1, json_mode: bool = False) -> ChatOllama:
    kwargs = dict(model=model, base_url=settings.OLLAMA_BASE_URL,
                  temperature=temperature,
                  # Small models at low temperature can loop on the same line
                  # until Ollama aborts. A mild repeat penalty and a cap help.
                  repeat_penalty=1.1, num_predict=2048)
    if json_mode:
        # Force valid JSON output — essential for small local models that
        # otherwise wrap JSON in prose or break the schema.
        kwargs["format"] = "json"
    return ChatOllama(**kwargs)


def _extract_json(text: str) -> dict:
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    else:
        a, b = text.find("{"), text.rfind("}")
        if a != -1 and b != -1:
            text = text[a:b + 1]
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return {}


def _invoke_json(llm: ChatOllama, system: str, user: str, retries: int = 2):
    """Call the model and parse JSON. If the call fails (for example Ollama
    aborting a repeat loop) or returns no usable JSON, retry with a slightly
    higher temperature."""
    last_err, raw = None, ""
    for i in range(retries + 1):
        model = llm if i == 0 else llm.model_copy(
            update={"temperature": (llm.temperature or 0.0) + 0.3 * i})
        try:
            resp = model.invoke([("system", system), ("human", user)])
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue
        raw = resp.content if hasattr(resp, "content") else str(resp)
        data = _extract_json(raw)
        if data:
            return data, raw
    if last_err is not None and not raw:
        raise last_err
    return {}, raw


# --- Node 1: Retriever -------------------------------------------------------
def retriever_node(state):
    f: Finding = state["finding"]
    # Ablation switch: when VULNFIX_NO_RETRIEVAL is set, skip retrieval entirely
    # and return empty context. Used to measure whether retrieval earns its place.
    if os.getenv("VULNFIX_NO_RETRIEVAL"):
        return {"retrieved_context": ""}
    query = f"{f.rule_id} {f.message} {' '.join(f.cwe)} {f.snippet}".strip()
    return {"retrieved_context": retrieve_context(query)}


# --- Node 2: Static Analyst --------------------------------------------------
_ANALYST_SYS = (
    "You are a secure-code static analyst. Given a SAST finding and the source "
    "file, identify the precise weakness, the vulnerable lines, and the CWE "
    "class. Respond ONLY as JSON: "
    '{"weakness": str, "vulnerable_lines": str, "cwe": str, "analysis": str}.'
)


def static_analyst_node(state):
    f: Finding = state["finding"]
    _guidance = build_guidance((getattr(f, "language", None) or ("java" if f.file_path.endswith(".java") else "csharp" if f.file_path.endswith(".cs") else "python")), f.cwe)
    user = (f"FINDING:\nrule={f.rule_id}\nmessage={f.message}\ncwe={f.cwe}\n"
            f"line={f.start_line}\n\nSOURCE ({f.file_path}):\n{state['source_code']}")
    data, raw = _invoke_json(_llm(settings.REASONING_MODEL, json_mode=True),
                             _ANALYST_SYS, user)
    return {"analysis": data.get("analysis") or raw}


# --- Node 3: Root-Cause Reasoner --------------------------------------------
_ROOT_CAUSE_SYS = (
    "You are a root-cause security reasoner. Using the analysis, the source, "
    "and retrieved fix patterns from similar real vulnerabilities, explain the "
    "root cause and propose a concrete, minimal fix strategy. Respond ONLY as "
    'JSON: {"root_cause": str, "fix_strategy": str}.'
)


def root_cause_node(state):
    user = (f"ANALYSIS:\n{state.get('analysis', '')}\n\n"
            f"RETRIEVED FIX PATTERNS:\n{state.get('retrieved_context', '')}\n\n"
            f"SOURCE:\n{state['source_code']}")
    data, raw = _invoke_json(_llm(settings.REASONING_MODEL, json_mode=True),
                             _ROOT_CAUSE_SYS, user)
    return {
        "root_cause": data.get("root_cause", "") or raw,
        "fix_strategy": data.get("fix_strategy", ""),
    }


# --- Node 4: Patch Generator -------------------------------------------------
_PATCH_SYS = (
    "You are a secure patch generator. Rewrite the ENTIRE source file to fix "
    "the described vulnerability, changing as little as possible and preserving "
    "behavior. Also write a short security regression test that would fail on "
    "the original code and pass on the fix. Respond ONLY as JSON: "
    '{"patched_file": "<full file content>", "verification_test": "<test code>", '
    '"explanation": str}.'
)


def patch_generator_node(state):
    f: Finding = state["finding"]
    src = state["source_code"]

    # Deterministic codemod routing: for CWEs with a known-correct fix, apply it
    # directly and skip the LLM. The ablation showed the 7B model fixes these
    # patterns (LDAP injection, open redirect) poorly; a codemod fixes them
    # reliably. Only runs on the first attempt (no feedback yet).
    if not state.get("validation_feedback"):
        _fixed, _cm = try_codemod(f.cwe, src)
        if _fixed and _fixed.strip() != src.strip():
            _diff = "".join(difflib.unified_diff(
                src.splitlines(keepends=True), _fixed.splitlines(keepends=True),
                fromfile=f"a/{f.file_path}", tofile=f"b/{f.file_path}"))
            return {"patched_code": _fixed, "patch_diff": _diff,
                    "verification_test": "", "codemod": _cm,
                    "attempts": state.get("attempts", 0) + 1}

    feedback = state.get("validation_feedback", "")

    # Function-level targeting: if the finding points at a line and we can extract
    # the enclosing function, fix only that function and splice it back into the
    # full file. This avoids whole-file rewrites that mangle unrelated code on
    # large/multi-function files. Falls back to whole-file when extraction fails.
    _lang = getattr(f, "language", None) or ("java" if f.file_path.endswith(".java")
             else "csharp" if f.file_path.endswith(".cs") else "python")
    _span = None
    if getattr(f, "start_line", 0) and len(src.splitlines()) > 12:
        _span = extract_function(src, f.start_line, _lang)
    _patch_target = _span.source if _span else src

    user = (
        f"{_guidance}\n\n"
        f"ROOT CAUSE:\n{state.get('root_cause', '')}\n\n"
        f"FIX STRATEGY:\n{state.get('fix_strategy', '')}\n\n"
        + (f"PREVIOUS ATTEMPT FAILED VALIDATION: {feedback}\n\n" if feedback else "")
        + f"FILE: {f.file_path}\nSOURCE:\n{_patch_target}"
    )
    data, raw = _invoke_json(
        _llm(settings.CODE_MODEL, temperature=0.2, json_mode=True),
        _PATCH_SYS, user)
    patched_fragment = data.get("patched_file") or _patch_target
    if _span and patched_fragment.strip() != _patch_target.strip():
        patched = splice_function(src, _span, patched_fragment)
    else:
        patched = data.get("patched_file") or src
    diff = "".join(difflib.unified_diff(
        src.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f"a/{f.file_path}", tofile=f"b/{f.file_path}",
    ))
    return {
        "patched_code": patched,
        "patch_diff": diff,
        "verification_test": data.get("verification_test", ""),
        "attempts": state.get("attempts", 0) + 1,
    }