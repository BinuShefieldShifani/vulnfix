# VulnFix — Agentic Vulnerability Remediation

A fully local, air-gappable system that takes a SAST/DAST finding, analyzes the
code, and proposes a **validated** fix. Built with LangGraph, ChromaDB and
Ollama. No external API calls.

```
SAST/DAST report ──▶ secure parsing ──▶ local embeddings ──▶ private Chroma DB
                                                                      │
        ┌─────────────────────────────────────────────────────────── ┘
        ▼
   Retriever ─▶ Static Analyst ─▶ Root-Cause ─▶ Patch Generator ─▶ Validator
                                                      ▲                │
                                                      └── retry if failed ┘
                                                                       │
                                            Structured JSON + patch + test
                                                                       │
                                              Streamlit UI  /  REST API (CI/CD)
```

## Project layout

```
vulnfix/
├── docker-compose.yml      # ChromaDB + Ollama services
├── requirements.txt
├── .env.example            # optional config overrides
├── config.py               # endpoints + 12GB-friendly model defaults
├── models.py               # Pydantic schemas + LangGraph state
├── sarif.py                # SARIF 2.1.0 intake (Semgrep/CodeQL/Bandit)
├── ingest_osv.py           # build the Chroma advisory collection
├── query.py                # retrieval sanity-check tool
├── retriever.py            # Chroma + Ollama retrieval
├── agents.py               # the four LLM agent nodes
├── validator.py            # guardrails + Semgrep re-scan
├── graph.py                # LangGraph assembly + CLI
├── api.py                  # FastAPI service for CI/CD
├── app.py                  # Streamlit UI
└── examples/
    ├── vulnerable_app.py   # demo file (SQL injection)
    └── findings.sarif      # matching SARIF report
```

## Run order (start to finish)

### 1. Services
```bash
docker compose up -d
```

### 2. Pull models (12GB-friendly — NOT Llama-3.1-70B)
```bash
docker exec vulnfix-ollama ollama pull nomic-embed-text   # embeddings (ingest)
docker exec vulnfix-ollama ollama pull qwen2.5-coder:7b   # patch generator
docker exec vulnfix-ollama ollama pull llama3.1:8b        # reasoning agents
```
On 12GB you host one large model at a time; you can set `CODE_MODEL` and
`REASONING_MODEL` to the same model to avoid swapping.

### 3. Python deps
```bash
pip install -r requirements.txt
```

### 4. Ingest advisories → Chroma  *(do this before the agents)*
This populates the collection the **Retriever** agent reads. Only needs the
embedding model.
```bash
python ingest_osv.py --ecosystems PyPI Maven NuGet --limit 500   # quick test
python ingest_osv.py --ecosystems PyPI Maven NuGet               # full
```
> The pipeline still runs without this (retrieval degrades gracefully), but the
> Retriever adds grounding only once the collection has data.

### 5. (Optional) Verify retrieval
```bash
python query.py "SQL injection via string formatting" --eco PyPI
```

### 6. Run the agents — pick any front end

**Streamlit UI (recommended for demos):**
```bash
streamlit run app.py
```
Click *Load SQLi example* → *Run remediation*, or upload a SARIF + source files.

**CLI:**
```bash
python graph.py --sarif examples/findings.sarif --src-root examples
```

**REST API (CI/CD):**
```bash
uvicorn api:app --host 0.0.0.0 --port 8080
# POST /remediate  {rule_id, file_path, source_code, cwe, ...}
# POST /remediate-batch  {sarif, sources}
```

## Validation (the honest part)
The Validator re-runs Semgrep on the patched code and marks a finding
`validated` only if the original rule no longer fires **and** the guardrails
pass. Without Semgrep installed it falls back to heuristic checks and says so in
`validation.notes`. Scope claims to localized weakness classes (SQLi, hardcoded
secrets, weak crypto, missing input validation, path traversal); lead with SAST
over DAST.

## Data layers
- **Layer 1 (built):** OSV advisories in Chroma — descriptions, CWE, CVSS,
  fixed versions. Grounding + dependency-level fixes.
- **Layer 2 (next):** CVEfixes / SAP Project KB — real before/after code diffs
  for code-level patches. Load into a second collection keyed on CWE + code.
- **Layer 3:** CWE/OWASP remediation text to ground the reasoning.

## Notes
- All processing is local; suitable for air-gapped / IP-sensitive deployment.
- Patch generation currently rewrites the whole file (fine for small files);
  switch to enclosing-function extraction for large files.
