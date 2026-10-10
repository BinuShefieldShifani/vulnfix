# VulnFix: local AI agents that fix code vulnerabilities and check their own work

VulnFix takes a finding from a security scanner (a SARIF file from Semgrep, CodeQL or Bandit), works out why the code is vulnerable, writes a patch, and re-runs Semgrep to check the patch. Everything runs on your own machine with LangGraph, ChromaDB and Ollama. No code leaves the box, so it can run air-gapped.

![VulnFix fixing a Python SQL injection](screenshots/python-sqli.png)

## How it works

```
SAST/DAST report ──▶ secure parsing ──▶ local embeddings ──▶ private Chroma DB
                                                                      │
        ┌──────────────────────────────────────────────────────────── ┘
        ▼
   Retriever ─▶ Static Analyst ─▶ Root-Cause ─▶ Patch Generator ─▶ Validator
                                                      ▲                │
                                                      └── retry if failed ┘
                                                                       │
                                            Structured JSON + patch + test
                                                                       │
                                              Streamlit UI  /  REST API (CI/CD)
```

1. **Retriever** pulls related OSV advisories (CWE, CVSS, fixed versions) from a local Chroma collection.
2. **Static Analyst** reads the flagged code and the finding.
3. **Root-Cause Reasoner** explains in plain words why the code is exploitable.
4. **Patch Generator** writes a fix as a unified diff.
5. **Validator** runs guardrails and re-scans the patched file with Semgrep. If the original rule still fires, the patch goes back for another attempt.

Models used: `qwen2.5-coder:7b` for patches, `llama3.1:8b` for reasoning, `nomic-embed-text` for embeddings. All small enough for a single consumer GPU.

## Results: 10 findings, 10 "validated", 7 real fixes

I ran VulnFix on 10 common vulnerability types in Python and Java. The Validator marked all 10 as fixed on the first attempt. Then I reviewed every patch by hand. Three of them would still be exploitable.

| Finding | Language | Validator | Manual review | Time |
|---|---|---|---|---|
| [SQL injection (string format)](screenshots/python-sqli.png) | Python | ✅ validated | ✅ Fixed: parameterized query | 199.5 s |
| [SQL injection (Statement concat)](screenshots/java-sqli.png) | Java | ✅ validated | ✅ Fixed: PreparedStatement | 200.5 s |
| [Command injection (Runtime.exec)](screenshots/java-command-injection.png) | Java | ✅ validated | ✅ Fixed: ProcessBuilder with argument list | 187.4 s |
| [Insecure YAML load](screenshots/python-yaml-load.png) | Python | ✅ validated | ✅ Fixed: `yaml.safe_load` | 132.2 s |
| [Weak password hash (MD5)](screenshots/python-md5-password.png) | Python | ✅ validated | ✅ Fixed: bcrypt (old hashes need migrating) | 159.6 s |
| [Hardcoded credentials](screenshots/python-hardcoded-credentials.png) | Python | ✅ validated | ✅ Fixed: token read from environment | 181.2 s |
| [Unsafe deserialization (pickle)](screenshots/python-pickle.png) | Python | ✅ validated | ✅ Fixed: JSON instead (changes behavior) | 172.0 s |
| [OS command injection](screenshots/python-os-command-injection.png) | Python | ✅ validated | ❌ Still injectable | 141.8 s |
| [Path traversal](screenshots/python-path-traversal.png) | Python | ✅ validated | ❌ Still traversable | 181.2 s |
| [Code injection (eval)](screenshots/python-eval.png) | Python | ✅ validated | ❌ Still runs attacker code | 187.7 s |

Average time per finding: about 3 minutes on a 16 GB GPU.

### Why three bad patches passed

The Validator checks that the **Semgrep rule stops firing**. It doesn't check that the **attack stops working**. In all three cases the model changed the code just enough to stop matching the rule's pattern.

**OS command injection.** The patch swapped `"ping -c 1 " + host` for `f'ping -c 1 {host}'`. Same shell, same string, same bug. `host = "8.8.8.8; rm -rf /"` still works. The real fix is `subprocess.run(["ping", "-c", "1", host])` with no shell. The Java patch for the same bug got this right with `ProcessBuilder`, which makes the Python miss more interesting.

**Path traversal.** The patch replaced string concatenation with `Path('/var/data/') / filename`. That doesn't stop `../../etc/passwd`. Worse, if `filename` is an absolute path like `/etc/passwd`, pathlib throws away the base folder entirely. The fix needs `.resolve()` followed by a check that the result is still inside `/var/data`.

**Code injection (eval).** The patch parses the input with `ast` but only checks the top-level node. `__import__('os').system('id') + 1` is a `BinOp` at the top, so it passes the check and runs. A safe version walks the whole tree, or uses a small arithmetic evaluator instead of `eval`.

### What I'd change next

- Generate an exploit input for each finding and run it against the patched code, so validation means "the attack fails", not "the rule is quiet".
- Re-scan with more than one rule set (Semgrep plus Bandit for Python) so a patch can't dodge a single pattern.
- Actually execute the generated verification test instead of only producing it.
- Flag patches that change behavior (pickle to JSON, MD5 to bcrypt) for a human, even when they're secure.

## Project layout

```
vulnfix/
├── docker-compose.yml      # ChromaDB + Ollama services
├── requirements.txt
├── .env.example            # optional config overrides
├── config.py               # endpoints + model defaults
├── models.py               # Pydantic schemas + LangGraph state
├── sarif.py                # SARIF 2.1.0 intake (Semgrep/CodeQL/Bandit)
├── ingest_osv.py           # build the Chroma advisory collection
├── query.py                # retrieval sanity check
├── retriever.py            # Chroma + Ollama retrieval
├── agents.py               # the LLM agent nodes
├── validator.py            # guardrails + Semgrep re-scan
├── graph.py                # LangGraph assembly + CLI
├── testcases.py            # 10 labeled vulnerable cases + 1 negative control
├── api.py                  # FastAPI service for CI/CD
├── app.py                  # Streamlit UI
├── examples/
│   ├── vulnerable_app.py   # demo file (SQL injection)
│   └── findings.sarif      # matching SARIF report
└── screenshots/            # results from the runs above
```

## Running it

You need Docker, Python 3.10+ and a GPU with about 12 GB of memory or more.

**1. Start ChromaDB and Ollama**
```bash
docker compose up -d
```

**2. Pull the models**
```bash
docker exec vulnfix-ollama ollama pull nomic-embed-text
docker exec vulnfix-ollama ollama pull qwen2.5-coder:7b
docker exec vulnfix-ollama ollama pull llama3.1:8b
```
On a 12 GB card you can point `CODE_MODEL` and `REASONING_MODEL` at the same model to avoid swapping.

**3. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**4. Load OSV advisories into Chroma** (before running the agents)
```bash
python ingest_osv.py --ecosystems PyPI Maven NuGet --limit 500   # quick test
python ingest_osv.py --ecosystems PyPI Maven NuGet               # full
```
The pipeline still runs without this step, but the Retriever has nothing to ground on.

**5. Check retrieval (optional)**
```bash
python query.py "SQL injection via string formatting" --eco PyPI
```

**6. Run it**

Streamlit UI:
```bash
streamlit run app.py
```
Click *Load SQLi example*, then *Run remediation*, or upload your own SARIF and source files.

CLI:
```bash
python graph.py --sarif examples/findings.sarif --src-root examples
```

REST API for CI/CD:
```bash
uvicorn api:app --host 0.0.0.0 --port 8080
# POST /remediate        {rule_id, file_path, source_code, cwe, ...}
# POST /remediate-batch  {sarif, sources}
```

## Limits

- Best suited to localized bugs: SQL injection, hardcoded secrets, weak crypto, unsafe deserialization, missing input validation. Not built for logic flaws or multi-file issues.
- Patch generation rewrites the whole file, which is fine for small files. Large files need enclosing-function extraction.
- Without Semgrep installed, the Validator falls back to heuristic checks and says so in `validation.notes`.
- As the results show, "validated" means the scanner is satisfied. Review patches before merging.

## Data layers

- **Layer 1 (built):** OSV advisories in Chroma, with descriptions, CWE, CVSS and fixed versions.
- **Layer 2 (planned):** CVEfixes / SAP Project KB before-and-after code diffs, for code-level patch examples.
- **Layer 3 (planned):** CWE and OWASP remediation guidance to ground the reasoning.
