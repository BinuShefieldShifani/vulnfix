# VulnFix: local AI agents that fix code vulnerabilities and verify their own fixes

VulnFix takes a security finding, works out why the code is vulnerable, writes a patch, and then **verifies the patch by running the actual exploit against it**, not just by re-scanning. A fix is accepted only when the attack provably stops working and the code still behaves correctly. A human approves every fix before it is applied, and every decision is written to a tamper-evident audit log. Everything runs locally (LangGraph + Ollama + ChromaDB), so it can run air-gapped.

[![CI](https://github.com/BinuShefieldShifani/vulnfix/actions/workflows/ci.yml/badge.svg)](https://github.com/BinuShefieldShifani/vulnfix/actions/workflows/ci.yml)

## The idea in one line

Scanners are unreliable (this repo measures exactly how unreliable, on public benchmarks). So VulnFix does not trust the scanner's verdict. It verifies every fix by execution: run the exploit, run the behavior tests, compile the code. If it cannot verify a fix, it says so and ships nothing, rather than approving a patch that looks fixed but is not. A human makes the final call.

## How it works

```
finding ─▶ Retriever ─▶ Static Analyst ─▶ Root-Cause ─▶ Patch router ─▶ Validator ─▶ human approval
                                                         │  ▲               │              │
                                           codemod ──────┘  └── retry ──────┘         audit log
                                           (known patterns)
```

The **Patch router** either applies a deterministic codemod (for patterns the model handles poorly) or calls the LLM. For large/multi-function files it extracts just the vulnerable function, fixes that, and splices it back.

The **Validator** is the heart of it. A patch is `validated` only if:
1. the security re-scan (Semgrep custom taint rules + public packs + Bandit) shows the finding's CWE is gone,
2. the patched code **compiles** (`py_compile` / `javac`),
3. if a behavior test is supplied, the patched code **still passes it**, and
4. no new issue was introduced.

If no scanner can confirm the original was vulnerable, it returns `inconclusive` and ships nothing. Models: `qwen2.5-coder:7b` (patches), `llama3.1:8b` (reasoning), `nomic-embed-text` (embeddings).

## Headline result: ~90% verified fix rate across 30 vulnerability types

Across 30 vulnerability classes in Python and Java (5 runs each, codemods active), scored by independent oracles that run the real exploit and behavior tests against each patch:

| Metric | Result |
|---|---|
| **Verified-secure fix rate** | **~90%** across 30 CWE classes |
| Patches approved that were still exploitable | **0** across all runs (home + held-out, 95+ runs) |
| Patches approved that broke behavior | **0** |
| Negative control (already-safe code) | correctly abstained; never shipped an unnecessary change |

The weak cases (unsafe deserialization, path traversal, and some Java fixes) are where the 7B model struggles; the rest fix reliably. Deterministic **codemods** handle patterns the model fixes poorly: LDAP injection and open redirect went from a 0/5 model fix rate to 100% via codemod.

Raw data: [`results/eval/`](results/eval), [`results/fix_benchmark_codemods.json`](results/fix_benchmark_codemods.json).

## Generalization: held-out CWEs the rules never saw

| Metric | Result |
|---|---|
| Patches approved that were still exploitable | **0 / 40 runs** |
| Fix rate on cases the validator could verify | **~80%** |
| On unverifiable CWEs (SSRF, open redirect, LDAP) | correctly abstained (`inconclusive`) |

On vulnerability types it had never seen, VulnFix never once approved an exploitable patch, and fixed most of what it could verify.

## Two kinds of evaluation

- **Detection** measures the off-the-shelf scanner layer (Semgrep, Bandit, CodeQL) on public benchmarks. These numbers are modest because free scanners are modest. This is the *motivation* for the project, not its result.
- **Fix-and-verify** measures what VulnFix itself does. These are the project's real numbers (above), and they are strong.

## Detection results (the scanner layer, on public benchmarks)

Standard OWASP scoring (Youden's J = TPR − FPR; a scanner that flags everything scores 0).

| Benchmark | Engine | Cases | TPR | FPR | Youden |
|---|---|---|---|---|---|
| OWASP Benchmark, Java | Semgrep | 2,740 | 0.882 | 0.417 | **0.465** |
| OWASP Benchmark, Python | Semgrep + Bandit | 1,230 | 0.485 | 0.108 | **0.377** |
| Juliet C# 1.3 (NIST SARD) | Semgrep | sampled | — | — | **0.295** |

Consistent finding across three languages: free pattern-based scanners reliably catch *insecure-API-usage* bugs (weak hash, weak crypto, unsafe deserialization) but fail on *taint-flow* bugs (injection, path traversal, XSS). Open-source coverage decreases Java → Python → C#.

**Combining engines.** On Python, CodeQL and Semgrep have opposite blind spots. Their union lifts recall from 0.49 to 0.67 at the cost of more false positives; confidence filtering (medium-and-up) cuts Semgrep's FPR from 0.108 to 0.094 with no loss of recall. CodeQL is used only for benchmark evaluation (license restricts use on non-OSS code), so it is not bundled into VulnFix; Semgrep + Bandit are the built-in engines, keeping the air-gapped guarantee.

Raw data: [`results/detection/`](results/detection).

## Is the LLM judgment trustworthy? (calibration against a human golden set)

We tested whether an LLM could judge patch quality instead of execution-based checks, calibrated against 80 hand-labeled patches:

| Judge mode | Agreement with human | Bad patches wrongly called "good" |
|---|---|---|
| LLM alone (code + diff) | 47% | **93%** (40/43) |
| LLM + execution evidence | 69% | 16% (7/43) |

An LLM judging security fixes on its own misses 93% of bad patches. It only becomes reliable when given the results of actually running the code. This is independent evidence for the whole design: **don't trust model judgment, verify by execution.**

The model rarely hallucinates: across 120 patches, 2.5% referenced an unavailable import and 0% called a nonexistent API; all hallucinated patches failed validation and were never approved.

## Engineering, LLMOps, and enterprise features

- **Human-approval workflow**: VulnFix never auto-applies a fix. Each validated patch enters a review queue with its evidence (diff, exploit result, behavior result); a human approves or rejects. A patch cannot be applied without approval.
- **Tamper-evident audit log**: every submit/approve/reject/apply is appended to a hash-chained JSONL log. Editing any past entry breaks the chain and is detected (`verify_audit()`).
- **Function-level patching**: on large/multi-function files, VulnFix extracts the enclosing function of the finding (Python AST; Java/C# brace-matching), fixes only that, and splices it back, leaving the rest of the file untouched. Demonstrated on a multi-route Flask app: the flagged function was fixed and validated while all other routes and the entrypoint were preserved.
- **Retrieval ablation**: a controlled ablation across 31 CWEs showed OSV advisory retrieval changes the fix rate by under 4 points in either direction (within noise), i.e. it adds no measurable benefit. Reported honestly; retrieval can be removed to simplify the system.
- **CI** with a skip-gate (fails if any test is unexpectedly skipped, so coverage can't silently erode), **pinned dependencies** + lock file, and optional **MLflow tracing** (local SQLite, off by default).
- **Sandboxed execution** of untrusted code with timeouts and an isolated temp dir.

## Limits and honest positioning

This is a rigorously-evaluated **research prototype**, not an enterprise-ready product. What it does well: localized, function-scoped vulnerabilities across Python, Java, and C#, verified by execution, with human oversight and an audit trail. What it does not do yet:

- **Cross-file / multi-function taint** and whole-repo reasoning (function-level patching handles one function; cross-file analysis is future work).
- **Production-scale deployment**: queueing, caching, and validation on a real team's codebase at scale are untested.
- **Full production sandboxing**: execution is isolated at the process level; a production deployment would use container/gVisor-level isolation (documented, not built).
- **C# fix-and-verify** is partial (scanner + extraction work; a `dotnet` compile branch in the validator is scoped).

The core loop (generate → verify by execution → human-approve) is sound and measured. Productionizing it is integration, isolation, and scale work.

## Running it

See [`results/`](results) for all committed evaluation data. A Kaggle notebook (GPU for the fixer, CPU-only for detection scoring) reproduces the runs.

**Quick start (Docker):**
```bash
docker compose up -d
docker exec vulnfix-ollama ollama pull qwen2.5-coder:7b
pip install -r requirements.txt
python ingest_osv.py --ecosystems PyPI Maven NuGet --limit 500
python graph.py --sarif examples/findings.sarif --src-root examples
```

On Kaggle, pin Ollama to one GPU (`CUDA_VISIBLE_DEVICES=0`) or it falls back to CPU. The Streamlit UI (`streamlit run app.py`) provides remediation plus the human-approval queue.
