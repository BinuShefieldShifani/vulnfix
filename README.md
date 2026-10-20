# VulnFix: local AI agents that fix code vulnerabilities and verify their own fixes

[![CI](https://github.com/BinuShefieldShifani/vulnfix/actions/workflows/ci.yml/badge.svg)](https://github.com/BinuShefieldShifani/vulnfix/actions/workflows/ci.yml)

## What this is

VulnFix is an AI agent pipeline that takes a security finding and produces a fix you can trust: it generates a patch, then proves the patch works by running the real exploit against it and checking the code still behaves correctly. Only verified fixes reach a human, who approves or rejects each one, and every decision is written to a tamper-evident log. Everything runs locally (LangGraph + Ollama + ChromaDB), so it can run air-gapped.

The design principle: scanners and language models are both unreliable at security, so VulnFix never trusts either on its own. It verifies every fix by execution, running the exploit, the behavior tests, and the compiler, and ships nothing it cannot verify. Where it cannot confirm a fix, it says so rather than guessing. This repo also measures, on public benchmarks, exactly how unreliable off-the-shelf scanners are, which is the evidence for why execution-based verification is necessary.

## How it works

```
finding ─▶ Retriever ─▶ Static Analyst ─▶ Root-Cause ─▶ Patch router ─▶ Validator ─▶ human approval
                                                         │  ▲               │              │
                                           codemod ──────┘  └── retry ──────┘         audit log
                                           (known patterns)
```

The **Patch router** either applies a deterministic codemod (for patterns the model handles poorly) or calls the LLM. On large/multi-function files it can extract just the vulnerable function, fix that, and splice it back.

The **Validator** is the heart of it. A patch is `validated` only if:
1. the security re-scan (Semgrep custom taint rules + public packs + Bandit) shows the finding's CWE is gone,
2. the patched code **compiles** (`py_compile` / `javac`),
3. if a behavior test is supplied, the patched code **still passes it**, and
4. no new issue was introduced.

If no scanner can confirm the original was vulnerable, it returns `inconclusive` and ships nothing. Models: `qwen2.5-coder:7b` (patches), `llama3.1:8b` (reasoning), `nomic-embed-text` (embeddings).

## Headline result: ~93% verified fix rate across 30 vulnerability types

Across 30 vulnerability classes in Python and Java (5 runs each), scored by independent oracles that run the real exploit and behavior tests against each patch:

| Metric | Result |
|---|---|
| **Verified-secure fix rate** | **0.927** across 30 CWE classes (with dependency + CWE fix guidance) |
| Patches approved that were still exploitable | **0** across all runs (home + held-out, 95+ runs) |
| Patches approved that broke behavior | **0** |
| Negative control (already-safe code) | correctly abstained; never shipped an unnecessary change |

The fix rate improved from ~0.84 (baseline model) to 0.90 (with deterministic codemods) to **0.927** (with dependency-awareness and per-CWE fix guidance). Deterministic codemods handle patterns the model fixes poorly: LDAP injection and open redirect went from a 0/5 model fix rate to 100% via codemod.

Raw data: [`results/eval/`](results/eval), [`results/fix_benchmark_lever2.json`](results/fix_benchmark_lever2.json).

### What raised the fix rate, and what didn't

Three levers were tried, each measured against the benchmark with the rule "fix rate must go up or stay flat, never down":

| Lever | Change | Result |
|---|---|---|
| Deterministic codemods | known-correct fixes for LDAP injection, open redirect | 0.84 → 0.90; two 0/5 cases became 100% |
| Dependency + CWE guidance | tell the model which packages exist and how each CWE class should be fixed | 0.90 → 0.927; fixed path traversal, pickle, SSRF; no regression |
| Bigger model (14B vs 7B) | swap the patch model for one twice the size | **no overall gain** (0.933 vs 0.927, within noise), regressed some cases, 2–3x slower |

The bigger-model result is the interesting negative: with good guidance already in place, model size was not the bottleneck. The 7B plus guidance is the production config.

## Generalization: held-out CWEs the rules never saw

| Metric | Result |
|---|---|
| Patches approved that were still exploitable | **0 / 40 runs** |
| Fix rate on cases the validator could verify | **~80%** |
| On unverifiable CWEs (SSRF, open redirect, LDAP) | correctly abstained (`inconclusive`) |

On vulnerability types it had never seen, VulnFix never once approved an exploitable patch, and fixed most of what it could verify.

## End-to-end test: 15 realistic multi-function files, 3 languages

Fifteen realistic service files (Flask apps, DAOs, workers, config loaders) run through the full UI: finding → remediation → human review in the approval queue.

| Outcome | Count |
|---|---|
| Approved (correct fix) | 9 / 15 |
| Rejected (bad, unverifiable, or secure-but-broken) | 6 / 15 |
| By language | Python 5/7, Java 3/4, C# 2/4 |

Nothing was auto-applied; every fix passed through human approval. What the test showed:
- **Each validator gate caught real failures**: the compile check blocked fixes importing unavailable libraries (jbcrypt, commons-lang3); the scanner baseline correctly returned inconclusive where no scanner could confirm the bug; a secure-but-behavior-breaking fix (`ast.literal_eval` for a calculator) passed the security scan but was caught on review.
- **Human review caught what automation could not, in both directions**: it approved correct fixes the validator falsely rejected (a safe-argv command fix that a custom rule over-flagged), and rejected bad fixes the validator passed (a plausible-looking but broken SSRF check; a patch with missing imports that failed at runtime, not compile time).

Full result table: [`results/e2e_ui_test.md`](results/e2e_ui_test.md).

## Detection results (the scanner layer, on public benchmarks)

Standard OWASP scoring (Youden's J = TPR − FPR; a scanner that flags everything scores 0).

| Benchmark | Engine | Cases | TPR | FPR | Youden |
|---|---|---|---|---|---|
| OWASP Benchmark, Java | Semgrep | 2,740 | 0.882 | 0.417 | **0.465** |
| OWASP Benchmark, Python | Semgrep + Bandit | 1,230 | 0.485 | 0.108 | **0.377** |
| Juliet C# 1.3 (NIST SARD) | Semgrep | sampled | — | — | **0.295** |

Consistent finding across three languages: free pattern-based scanners reliably catch *insecure-API-usage* bugs (weak hash, weak crypto, unsafe deserialization) but fail on *taint-flow* bugs (injection, path traversal, XSS). Open-source coverage decreases Java → Python → C#.

**Combining engines (Python).** CodeQL and Semgrep have opposite blind spots:

| Engine | TPR | FPR | Youden |
|---|---|---|---|
| Semgrep | 0.485 | 0.108 | 0.377 |
| CodeQL | 0.252 | 0.193 | 0.059 |
| **Combined (union)** | **0.668** | 0.274 | 0.394 |

Their union lifts recall from 0.49 to 0.67 at the cost of more false positives. Confidence filtering (medium-and-up) cuts Semgrep's FPR from 0.108 to 0.094 with no loss of recall. CodeQL is used only for benchmark evaluation (its license restricts use on non-OSS code), so it is not bundled into VulnFix; Semgrep + Bandit are the built-in engines, which keeps the air-gapped guarantee.

Raw data: [`results/detection/`](results/detection).

## Is LLM judgment trustworthy? (calibration against a human golden set)

We tested whether an LLM could judge patch quality instead of execution-based checks, calibrated against 80 hand-labeled patches:

| Judge mode | Agreement with human | Bad patches wrongly called "good" |
|---|---|---|
| LLM alone (code + diff) | 47% | **93%** (40/43) |
| LLM + execution evidence | 69% | 16% (7/43) |

An LLM judging security fixes on its own misses 93% of bad patches. It becomes reliable only when given the results of actually running the code. This is independent evidence for the whole design: don't trust model judgment, verify by execution.

The model rarely hallucinates: across 120 patches, 2.5% referenced an unavailable import and 0% called a nonexistent API; all hallucinated patches failed validation and were never approved.

## Retrieval ablation

A controlled ablation across 31 CWEs (5 runs per arm, ~310 runs) compared the pipeline with OSV advisory retrieval on versus off:

| Arm | Verified fix rate |
|---|---|
| With retrieval | 0.839 |
| Without retrieval | 0.800 |

The difference is within run-to-run noise (a pilot run had it the other way). The honest conclusion: OSV advisory retrieval adds no measurable benefit to fix quality and can be removed to simplify the system. Running the ablation, rather than assuming the component helped, is the point.

Raw data: [`results/ablation/`](results/ablation).

## Capabilities

- **Verify-by-execution validator**: scanner re-scan + compile check + optional behavior test; returns `validated` / `unvalidated` / `inconclusive` and never ships an unverified fix.
- **Deterministic codemods**: known-correct fixes for patterns the model handles poorly (LDAP injection, open redirect), applied before the LLM.
- **Dependency + CWE fix guidance**: the patch prompt is told which packages are available and how each CWE class should be fixed, which cut hallucinated imports and wrong-approach fixes.
- **Function-level patching**: extracts the enclosing function of a finding (Python AST; Java/C# brace-matching), fixes only that, and splices it back, leaving the rest of the file untouched. Demonstrated via the programmatic/SARIF path on multi-function service files: the flagged function was fixed and validated while other functions and the entrypoint were preserved. (The interactive UI currently applies whole-file rewrites; wiring function-level patching into the UI is future work.)
- **Human-approval workflow**: every validated patch enters a review queue with its evidence (diff, exploit result, behavior result); a patch cannot be applied without human approval.
- **Tamper-evident audit log**: every submit/approve/reject/apply is appended to a hash-chained JSONL log; editing any past entry breaks the chain and is detected (`verify_audit()`).
- **SARIF-in / report-out**: consumes the standard SARIF that scanners emit, and produces annotated SARIF, a Markdown report, and an applyable patch of only the human-approved, verified fixes.
- **Hardened sandbox** (opt-in): runs untrusted code with memory, CPU-time, process-count, and file-size limits, an isolated temp dir, and a stripped environment, with a documented path to container/gVisor isolation (`HARDENING.md`).
- **Three languages**: Python, Java, and C# at the scanner and function-extraction layers.
- **LLMOps**: CI with a skip-gate (fails if any test is unexpectedly skipped), pinned dependencies + lock file, optional MLflow tracing (local SQLite, off by default), and a reproducible eval harness with a held-out generalization set.

## Limits and honest positioning

This is a rigorously-evaluated **research prototype**, not an enterprise-ready product. What it does well: localized, function-scoped vulnerabilities across Python, Java, and C#, verified by execution, with human oversight and an audit trail. What it does not do yet:

- **Cross-file / multi-function taint** and whole-repo reasoning. Function-level patching handles one function; cross-file analysis is future work.
- **Function-level patching in the interactive UI**. It works on the programmatic/SARIF path; the manual UI path still does whole-file rewrites. Wiring the finding's line number through the UI is a known next step.
- **True enterprise files with cross-module imports**. Files that import from across a project will not compile standalone, so the validator returns inconclusive even when the function-level fix is correct. Resolving project context is future work.
- **Production-scale deployment**: queueing, caching, and validation on a real team's codebase at scale are untested.
- **Full production sandboxing**: the hardened runner is process-level; a production deployment would add container/gVisor isolation (documented, not built).
- **C# fix-and-verify** is partial: scanner, extraction, and SQL-injection/deserialization fixes work; command-injection and weak-hash cases often return inconclusive because free C# scanner coverage is thin. A `dotnet` compile branch in the validator is scoped but not built.

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
