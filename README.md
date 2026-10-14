# VulnFix: local AI agents that fix code vulnerabilities and verify their own fixes

VulnFix takes a security finding, works out why the code is vulnerable, writes a patch, and then **verifies the patch by running the actual exploit against it**, not just by re-scanning. A fix is accepted only when the attack provably stops working and the code still behaves correctly. Everything runs locally (LangGraph + Ollama + ChromaDB), so it can run air-gapped.

[![CI](https://github.com/BinuShefieldShifani/vulnfix/actions/workflows/ci.yml/badge.svg)](https://github.com/BinuShefieldShifani/vulnfix/actions/workflows/ci.yml)

## The idea in one line

Scanners are unreliable (this repo measures exactly how unreliable, on public benchmarks). So VulnFix does not trust the scanner's verdict. It verifies every fix by execution: run the exploit, run the behavior tests, compile the code. If it cannot verify a fix, it says so and ships nothing, rather than approving a patch that looks fixed but is not.

## How it works

```
finding ─▶ Retriever ─▶ Static Analyst ─▶ Root-Cause ─▶ Patch Generator ─▶ Validator
                                                              ▲                 │
                                                              └── retry if failed┘
                                                                                │
                                                      validated / unvalidated / inconclusive
```

The **Validator** is the heart of it. A patch is `validated` only if:
1. the security re-scan (Semgrep custom taint rules + public packs + Bandit) shows the finding's CWE is gone,
2. the patched code **compiles** (`py_compile` / `javac`),
3. if a behavior test is supplied, the patched code **still passes it**, and
4. no new issue was introduced.

If no scanner can confirm the original was vulnerable, it returns `inconclusive` and ships nothing. Models: `qwen2.5-coder:7b` (patches), `llama3.1:8b` (reasoning), `nomic-embed-text` (embeddings).

## Two kinds of evaluation

This project measures two different things, and it is important not to confuse them:

- **Detection** measures the off-the-shelf scanner layer (Semgrep, Bandit, CodeQL) on public benchmarks. These numbers are modest, because free scanners are modest. This is the *motivation* for the project, not its result.
- **Fix-and-verify** measures what VulnFix itself does: given a finding, does it produce a patch that is genuinely secure and still works, and does it ever approve a bad one? These are the project's real numbers, and they are strong.

## Fix-and-verify results (the system's real numbers)

Every test case is run 5 times. Each patch is scored by independent oracles that run the real exploit and real behavior tests against the patched code, separately from the validator.

**Home set (11 cases, built alongside the rules):**

| Metric | Result |
|---|---|
| Patches approved that were still exploitable | **0 / 55 runs** |
| Patches approved that broke behavior | **0 / 55 runs** |
| Cleanly fixed on the categories it covers | SQLi, command injection, YAML, hardcoded secret, weak hash, Java SQLi all fixed reliably |

The behavior gate is what makes "0 broken approved" possible: e.g. a secure-but-useless `ast.literal_eval` fix for an `eval` bug is caught every time, because it fails the behavior test (`compute("2+3")` no longer returns 5).

**Held-out set (8 unseen CWEs the custom rules were never built for):**

| Metric | Result |
|---|---|
| Patches approved that were still exploitable | **0 / 40 runs** |
| Fix rate on cases the validator could verify | **~80%** (4 of 5 verifiable categories) |
| Coverage (cases a scanner could give a baseline for) | ~60% |

The held-out run is the generalization test. On vulnerability types it had never seen, VulnFix never once approved an exploitable patch, and fixed most of what it could verify. Where no scanner could confirm the original bug (SSRF, open redirect, LDAP), it correctly abstained (`inconclusive`) rather than guessing.

Raw data: [`results/eval/run8_home/`](results/eval/run8_home) and [`results/eval/run8_heldout/`](results/eval/run8_heldout).

## Detection results (the scanner layer, on public benchmarks)

Measured with the standard OWASP scoring (Youden's J = TPR − FPR; a scanner that flags everything scores 0).

| Benchmark | Engine | Cases | TPR | FPR | Youden |
|---|---|---|---|---|---|
| OWASP Benchmark, Java | Semgrep | 2,740 | 0.882 | 0.417 | **0.465** |
| OWASP Benchmark, Python | Semgrep + Bandit | 1,230 | 0.485 | 0.108 | **0.377** |
| Juliet C# 1.3 (NIST SARD), baseline | Semgrep | sampled | 0.60 (SQLi) | 0.0 | **0.295** |

Three languages, three public benchmarks, and a consistent finding: free pattern-based scanners reliably catch *insecure-API-usage* bugs (weak hash, weak crypto, unsafe deserialization) but fail on *taint-flow* bugs (injection, path traversal, XSS), where they either miss everything or flag everything. Open-source scanner coverage decreases Java → Python → C#: Java has mature, high-recall (but noisy) rules; Python is thinner; C# has essentially only a working SQL-injection rule in the free Semgrep set.

**Adding CodeQL (real taint analysis) and combining engines.** On the Python benchmark, CodeQL and Semgrep have *opposite* blind spots: Semgrep catches the API-check categories CodeQL's taint queries skip, CodeQL catches the taint categories Semgrep's patterns miss. Taking the union of both:

| Engine | TPR | FPR | Youden |
|---|---|---|---|
| Semgrep | 0.485 | 0.108 | 0.377 |
| CodeQL | 0.252 | 0.193 | 0.059 |
| **Combined (union)** | **0.668** | 0.274 | 0.394 |

Combining engines lifts recall from 0.49 to 0.67 (it finds far more real bugs) at the cost of more false positives. **Confidence filtering** recovers some of that precision: keeping only medium-and-up confidence findings cuts Semgrep's FPR from 0.108 to 0.094 with no loss of recall.

CodeQL is used only for benchmark evaluation (its license restricts use on non-open-source code), so it is not bundled into VulnFix itself; Semgrep and Bandit remain the built-in engines, which keeps the air-gapped guarantee.

Raw data: [`results/detection/`](results/detection).

## Why the modest detection numbers are the point

VulnFix does not depend on the scanner being right. A scanner false positive just means the fixer is handed a case with nothing to fix, and the validator returns `inconclusive`. A scanner false negative is caught where the exploit oracle can run. The verification layer, not the scanner, is what decides whether a fix ships. The detection benchmarks exist to show, with real numbers, why that design is necessary.

## Engineering / LLMOps

- **CI** (GitHub Actions) runs the full test suite on every push, with a gate that fails if any test is unexpectedly skipped, so coverage cannot silently erode.
- **Pinned dependencies** plus a full lock file; every result is reproducible against a known environment.
- **Tracing**: optional MLflow autolog captures every agent call (latency, chain structure) to a local SQLite store. Off by default, no-op if MLflow is absent, so it adds no dependency to the pipeline or CI.
- **Reproducible eval harness** with sandboxed exploit/behavior execution, repeated runs, and a held-out generalization set.
- Per-agent timing from the traces: the validator costs about as much wall-clock time as patch generation (it runs Semgrep + Bandit + compile + behavior test), and the retriever is near-free.

## Limits and roadmap

- **Scope**: localized, single-file bugs. Not built for logic flaws, multi-file taint, or whole-repo reasoning.
- **Verification coverage is bounded by the detection layer.** Where no scanner and no exploit oracle can confirm a bug, VulnFix abstains. Broadening coverage (more rules, the exploit oracle as a first-class verification signal) is the main line of future work.
- **"Validated" means secure, compiling, and behavior-preserving** on the supplied tests. It is not a guarantee for untested behavior. Review patches before merging.
- **C# support** exists at the scanner and compile layers (Semgrep C# rules + a `dotnet` compile branch is scoped); a full fix-and-verify suite for C# is future work.
- Larger models and CodeQL-grade taint analysis would raise fix quality and coverage; the core verify-by-execution loop is independent of model size.

## Running it

See [`results/`](results) for all committed evaluation data. A Kaggle notebook (GPU for the fixer, CPU for detection scoring) reproduces the runs; the detection scorers need only Semgrep/Bandit/CodeQL and run without a GPU.

**Quick start (Docker):**
```bash
docker compose up -d
docker exec vulnfix-ollama ollama pull qwen2.5-coder:7b
pip install -r requirements.txt
python ingest_osv.py --ecosystems PyPI Maven NuGet --limit 500
python graph.py --sarif examples/findings.sarif --src-root examples
```

On Kaggle, pin Ollama to one GPU (`CUDA_VISIBLE_DEVICES=0`) or it falls back to CPU.
